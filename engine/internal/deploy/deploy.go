// Package deploy migrates and upgrades the unified service transactionally.
// Candidates are checked in isolation before stopping installed workers.
package deploy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"

	"network-owned-engine/internal/runtimecheck"
)

const (
	Label      = "system/com.local.network-domain-proxy"
	EngineName = "network-domain-engine"
	PlistName  = "com.local.network-domain-proxy.plist"
	ToolName   = "network-domain-proxy-deploy"
	ProxyPort  = 17890
)

var (
	Services  = []string{"Wi-Fi", "Ethernet"}
	Kinds     = []string{"webproxy", "securewebproxy"}
	RuleNames = []string{"domestic", "foreign", "china"}
)

type Paths = runtimecheck.Paths

var Production = runtimecheck.Production

type CommandError = runtimecheck.CommandError

func exitCode(err error) (int, bool) { return runtimecheck.ExitCode(err) }

// Record describes one snapshotted target.
type Record struct {
	Target  string `json:"target"`
	Present bool   `json:"present"`
	Copy    string `json:"copy"`
	Mode    uint32 `json:"mode,omitempty"`
	UID     uint32 `json:"uid,omitempty"`
	GID     uint32 `json:"gid,omitempty"`
}

// Deployer holds the target paths and every system interaction. Tests replace
// these fields; nil step overrides use the real implementations.
type Deployer struct {
	preflightOnly bool
	userFiles     *ownedUserFiles
	unifiedLayout *unifiedLayout
	acceptUnified func(serviceConfigPath string, previous int64) error
	Paths
	Context      context.Context
	Root         string // staging directory holding the new files
	Out          io.Writer
	Run          func(args ...string) (string, error)
	ProcessAlive func(pid int) (bool, error)
	Sleep        func(time.Duration)
	Now          func() time.Time
	Dial         func(address string, timeout time.Duration) (io.Closer, error)
	Chown        func(path string, uid, gid uint32) error
	Rename       func(oldpath, newpath string) error
	Interrupted  func() bool

	Preflight func(config map[string]any) error
	Snapshot  func(backup string, targets []string) ([]Record, error)
	Restore   func(backup string, records []Record) error
	EnsureDir func(path string, mode os.FileMode, owner string) error
}

func New(paths Paths, root string, out io.Writer) *Deployer {
	return &Deployer{Paths: paths, Context: context.Background(), Root: root, Out: out, Run: runCommand, ProcessAlive: processAlive,
		Sleep: time.Sleep, Now: time.Now, Interrupted: func() bool { return false },
		Dial: func(address string, timeout time.Duration) (io.Closer, error) {
			return net.DialTimeout("tcp", address, timeout)
		},
		Chown:  func(path string, uid, gid uint32) error { return os.Chown(path, int(uid), int(gid)) },
		Rename: os.Rename}
}

func runCommand(args ...string) (string, error) { return runtimecheck.Run(args...) }

func processAlive(pid int) (bool, error) {
	switch err := syscall.Kill(pid, 0); {
	case err == nil:
		return true, nil
	case errors.Is(err, syscall.ESRCH):
		return false, nil
	default:
		return false, err
	}
}

func lookupUser(name string) (uint32, error) {
	account, err := user.Lookup(name)
	if err != nil {
		return 0, err
	}
	id, err := strconv.ParseInt(account.Uid, 10, 64)
	if err != nil {
		return 0, err
	}
	return uint32(id), nil // macOS nobody is -2, stored as 4294967294
}

// Lock takes the private deployment lock; call the returned function to
// release it. Overlapping deployments are rejected rather than queued.
func (d *Deployer) Lock() (func(), error) {
	fd, err := syscall.Open(d.Paths.Lock, syscall.O_CREAT|syscall.O_RDWR|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0o600)
	if err != nil {
		return nil, &fs.PathError{Op: "open", Path: d.Paths.Lock, Err: err}
	}
	file := os.NewFile(uintptr(fd), d.Paths.Lock)
	var status syscall.Stat_t
	if err := syscall.Fstat(fd, &status); err != nil {
		file.Close()
		return nil, err
	}
	if status.Mode&syscall.S_IFMT != syscall.S_IFREG || int(status.Uid) != os.Geteuid() || status.Mode&0o077 != 0 {
		file.Close()
		return nil, errors.New("unsafe deployment lock")
	}
	if err := syscall.Flock(fd, syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		file.Close()
		if errors.Is(err, syscall.EWOULDBLOCK) {
			return nil, errors.New("another proxy deployment is active")
		}
		return nil, err
	}
	return func() { file.Close() }, nil
}

type proxySettings map[string]map[string]map[string]string

func (d *Deployer) settings() (proxySettings, error) {
	saved := proxySettings{}
	for _, service := range Services {
		saved[service] = map[string]map[string]string{}
		for _, kind := range Kinds {
			raw, err := d.Run("/usr/sbin/networksetup", "-get"+kind, service)
			if err != nil {
				return nil, err
			}
			values := map[string]string{}
			for _, line := range strings.Split(raw, "\n") {
				if key, value, ok := strings.Cut(line, ": "); ok {
					values[key] = value
				}
			}
			if values["Authenticated Proxy Enabled"] != "0" {
				return nil, errors.New("authenticated proxy present; refusing to overwrite")
			}
			saved[service][kind] = values
		}
	}
	return saved, nil
}

func orderedKeys[V any](m map[string]V, preferred []string) []string {
	var keys []string
	for _, key := range preferred {
		if _, ok := m[key]; ok {
			keys = append(keys, key)
		}
	}
	var rest []string
	for key := range m {
		if !slices.Contains(preferred, key) {
			rest = append(rest, key)
		}
	}
	slices.Sort(rest)
	return append(keys, rest...)
}

func (d *Deployer) restoreSettings(saved proxySettings) error {
	for _, service := range orderedKeys(saved, Services) {
		for _, kind := range orderedKeys(saved[service], Kinds) {
			values := saved[service][kind]
			server, ok := values["Server"]
			if !ok {
				return fmt.Errorf("saved %s %s settings lack a server", service, kind)
			}
			if server != "" {
				port, err := strconv.Atoi(strings.TrimSpace(values["Port"]))
				if err != nil {
					return err
				}
				if port > 0 {
					if _, err := d.Run("/usr/sbin/networksetup", "-set"+kind, service, server, values["Port"]); err != nil {
						return err
					}
				}
			}
			enabled, ok := values["Enabled"]
			if !ok {
				return fmt.Errorf("saved %s %s settings lack a state", service, kind)
			}
			state := "off"
			if enabled == "Yes" {
				state = "on"
			}
			if _, err := d.Run("/usr/sbin/networksetup", "-set"+kind+"state", service, state); err != nil {
				return err
			}
		}
	}
	return nil
}

// InstallFile atomically replaces target with a root-owned copy of source.
// The temporary file is removed whether or not the replacement succeeds.
func (d *Deployer) InstallFile(source, target string, mode os.FileMode) error {
	temporary, err := os.CreateTemp(filepath.Dir(target), "."+filepath.Base(target)+".")
	if err != nil {
		return err
	}
	defer os.Remove(temporary.Name())
	input, err := os.Open(source)
	if err == nil {
		_, err = io.Copy(temporary, input)
		input.Close()
	}
	if err == nil {
		err = temporary.Chmod(mode)
	}
	if err == nil {
		err = d.Chown(temporary.Name(), 0, 0)
	}
	if err == nil {
		err = temporary.Sync()
	}
	if closeErr := temporary.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	return d.Rename(temporary.Name(), target)
}

func (d *Deployer) preflight(config map[string]any) error {
	if d.Preflight != nil {
		return d.Preflight(config)
	}
	directory, err := os.MkdirTemp(d.BackupParent, "network-domain-independent-preflight.")
	if err != nil {
		return err
	}
	defer os.RemoveAll(directory)
	nobody, err := lookupUser("nobody")
	if err != nil {
		return err
	}
	if err := d.Chown(directory, nobody, 0); err != nil {
		return err
	}
	var candidate map[string]any
	data, _ := json.Marshal(config)
	json.Unmarshal(data, &candidate)
	candidate["cache_directory"] = filepath.Join(directory, "cache")
	for _, item := range candidate["rule_sources"].([]any) {
		source := item.(map[string]any)
		source["seed"] = filepath.Join(d.Root, source["kind"].(string)+".json")
	}
	reservation, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return err
	}
	port := reservation.Addr().(*net.TCPAddr).Port
	reservation.Close()
	candidate["listen"] = fmt.Sprintf("127.0.0.1:%d", port)
	path, logPath := filepath.Join(directory, "config.json"), filepath.Join(directory, "service.log")
	if data, err = json.Marshal(candidate); err != nil {
		return err
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		return err
	}
	if err := d.Chown(path, nobody, 0); err != nil {
		return err
	}
	binary := filepath.Join(d.Root, EngineName)
	if _, err := d.Run(binary, "check", "-c", path); err != nil {
		return err
	}
	output, err := os.Create(filepath.Join(directory, "startup.log"))
	if err != nil {
		return err
	}
	defer output.Close()
	command := exec.Command(binary, "run", "--log-file", logPath, "-c", path)
	command.Stdout, command.Stderr = output, output
	for _, entry := range os.Environ() {
		if name, _, _ := strings.Cut(entry, "="); name != "SUDO_USER" && name != "SUDO_UID" && name != "SUDO_GID" {
			command.Env = append(command.Env, entry)
		}
	}
	command.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: nobody, Gid: 0, Groups: []uint32{}}}
	if err := command.Start(); err != nil {
		return err
	}
	exited := make(chan struct{})
	go func() { command.Wait(); close(exited) }()
	defer func() {
		select {
		case <-exited:
			return
		default:
		}
		command.Process.Signal(syscall.SIGTERM)
		select {
		case <-exited:
		case <-time.After(5 * time.Second):
			command.Process.Kill()
			<-exited
		}
	}()
	for deadline := time.Now().Add(15 * time.Second); ; time.Sleep(100 * time.Millisecond) {
		select {
		case <-exited:
			return errors.New("independent candidate did not start")
		default:
		}
		if started(logPath) {
			break
		}
		if !time.Now().Before(deadline) {
			return errors.New("independent candidate did not start")
		}
	}
	return d.health(port)
}

func started(logPath string) bool {
	data, err := os.ReadFile(logPath)
	if err != nil {
		return false
	}
	for _, line := range strings.Split(string(data), "\n") {
		var event struct {
			Event string `json:"event"`
		}
		if json.Unmarshal([]byte(line), &event) == nil && event.Event == "started" {
			return true
		}
	}
	return false
}

// Health waits for the listener, then requires a domestic and a foreign HTTPS
// request through the proxy to succeed.
func (d *Deployer) health(port int) error {
	address := fmt.Sprintf("127.0.0.1:%d", port)
	deadline := d.Now().Add(15 * time.Second)
	for {
		connection, err := d.Dial(address, 250*time.Millisecond)
		if err == nil {
			connection.Close()
			break
		}
		if !d.Now().Before(deadline) {
			return fmt.Errorf("proxy listener did not become ready: %w", err)
		}
		d.Sleep(100 * time.Millisecond)
	}
	for _, url := range []string{"https://www.douyin.com/", "https://github.com/"} {
		if _, err := d.Run("/usr/bin/curl", "--proxy", "http://"+address, "--noproxy", "",
			"-fsS", "-o", "/dev/null", "--max-time", "15", url); err != nil {
			return err
		}
	}
	return nil
}

func (d *Deployer) snapshot(backup string, targets []string) ([]Record, error) {
	if d.Snapshot != nil {
		return d.Snapshot(backup, targets)
	}
	return d.snapshotFiles(backup, targets)
}

func (d *Deployer) snapshotFiles(backup string, targets []string) ([]Record, error) {
	var records []Record
	for index, target := range targets {
		if d.userFiles != nil && d.userFiles.has(target) {
			record, err := d.userFiles.snapshot(backup, index, target)
			if err != nil {
				return nil, err
			}
			records = append(records, record)
			continue
		}
		record := Record{Target: target, Copy: strconv.Itoa(index)}
		info, err := os.Lstat(target)
		switch {
		case errors.Is(err, fs.ErrNotExist):
		case err != nil:
			return nil, err
		case info.Mode()&os.ModeSymlink != 0:
			return nil, errors.New("refusing to snapshot a symlink")
		case !info.Mode().IsRegular():
			return nil, errors.New("refusing to snapshot a non-file")
		default:
			status := info.Sys().(*syscall.Stat_t)
			if err := copyFile(target, filepath.Join(backup, record.Copy), info); err != nil {
				return nil, err
			}
			record.Present, record.Mode, record.UID, record.GID = true, uint32(status.Mode&0o7777), status.Uid, status.Gid
		}
		records = append(records, record)
	}
	manifest, err := json.Marshal(records)
	if err != nil {
		return nil, err
	}
	return records, os.WriteFile(filepath.Join(backup, "manifest.json"), manifest, 0o600)
}

func copyFile(source, target string, info fs.FileInfo) error {
	input, err := os.Open(source)
	if err != nil {
		return err
	}
	defer input.Close()
	output, err := os.OpenFile(target, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	if _, err = io.Copy(output, input); err == nil {
		err = output.Chmod(info.Mode().Perm())
	}
	if closeErr := output.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	return os.Chtimes(target, info.ModTime(), info.ModTime())
}

// unixMode converts permission bits with setuid, setgid and sticky flags.
func unixMode(mode uint32) os.FileMode {
	result := os.FileMode(mode & 0o777)
	if mode&syscall.S_ISUID != 0 {
		result |= os.ModeSetuid
	}
	if mode&syscall.S_ISGID != 0 {
		result |= os.ModeSetgid
	}
	if mode&syscall.S_ISVTX != 0 {
		result |= os.ModeSticky
	}
	return result
}

func (d *Deployer) restore(backup string, records []Record) error {
	if d.Restore != nil {
		return d.Restore(backup, records)
	}
	return d.restoreFiles(backup, records)
}

func (d *Deployer) restoreFiles(backup string, records []Record) error {
	for _, record := range records {
		if d.userFiles != nil && d.userFiles.has(record.Target) {
			if err := d.userFiles.restore(backup, record); err != nil {
				return err
			}
			continue
		}
		if record.Present {
			if err := d.InstallFile(filepath.Join(backup, record.Copy), record.Target, unixMode(record.Mode)); err != nil {
				return err
			}
			if err := d.Chown(record.Target, record.UID, record.GID); err != nil {
				return err
			}
		} else if err := os.Remove(record.Target); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return err
		}
	}
	return nil
}

func (d *Deployer) ensureDirectory(path string, mode os.FileMode, owner string) error {
	if d.EnsureDir != nil {
		return d.EnsureDir(path, mode, owner)
	}
	uid, err := lookupUser(owner)
	if err != nil {
		return err
	}
	info, err := os.Lstat(path)
	if err == nil && info.Mode()&os.ModeSymlink != 0 {
		return errors.New("refusing a symlink directory")
	}
	if errors.Is(err, fs.ErrNotExist) {
		if err := os.Mkdir(path, mode); err != nil {
			return err
		}
		if err := os.Chmod(path, mode); err != nil {
			return err
		}
		if err := d.Chown(path, uid, 0); err != nil {
			return err
		}
		info, err = os.Lstat(path)
	}
	if err != nil {
		return err
	}
	forbidden := os.FileMode(0o022)
	if mode == 0o700 {
		forbidden = 0o077
	}
	if !info.IsDir() || info.Sys().(*syscall.Stat_t).Uid != uid || info.Mode().Perm()&forbidden != 0 {
		return errors.New("unsafe installed directory")
	}
	return nil
}

func (d *Deployer) checkInterrupted() error {
	if d.Interrupted() {
		return errors.New("deployment interrupted")
	}
	return nil
}

// Enable points the macOS HTTP and HTTPS proxies at the engine after a health
// check, saving the previous settings once for Rollback.
func (d *Deployer) Enable() error {
	if err := d.health(ProxyPort); err != nil {
		return err
	}
	saved, err := d.settings()
	if err != nil {
		return err
	}
	data, err := json.MarshalIndent(saved, "", "  ")
	if err != nil {
		return err
	}
	state, err := os.OpenFile(d.State, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	_, err = state.Write(data)
	if closeErr := state.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	for _, service := range Services {
		for _, kind := range Kinds {
			if _, err := d.Run("/usr/sbin/networksetup", "-set"+kind, service, "127.0.0.1", strconv.Itoa(ProxyPort)); err == nil {
				_, err = d.Run("/usr/sbin/networksetup", "-set"+kind+"state", service, "on")
			}
			if err != nil {
				if restoreErr := d.restoreSettings(saved); restoreErr != nil {
					return fmt.Errorf("%w; restoring previous settings failed: %v", err, restoreErr)
				}
				return err
			}
		}
	}
	return nil
}

// Rollback restores the macOS proxy settings saved by Enable.
func (d *Deployer) Rollback() error {
	data, err := os.ReadFile(d.State)
	if err != nil {
		return err
	}
	var saved proxySettings
	if err := json.Unmarshal(data, &saved); err != nil {
		return err
	}
	if err := d.restoreSettings(saved); err != nil {
		return err
	}
	fmt.Fprintln(d.Out, "Prior HTTP/HTTPS proxy settings restored; bypass lists untouched")
	return nil
}
