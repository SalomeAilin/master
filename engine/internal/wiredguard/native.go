package wiredguard

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"golang.org/x/sys/unix"
	"io"
	"net"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"
)

type Native struct {
	Store    Store
	Account  Account
	Listener net.Listener
}

func LookupAccount(uid uint32) (Account, error) {
	a := Account{UID: uid}
	if uid == 0 || uid > 2147483647 {
		return a, errors.New("a real unprivileged account is required")
	}
	u, err := user.LookupId(strconv.FormatUint(uint64(uid), 10))
	if err != nil {
		return a, err
	}
	gid, err := strconv.ParseUint(u.Gid, 10, 32)
	if err != nil {
		return a, err
	}
	a.GID, a.Name, a.Home = uint32(gid), u.Username, u.HomeDir
	groups, err := u.GroupIds()
	if err != nil {
		return a, err
	}
	a.Groups, err = accountGroups(a.GID, groups)
	if err != nil {
		return a, err
	}
	if !filepath.IsAbs(a.Home) {
		return a, errors.New("account home cannot be preserved safely")
	}
	return a, nil
}

func accountGroups(primary uint32, groups []string) ([]uint32, error) {
	result := []uint32{primary}
	for _, raw := range groups {
		g, err := strconv.ParseUint(raw, 10, 32)
		if err != nil {
			return nil, err
		}
		if !slices.Contains(result, uint32(g)) {
			result = append(result, uint32(g))
		}
	}
	if len(result) > 16 {
		return nil, errors.New("account supplementary groups exceed the Darwin limit")
	}
	return result, nil
}

func (n *Native) Inspect(ctx context.Context, s *State) (Snapshot, error) {
	snap, err := nativeSnapshot(ctx, n.Account.UID)
	if err != nil {
		return snap, err
	}
	if s != nil && s.Proxy != nil {
		p, e := nativeIdentity(s.Proxy.PID)
		if e == nil {
			snap.Processes = append(snap.Processes, p)
		} else if !os.IsNotExist(e) {
			return snap, e
		}
	}
	if s != nil && s.Launcher != nil {
		p, e := nativeIdentity(s.Launcher.PID)
		if e == nil {
			snap.Processes = append(snap.Processes, p)
		} else if !os.IsNotExist(e) {
			return snap, e
		}
	}
	return snap, nil
}
func (n *Native) Save(s State) error { return n.Store.Save(s) }

type boundedOutput struct{ bytes.Buffer }

func (w *boundedOutput) Write(p []byte) (int, error) {
	if w.Len()+len(p) > 1<<20 {
		return 0, errors.New("system command output exceeds limit")
	}
	return w.Buffer.Write(p)
}

func command(ctx context.Context, input string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, args[0], args[1:]...)
	cmd.Env = []string{"PATH=/usr/bin:/bin:/usr/sbin:/sbin", "LC_ALL=C"}
	if input != "" {
		cmd.Stdin = strings.NewReader(input)
	}
	var output boundedOutput
	cmd.Stdout, cmd.Stderr = &output, &output
	err := cmd.Run()
	if err != nil {
		return output.String(), fmt.Errorf("%s: %w: %s", filepath.Base(args[0]), err, output.String())
	}
	return output.String(), nil
}

func pf(ctx context.Context, input string, args ...string) (string, error) {
	output, err := command(ctx, input, append([]string{"/sbin/pfctl"}, args...)...)
	return cleanPFOutput(output), err
}

func cleanPFOutput(output string) string {
	var lines []string
	for _, line := range strings.Split(output, "\n") {
		switch strings.TrimSpace(line) {
		case "No ALTQ support in kernel", "ALTQ related functions disabled":
			continue
		}
		lines = append(lines, line)
	}
	return strings.Join(lines, "\n")
}

func (n *Native) pfSnapshot(ctx context.Context) (PFSnapshot, error) {
	p := PFSnapshot{Filters: map[string]string{}, Translations: map[string]string{}}
	var err error
	if p.Root, err = pf(ctx, "", "-sr"); err != nil {
		return p, err
	}
	if p.NAT, err = pf(ctx, "", "-sn"); err != nil {
		return p, err
	}
	if p.Interfaces, err = pf(ctx, "", "-v", "-s", "Interfaces"); err != nil {
		return p, err
	}
	if p.States, err = pf(ctx, "", "-ss"); err != nil {
		return p, err
	}
	queue := []string{"com.apple"}
	seen := map[string]bool{}
	for len(queue) > 0 {
		anchor := queue[0]
		queue = queue[1:]
		if seen[anchor] {
			continue
		}
		seen[anchor] = true
		if len(seen) > 128 || strings.Count(anchor, "/") > 8 {
			return p, errors.New("PF anchor inventory exceeds limit")
		}
		if p.Filters[anchor], err = pf(ctx, "", "-a", anchor, "-sr"); err != nil {
			return p, err
		}
		if p.Translations[anchor], err = pf(ctx, "", "-a", anchor, "-sn"); err != nil {
			return p, err
		}
		children, err := pf(ctx, "", "-a", anchor, "-s", "Anchors")
		if err != nil {
			return p, err
		}
		for _, child := range nonemptyLines(children) {
			child = strings.Trim(child, "\"")
			child = strings.TrimPrefix(child, anchor+"/")
			if !regexp.MustCompile(`^[A-Za-z0-9_.-]+$`).MatchString(child) {
				return p, errors.New("unrecognized PF child anchor listing")
			}
			queue = append(queue, anchor+"/"+child)
		}
	}
	return p, nil
}

func (n *Native) Preflight(ctx context.Context, s *State) error {
	if err := trustedExecutable(App); err != nil {
		return err
	}
	if _, err := command(ctx, "", "/usr/bin/codesign", "--verify", "--deep", "--strict", "-R", `anchor apple generic and certificate leaf[subject.OU] = "LKD5676Y5W" and identifier "com.baidu.netdisk"`, AppBundle); err != nil {
		return err
	}
	wired, err := installedWiredInterface(ctx, true)
	if err != nil {
		return err
	}
	if s != nil && wired != s.Wired {
		return errors.New("installed wired policy changed during the session")
	}
	device, err := net.InterfaceByName(wired)
	if err != nil {
		return err
	}
	if device.Flags&net.FlagUp == 0 {
		return errors.New("configured wired interface is down")
	}
	if _, err := net.InterfaceByName("en999"); err == nil {
		return errors.New("the closed foreign interface en999 unexpectedly exists")
	}
	p, err := n.pfSnapshot(ctx)
	if err != nil {
		return err
	}
	p.Wired = wired
	if s == nil {
		return ValidatePF(p, "")
	}
	actual := p.Filters[Anchor]
	if actual == "" || Digest(actual) != s.RuleHash {
		return errors.New("PF barrier is missing or changed; refusing to release or launch")
	}
	if err := ValidateLoadedRules(actual, *s, n.Account.Name); err != nil {
		return err
	}
	return ValidatePF(p, actual)
}

func trustedExecutable(path string) error {
	for current := path; current != "/"; current = filepath.Dir(current) {
		info, err := os.Lstat(current)
		if err != nil {
			return err
		}
		st, ok := info.Sys().(*syscall.Stat_t)
		standardApplications := ok && path == App && current == "/Applications" && st.Gid == 80 && info.IsDir() && info.Mode().Perm() == 0775
		if !ok || st.Uid != 0 || info.Mode()&os.ModeSymlink != 0 || (info.Mode().Perm()&0022 != 0 && !standardApplications) {
			return fmt.Errorf("unsafe privileged executable or parent: %s", current)
		}
		if current == path && (!info.Mode().IsRegular() || info.Mode().Perm()&0111 == 0 || st.Nlink != 1) {
			return errors.New("privileged executable is not a unique regular executable")
		}
	}
	return nil
}

func (n *Native) Enable(ctx context.Context) (string, error) {
	output, err := pf(ctx, "", "-E")
	if err != nil {
		return "", err
	}
	match := regexp.MustCompile(`(?m)Token\s*:\s*([0-9]+)`).FindStringSubmatch(output)
	if len(match) != 2 {
		return "", errors.New("PF enabled but its token was not recognized; manual inspection required")
	}
	return match[1], nil
}

func (n *Native) Load(ctx context.Context, s State) (string, error) {
	if _, err := pf(ctx, Rules(s.UID, s.GID), "-a", Anchor, "-f", "-"); err != nil {
		return "", err
	}
	actual, err := pf(ctx, "", "-a", Anchor, "-sr")
	if err != nil {
		return "", err
	}
	if err = ValidateLoadedRules(actual, s, n.Account.Name); err != nil {
		return "", err
	}
	return Digest(actual), nil
}

func (n *Native) Verify(ctx context.Context, s State) error {
	p, err := n.pfSnapshot(ctx)
	if err != nil {
		return err
	}
	p.Wired = s.Wired
	actual := p.Filters[Anchor]
	if actual == "" || Digest(actual) != s.RuleHash {
		return errors.New("PF barrier is missing or changed")
	}
	if err = ValidateLoadedRules(actual, s, n.Account.Name); err != nil {
		return err
	}
	if err = ValidatePF(p, actual); err != nil {
		return err
	}
	info, err := pf(ctx, "", "-s", "info")
	if err != nil {
		return err
	}
	if !strings.Contains(info, "Status: Enabled") {
		return errors.New("PF is not enabled; controlled session is unsafe")
	}
	references, err := pf(ctx, "", "-s", "References")
	if err != nil {
		return err
	}
	if s.Token == "" || !regexp.MustCompile(`(^|[^0-9])`+regexp.QuoteMeta(s.Token)+`([^0-9]|$)`).MatchString(references) {
		return errors.New("session PF enable token is missing")
	}
	return nil
}

func (n *Native) Clear(ctx context.Context, s State) error {
	present, err := n.ReleaseBarrier(ctx, s)
	if err != nil || !present {
		return err
	}
	_, err = pf(ctx, "", "-a", Anchor, "-F", "rules")
	return err
}
func (n *Native) ReleaseBarrier(ctx context.Context, s State) (bool, error) {
	if !releasing(s.Phase) {
		return false, errors.New("no durable release intent")
	}
	p, err := n.pfSnapshot(ctx)
	if err != nil {
		return false, err
	}
	p.Wired = s.Wired
	actual := p.Filters[Anchor]
	if actual != "" {
		if Digest(actual) != s.RuleHash {
			return false, errors.New("unexpected PF rules during release; refusing cleanup")
		}
		if err = ValidateLoadedRules(actual, s, n.Account.Name); err != nil {
			return false, err
		}
	}
	if err = ValidatePF(p, actual); err != nil {
		return false, err
	}
	return actual != "", nil
}
func (n *Native) DisableReference(ctx context.Context, token string) error {
	references, err := pf(ctx, "", "-s", "References")
	if err != nil {
		return err
	}
	if !regexp.MustCompile(`(^|[^0-9])` + regexp.QuoteMeta(token) + `([^0-9]|$)`).MatchString(references) {
		return nil
	}
	_, err = pf(ctx, "", "-X", token)
	return err
}

func proxyConfiguration(cache, wired string) []byte {
	egress := func(iface string) map[string]any {
		return map[string]any{"interface": iface, "dns": map[string]string{"address": "223.5.5.5", "server_name": "dns.alidns.com"}}
	}
	var sources []map[string]string
	for _, kind := range []string{"domestic", "foreign", "china"} {
		sources = append(sources, map[string]string{"kind": kind, "url": "http://127.0.0.1:1/disabled", "seed": "/usr/local/etc/network-domain-rules-independent/" + kind + ".json", "interval": "168h"})
	}
	data, _ := json.Marshal(map[string]any{"version": 1, "listen": fmt.Sprintf("127.0.0.1:%d", Port), "max_clients": 512, "domestic": egress(wired), "foreign": egress("en999"), "protected_foreign": map[string]any{}, "local_domestic": map[string]any{"domain_regex": []string{".*"}}, "china_cidr": []string{"0.0.0.0/0"}, "cache_directory": cache, "rule_sources": sources})
	return data
}

func (n *Native) LaunchProxy(ctx context.Context, s *State) (Identity, error) {
	var zero Identity
	if s.Cache != "" {
		return zero, errors.New("proxy cache already recorded")
	}
	listener, err := net.Listen("tcp4", fmt.Sprintf("127.0.0.1:%d", Port))
	if err != nil {
		return zero, err
	}
	ready := false
	defer func() {
		if !ready {
			listener.Close()
		}
	}()
	n.Listener = listener
	file, err := listener.(*net.TCPListener).File()
	if err != nil {
		listener.Close()
		return zero, err
	}
	defer file.Close()
	dir, err := os.MkdirTemp("/private/tmp", "network-domain-wired-app.")
	if err != nil {
		return zero, err
	}
	if err = os.Chmod(dir, 0711); err != nil {
		os.Remove(dir)
		return zero, err
	}
	s.Cache = dir
	if err = n.Save(*s); err != nil {
		_ = os.Remove(dir)
		s.Cache = ""
		return zero, err
	}
	nobody, err := user.Lookup("nobody")
	if err != nil {
		return zero, err
	}
	uid64, err := strconv.ParseUint(nobody.Uid, 10, 32)
	if err != nil {
		return zero, err
	}
	uid := uint32(uid64)
	gid64, err := strconv.ParseUint(nobody.Gid, 10, 32)
	if err != nil {
		return zero, err
	}
	gid := uint32(gid64)
	workerDir := filepath.Join(dir, "worker")
	if err = os.Mkdir(workerDir, 0700); err != nil {
		return zero, err
	}
	if err = os.Chown(workerDir, int(uid), int(gid)); err != nil {
		return zero, err
	}
	read, write, err := os.Pipe()
	if err != nil {
		return zero, err
	}
	defer read.Close()
	cmd := exec.Command(Binary, "run", "-c", "/dev/fd/3", "-listen-fd", "4", "-log-file", filepath.Join(workerDir, "proxy.log"), "-log-max-size", "1048576", "-log-max-backups", "1")
	cmd.ExtraFiles = []*os.File{read, file}
	cmd.Env = []string{"PATH=/usr/bin:/bin:/usr/sbin:/sbin", "LC_ALL=C"}
	cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: uid, Gid: gid, Groups: []uint32{}}, Setpgid: true}
	if err = cmd.Start(); err != nil {
		write.Close()
		return zero, err
	}
	exited := make(chan error, 1)
	go func() { exited <- cmd.Wait(); close(exited) }()
	defer func() {
		if !ready {
			cmd.Process.Signal(syscall.SIGTERM)
			listener.Close()
			select {
			case <-exited:
			case <-time.After(3 * time.Second):
				cmd.Process.Kill()
				select {
				case <-exited:
				case <-time.After(time.Second):
				}
			}
		}
	}()
	_, writeErr := write.Write(proxyConfiguration(workerDir, s.Wired))
	closeErr := write.Close()
	if writeErr != nil || closeErr != nil {
		return zero, errors.Join(writeErr, closeErr)
	}
	for deadline := time.Now().Add(12 * time.Second); time.Now().Before(deadline); {
		select {
		case err := <-exited:
			return zero, fmt.Errorf("temporary proxy exited: %v", err)
		default:
		}
		identity, err := findProcess(ctx, cmd.Process.Pid, uid)
		if err == nil {
			if s.Proxy == nil {
				s.Proxy = &identity
				if err = n.Save(*s); err != nil {
					return zero, err
				}
			}
			if proxyReady(fmt.Sprintf("127.0.0.1:%d", Port)) == nil {
				ready = true
				return identity, nil
			}
		}
		if err = wait(ctx, 100*time.Millisecond); err != nil {
			return zero, err
		}
	}
	return zero, errors.New("temporary proxy did not become ready; barrier and private cache retained")
}

func proxyReady(address string) error {
	connection, err := net.DialTimeout("tcp4", address, 200*time.Millisecond)
	if err != nil {
		return err
	}
	defer connection.Close()
	if err = connection.SetDeadline(time.Now().Add(time.Second)); err != nil {
		return err
	}
	if _, err = connection.Write([]byte{5, 1, 0}); err != nil {
		return err
	}
	var response [2]byte
	if _, err = io.ReadFull(connection, response[:]); err != nil {
		return err
	}
	if response != [2]byte{5, 0} {
		return errors.New("temporary proxy did not accept SOCKS5 greeting")
	}
	return nil
}

func findProcess(ctx context.Context, pid int, uid uint32) (Identity, error) {
	if err := ctx.Err(); err != nil {
		return Identity{}, err
	}
	p, err := nativeIdentity(pid)
	if err != nil {
		return Identity{}, err
	}
	if p.UID != uid {
		return Identity{}, errors.New("process UID changed")
	}
	return p, nil
}

func (n *Native) LaunchApp(ctx context.Context, s *State) (Identity, error) {
	if err := n.Verify(ctx, *s); err != nil {
		return Identity{}, err
	}
	cmd := exec.Command("/bin/launchctl", "asuser", strconv.Itoa(int(s.UID)), Binary, "wired-app", "_launch", "-uid", strconv.Itoa(int(s.UID)))
	cmd.Env = []string{"PATH=/usr/bin:/bin:/usr/sbin:/sbin", "LC_ALL=C"}
	output, err := cmd.StdoutPipe()
	if err != nil {
		return Identity{}, err
	}
	ack, err := cmd.StdinPipe()
	if err != nil {
		return Identity{}, err
	}
	defer ack.Close()
	if err := cmd.Start(); err != nil {
		return Identity{}, err
	}
	exited := make(chan error, 1)
	go func() { exited <- cmd.Wait() }()
	type hello struct {
		identity Identity
		err      error
	}
	hellos := make(chan hello, 1)
	go func() {
		var p Identity
		err := json.NewDecoder(io.LimitReader(output, 4096)).Decode(&p)
		hellos <- hello{p, err}
	}()
	select {
	case h := <-hellos:
		if h.err != nil {
			return Identity{}, h.err
		}
		current, err := nativeIdentity(h.identity.PID)
		if err != nil || !SameProcess(current, h.identity) || current.Path != Binary || current.UID != 0 || current.GID != 0 {
			return Identity{}, errors.New("GUI launcher did not prove its root process identity")
		}
		s.Launcher = &current
		if err = n.Save(*s); err != nil {
			return Identity{}, err
		}
		if _, err = ack.Write([]byte{1}); err != nil {
			return Identity{}, err
		}
	case <-ctx.Done():
		return Identity{}, ctx.Err()
	case <-time.After(15 * time.Second):
		return Identity{}, errors.New("GUI producer handshake timed out; launch remains unacknowledged")
	}
	for deadline := time.Now().Add(15 * time.Second); time.Now().Before(deadline); {
		select {
		case err := <-exited:
			return Identity{}, fmt.Errorf("GUI launcher exited: %v", err)
		default:
		}
		snap, err := n.Inspect(ctx, s)
		if err != nil {
			return Identity{}, err
		}
		for _, p := range snap.Processes {
			if p.Path == App && p.UID == s.UID && p.GID == s.GID && p.RealGID == s.GID && p.SavedGID == s.GID {
				return p, nil
			}
		}
		if err = wait(ctx, 100*time.Millisecond); err != nil {
			return Identity{}, err
		}
	}
	return Identity{}, errors.New("GUI app did not present the required process identity; barrier retained")
}

func (n *Native) StopProxy(ctx context.Context, identity Identity) error {
	current, err := findProcess(ctx, identity.PID, identity.UID)
	if os.IsNotExist(err) {
		if n.Listener != nil {
			n.Listener.Close()
			n.Listener = nil
		}
		return nil
	}
	if err != nil {
		return err
	}
	if !SameProcess(current, identity) || current.Path != Binary {
		return errors.New("proxy PID identity changed; refusing to signal it")
	}
	if err = syscall.Kill(identity.PID, syscall.SIGTERM); err != nil {
		return err
	}
	for deadline := time.Now().Add(6 * time.Second); time.Now().Before(deadline); {
		_, err = findProcess(ctx, identity.PID, identity.UID)
		if os.IsNotExist(err) {
			if n.Listener != nil {
				n.Listener.Close()
				n.Listener = nil
			}
			return nil
		}
		if err != nil {
			return err
		}
		if err = wait(ctx, 100*time.Millisecond); err != nil {
			return err
		}
	}
	return errors.New("proxy has not exited; barrier retained")
}

func wait(ctx context.Context, d time.Duration) error {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func (n *Native) Remove() error {
	s, err := n.Store.Read()
	if err != nil {
		return err
	}
	if s.Cache != "" {
		if err = removeCache(s.Cache); err != nil {
			return err
		}
	}
	return n.Store.Remove()
}

func removeCache(path string) error {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	root := os.NewFile(uintptr(fd), path)
	defer root.Close()
	var st unix.Stat_t
	if err = unix.Fstat(fd, &st); err != nil {
		return err
	}
	if st.Uid != 0 || st.Mode&0777 != 0711 {
		return errors.New("unsafe root-owned proxy cache parent")
	}
	names, err := root.Readdirnames(-1)
	if err != nil {
		return err
	}
	if len(names) > 1 || (len(names) == 1 && names[0] != "worker") {
		return errors.New("unexpected root cache contents; retained")
	}
	if len(names) == 1 {
		workerFD, err := unix.Openat(fd, "worker", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if err != nil {
			return err
		}
		worker := os.NewFile(uintptr(workerFD), "private proxy worker cache")
		defer worker.Close()
		if err = unix.Fstat(workerFD, &st); err != nil {
			return err
		}
		if (st.Uid != 0 && st.Uid != 4294967294) || st.Mode&0777 != 0700 {
			return errors.New("unsafe private proxy worker cache")
		}
		entries, err := worker.Readdirnames(-1)
		if err != nil {
			return err
		}
		for _, name := range entries {
			if name != "proxy.log" && name != "proxy.log.1" {
				return errors.New("unexpected worker cache contents; retained")
			}
			if err = unix.Fstatat(workerFD, name, &st, unix.AT_SYMLINK_NOFOLLOW); err != nil {
				return err
			}
			if st.Mode&unix.S_IFMT != unix.S_IFREG || st.Nlink != 1 || st.Uid != 4294967294 {
				return errors.New("unsafe worker cache entry; retained")
			}
		}
		for _, name := range entries {
			if err = unix.Unlinkat(workerFD, name, 0); err != nil {
				return err
			}
		}
		if err = unix.Unlinkat(fd, "worker", unix.AT_REMOVEDIR); err != nil {
			return err
		}
	}
	// The sticky tmp directory prevents nobody from replacing this root-owned
	// parent; the worker never has write permission in its parent directory.
	return os.Remove(path)
}

func RequireInstalled() error {
	if os.Geteuid() != 0 || os.Getegid() != 0 {
		return errors.New("administrator authorization is required")
	}
	executable, err := os.Executable()
	if err != nil {
		return err
	}
	if executable != Binary {
		return errors.New("wired session changes require the installed engine executable")
	}
	return trustedExecutable(Binary)
}

// launchChild runs only after asuser selected the GUI bootstrap. It drops all
// real/effective/saved IDs in a fresh child before the original app can run.
func (n *Native) launchChild(ctx context.Context, s State) error {
	if s.Phase != "launching" || !s.LaunchPending || s.UID != n.Account.UID {
		return errors.New("no matching GUI launch intent")
	}
	if err := n.Verify(ctx, s); err != nil {
		return err
	}
	snap, err := n.Inspect(ctx, &s)
	if err != nil {
		return err
	}
	for _, p := range snap.Processes {
		if IsBaidu(p) {
			return errors.New("Baidu already running; GUI launch refused")
		}
	}
	self, err := nativeIdentity(os.Getpid())
	if err != nil {
		return err
	}
	if err = json.NewEncoder(os.Stdout).Encode(self); err != nil {
		return err
	}
	var ack [1]byte
	if _, err = io.ReadFull(os.Stdin, ack[:]); err != nil || ack[0] != 1 {
		return errors.New("GUI launch was not acknowledged; app remains stopped")
	}
	stored, err := n.Store.Read()
	if err != nil {
		return err
	}
	if stored.Phase != "launching" || stored.Launcher == nil || !SameProcess(self, *stored.Launcher) || stored.UID != s.UID || stored.GID != s.GID {
		return errors.New("GUI launch ownership changed before application creation")
	}
	cmd := exec.Command(App)
	cmd.Env = []string{"PATH=/usr/bin:/bin:/usr/sbin:/sbin", "HOME=" + n.Account.Home, "USER=" + n.Account.Name, "LOGNAME=" + n.Account.Name, "TMPDIR=/tmp/", "LC_ALL=C"}
	cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: s.UID, Gid: s.GID, Groups: n.Account.Groups}, Setpgid: true}
	return cmd.Run()
}

func SelectGID(account Account, snap Snapshot) (uint32, error) {
	for gid := uint32(62000); gid <= 62127; gid++ {
		if gid == account.GID || slices.Contains(account.Groups, gid) {
			continue
		}
		_, err := user.LookupGroupId(strconv.Itoa(int(gid)))
		var unknown user.UnknownGroupIdError
		if err == nil {
			continue
		}
		if !errors.As(err, &unknown) {
			return 0, err
		}
		used := false
		for _, p := range snap.Processes {
			if p.GID == gid || p.RealGID == gid || p.SavedGID == gid {
				used = true
			}
		}
		for _, socket := range snap.Sockets {
			if socket.GID == gid {
				used = true
			}
		}
		if !used {
			return gid, nil
		}
	}
	return 0, errors.New("no unclaimed dedicated GID is available")
}

var _ io.Writer = (*boundedOutput)(nil)
