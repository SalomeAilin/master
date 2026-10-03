package deploy

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"syscall"
)

const acceptancePrefix = "network-domain-independent-backup."
const installationPrefix = "network-split-backup."

var installationFiles = []string{
	"china-route.sh", "network-split-guard.sh", "network-split-policy",
	"network-split-dns-event-route-agent", ToolName,
	"com.local.network-split-dns-event-route-agent.plist",
	"network_split_policy.py", "network-split-dns-event-route-agent.py",
	"network-domain-proxy-deploy.py", "network-split-dns-route-agent.py",
	"network-split-guard.before-log-fix.sh",
}

// Backup describes recognized contents, not permission to discard a recovery copy.
type Backup struct {
	Path  string            `json:"path"`
	Kind  string            `json:"kind"`
	Bytes int64             `json:"bytes"`
	Files map[string]string `json:"files_sha256"`
	Error string            `json:"error,omitempty"`
}

func (d *Deployer) snapshotTargets() []string {
	targets := []string{d.Binary, d.Config, d.Plist, d.Tool}
	for _, directory := range []string{d.Rules, d.Cache} {
		for _, name := range RuleNames {
			targets = append(targets, filepath.Join(directory, name+".json"))
		}
	}
	return targets
}

func backupKind(name string) string {
	for prefix, kind := range map[string]string{acceptancePrefix: "acceptance", installationPrefix: "installation"} {
		if !strings.HasPrefix(name, prefix) {
			continue
		}
		suffix := strings.TrimPrefix(name, prefix)
		if len(suffix) < 6 || len(suffix) > 32 {
			return ""
		}
		for _, c := range suffix {
			if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z') {
				return ""
			}
		}
		return kind
	}
	return ""
}

func (d *Deployer) backupParent() (*os.Root, error) {
	root, err := os.OpenRoot(d.BackupParent)
	if err != nil {
		return nil, err
	}
	info, err := root.Stat(".")
	if err != nil || int(info.Sys().(*syscall.Stat_t).Uid) != os.Geteuid() || info.Mode().Perm()&0o022 != 0 {
		root.Close()
		return nil, errors.New("unsafe backup parent directory")
	}
	return root, nil
}

func (d *Deployer) backupName(path string) (string, error) {
	name := filepath.Base(path)
	if backupKind(name) == "" || filepath.Clean(path) != path {
		return "", errors.New("specify one exact recognized backup name or absolute path")
	}
	if path == name {
		return name, nil
	}
	parent, err := filepath.EvalSymlinks(filepath.Dir(path))
	if err != nil {
		return "", err
	}
	expected, err := filepath.EvalSymlinks(d.BackupParent)
	if err != nil || !filepath.IsAbs(path) || parent != expected {
		return "", errors.New("backup must be a direct child of the backup directory")
	}
	return name, nil
}

func (d *Deployer) inspectBackup(parent *os.Root, name string) (Backup, fs.FileInfo, error) {
	result := Backup{Path: filepath.Join(d.BackupParent, name), Kind: backupKind(name), Files: map[string]string{}}
	info, err := parent.Lstat(name)
	if err != nil {
		return result, nil, err
	}
	if !info.IsDir() || info.Mode().Perm() != 0o700 || int(info.Sys().(*syscall.Stat_t).Uid) != os.Geteuid() {
		return result, nil, errors.New("backup must be a private owned directory, not a symlink")
	}
	root, err := parent.OpenRoot(name)
	if err != nil {
		return result, nil, err
	}
	defer root.Close()
	opened, err := root.Stat(".")
	if err != nil || !os.SameFile(info, opened) {
		return result, nil, errors.New("backup changed while opening")
	}
	entries, err := fs.ReadDir(root.FS(), ".")
	if err != nil {
		return result, nil, err
	}
	allowed := map[string]bool{}
	switch result.Kind {
	case "acceptance":
		manifestInfo, err := root.Lstat("manifest.json")
		if err != nil || !manifestInfo.Mode().IsRegular() || manifestInfo.Size() > 64<<10 {
			return result, nil, errors.New("manifest must be a bounded regular file")
		}
		manifest, err := root.Open("manifest.json")
		if err != nil {
			return result, nil, err
		}
		data, readErr := io.ReadAll(io.LimitReader(manifest, (64<<10)+1))
		manifest.Close()
		if readErr != nil || len(data) > 64<<10 {
			return result, nil, errors.New("unreadable or oversized backup manifest")
		}
		decoder := json.NewDecoder(bytes.NewReader(data))
		decoder.DisallowUnknownFields()
		var records []Record
		if err := decoder.Decode(&records); err != nil {
			return result, nil, err
		}
		targets := d.snapshotTargets()
		if decoder.Decode(new(any)) != io.EOF || len(records) != len(targets) {
			return result, nil, errors.New("unexpected backup manifest")
		}
		allowed["manifest.json"] = true
		for index, record := range records {
			if record.Target != targets[index] || record.Copy != strconv.Itoa(index) {
				return result, nil, errors.New("backup manifest does not match managed files")
			}
			if record.Present {
				allowed[record.Copy] = true
			}
		}
		if len(allowed) == 1 {
			return result, nil, errors.New("empty recovery snapshot")
		}
	case "installation":
		for _, file := range installationFiles {
			allowed[file] = true
		}
		for _, file := range []string{"china-route.sh", "network-split-guard.sh"} {
			if _, err := root.Lstat(file); err != nil {
				return result, nil, errors.New("installation backup lacks the route guards")
			}
		}
	default:
		return result, nil, errors.New("unrecognized backup kind")
	}
	if result.Kind == "acceptance" && len(entries) != len(allowed) {
		return result, nil, errors.New("backup contents do not match the manifest")
	}
	for _, entry := range entries {
		if !allowed[entry.Name()] {
			return result, nil, fmt.Errorf("unexpected backup entry %q", entry.Name())
		}
		fileInfo, err := root.Lstat(entry.Name())
		if err != nil {
			return result, nil, err
		}
		if !fileInfo.Mode().IsRegular() || fileInfo.Mode().Perm()&0o022 != 0 || fileInfo.Sys().(*syscall.Stat_t).Nlink != 1 {
			return result, nil, errors.New("backup contains a directory, link or writable file")
		}
		file, err := root.Open(entry.Name())
		if err != nil {
			return result, nil, err
		}
		digest, size, hashErr := hashFile(file)
		file.Close()
		if hashErr != nil {
			return result, nil, hashErr
		}
		result.Files[entry.Name()] = digest
		result.Bytes += size
	}
	return result, info, nil
}

func hashFile(file *os.File) (string, int64, error) {
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() > 64<<20 {
		return "", 0, errors.New("unsafe or oversized maintenance file")
	}
	hash := sha256.New()
	size, err := io.Copy(hash, io.LimitReader(file, (64<<20)+1))
	if err != nil || size > 64<<20 {
		return "", 0, errors.New("could not hash bounded maintenance file")
	}
	return hex.EncodeToString(hash.Sum(nil)), size, nil
}

// Backups lists metadata only. Invalid candidates are reported without deletion.
func (d *Deployer) Backups() ([]Backup, error) {
	parent, err := d.backupParent()
	if err != nil {
		return nil, err
	}
	defer parent.Close()
	names, err := backupDirectoryNames(parent)
	if err != nil {
		return nil, err
	}
	result := []Backup{}
	for _, name := range names {
		if backupKind(name) == "" {
			continue
		}
		backup, _, err := d.inspectBackup(parent, name)
		if err != nil {
			backup.Error = err.Error()
		}
		result = append(result, backup)
	}
	return result, nil
}

func backupDirectoryNames(parent *os.Root) ([]string, error) {
	directory, err := parent.Open(".")
	if err != nil {
		return nil, err
	}
	defer directory.Close()
	// Root.FS().ReadDir eagerly stats every entry, including protected unrelated
	// macOS databases. Select our names before inspecting any entry metadata.
	names, err := directory.Readdirnames(-1)
	slices.Sort(names)
	return names, err
}

func (d *Deployer) InspectBackup(path string) (Backup, error) {
	name, err := d.backupName(path)
	if err != nil {
		return Backup{}, err
	}
	parent, err := d.backupParent()
	if err != nil {
		return Backup{}, err
	}
	defer parent.Close()
	backup, _, err := d.inspectBackup(parent, name)
	return backup, err
}

type maintenanceState struct {
	PIDs  map[string]int
	Files map[string]string
}

func (d *Deployer) maintenanceState() (maintenanceState, error) {
	state := maintenanceState{PIDs: map[string]int{}, Files: map[string]string{}}
	sbin := filepath.Dir(d.Tool)
	services := map[string]string{
		Label: d.Binary,
		"system/com.local.network-split-dns-event-route-agent": filepath.Join(sbin, "network-split-dns-event-route-agent"),
		"system/homebrew.mxcl.dnsmasq":                         filepath.Join(sbin, "dnsmasq-network-split"),
	}
	for label, program := range services {
		details, err := d.Run("/bin/launchctl", "print", label)
		if err != nil {
			return state, err
		}
		values := map[string]string{}
		for _, line := range strings.Split(details, "\n") {
			if key, value, ok := strings.Cut(strings.TrimSpace(line), " = "); ok {
				if _, exists := values[key]; !exists {
					values[key] = value
				}
			}
		}
		pid, err := strconv.Atoi(values["pid"])
		if err != nil || pid <= 0 || values["state"] != "running" || values["program"] != program {
			return state, fmt.Errorf("%s is not running the expected program", label)
		}
		state.PIDs[label] = pid
	}
	files := []string{d.Binary, d.Config, d.Plist, d.Tool,
		filepath.Join(filepath.Dir(d.Config), "dnsmasq-network-split.conf"),
		filepath.Join(filepath.Dir(d.Plist), "com.local.network-split-dns-event-route-agent.plist")}
	for _, name := range []string{"network-split-policy", "network-split-dns-event-route-agent", "dnsmasq-network-split", "china-route.sh", "network-split-guard.sh"} {
		files = append(files, filepath.Join(sbin, name))
	}
	for _, path := range files {
		fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
		if err != nil {
			return state, err
		}
		file := os.NewFile(uintptr(fd), path)
		digest, _, err := hashFile(file)
		file.Close()
		if err != nil {
			return state, err
		}
		state.Files[path] = digest
	}
	return state, nil
}

// RemoveBackup is explicit and limited to one validated backup. The CLI holds
// the deployment lock. No network probes, shell interpreter or service reload is used.
func (d *Deployer) RemoveBackup(path string) error {
	name, err := d.backupName(path)
	if err != nil {
		return err
	}
	parent, err := d.backupParent()
	if err != nil {
		return err
	}
	defer parent.Close()
	backup, identity, err := d.inspectBackup(parent, name)
	if err != nil {
		return err
	}
	before, err := d.maintenanceState()
	if err != nil {
		return err
	}
	for _, args := range [][]string{
		{"/usr/bin/pgrep", "-f", `[/]deploy-security-update\.zsh([[:space:]]|$)`},
		{"/usr/sbin/lsof", "-nP", "-t", "+D", backup.Path},
	} {
		out, err := d.Run(args...)
		code, known := exitCode(err)
		if !known || code != 1 || strings.TrimSpace(out) != "" {
			return fmt.Errorf("backup may be in use or its use could not be checked: %s: %w", args[0], errors.Join(err, errors.New(strings.TrimSpace(out))))
		}
	}
	current, currentIdentity, err := d.inspectBackup(parent, name)
	if err != nil || !os.SameFile(identity, currentIdentity) || !reflect.DeepEqual(backup, current) {
		return errors.New("backup changed during validation; nothing removed")
	}
	ready, err := d.maintenanceState()
	if err != nil || !reflect.DeepEqual(before, ready) {
		return errors.New("runtime changed during validation; nothing removed")
	}
	if err := d.checkInterrupted(); err != nil {
		return err
	}
	// Remove validated flat contents through a directory handle. Unexpected new
	// entries make the final directory removal fail instead of expanding deletion.
	root, err := parent.OpenRoot(name)
	if err != nil {
		return err
	}
	defer root.Close()
	opened, err := root.Stat(".")
	if err != nil || !os.SameFile(identity, opened) {
		return errors.New("backup directory replaced before removal")
	}
	for _, file := range orderedKeys(backup.Files, nil) {
		if err := root.Remove(file); err != nil {
			return fmt.Errorf("backup removal incomplete at %s: %w", backup.Path, err)
		}
	}
	if err := parent.Remove(name); err != nil {
		return fmt.Errorf("backup removal incomplete at %s: %w", backup.Path, err)
	}
	if _, err := parent.Lstat(name); !errors.Is(err, fs.ErrNotExist) {
		return errors.New("backup removal could not be confirmed")
	}
	after, err := d.maintenanceState()
	if err != nil || !reflect.DeepEqual(before, after) {
		return fmt.Errorf("backup removed, but unchanged runtime could not be confirmed: %w", errors.Join(err, errors.New("service or installed-file state changed")))
	}
	fmt.Fprintln(d.Out, "Removed backup:", backup.Path, "(service PIDs and installed hashes unchanged)")
	return nil
}

// InstallTool updates only the maintenance executable using the existing atomic
// installer, so adding maintenance commands never requires a proxy restart.
func (d *Deployer) InstallTool() error {
	before, err := d.maintenanceState()
	if err != nil {
		return err
	}
	backups, err := d.Backups()
	if err != nil {
		return fmt.Errorf("backup inventory preflight failed; tool not replaced: %w", err)
	}
	source := filepath.Join(d.Root, ToolName)
	file, err := os.Open(source)
	if err != nil {
		return err
	}
	digest, _, err := hashFile(file)
	file.Close()
	if err != nil {
		return err
	}
	if err := d.checkInterrupted(); err != nil {
		return err
	}
	if err := d.InstallFile(source, d.Tool, 0o755); err != nil {
		return err
	}
	before.Files[d.Tool] = digest
	after, err := d.maintenanceState()
	if err != nil || !reflect.DeepEqual(before, after) {
		return errors.New("tool installed, but its hash and unchanged runtime could not be confirmed")
	}
	fmt.Fprintln(d.Out, "Maintenance tool installed; service PIDs and other installed hashes unchanged")
	fmt.Fprintf(d.Out, "Backup inventory verified: %d candidate(s)\n", len(backups))
	return nil
}
