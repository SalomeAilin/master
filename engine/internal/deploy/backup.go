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

	"network-owned-engine/internal/runtimecheck"
	"network-owned-engine/internal/service"
)

const acceptancePrefix = "network-domain-independent-backup."
const installationPrefix = "network-split-backup."
const unifiedPrefix = "network-unified-backup."
const softwarePrefix = "network-software-update."
const legacySoftwareArchive = "sing-box-1.14.2-darwin-arm64"

var installationFiles = []string{
	"china-route.sh", "network-split-guard.sh", "network-split-policy",
	"network-split-dns-event-route-agent", ToolName,
	"com.local.network-split-dns-event-route-agent.plist",
	"network_split_policy.py", "network-split-dns-event-route-agent.py",
	"network-domain-proxy-deploy.py", "network-split-dns-route-agent.py",
	"network-split-guard.before-log-fix.sh",
}

// Backup records a candidate and any validated contents, not permission to discard it.
type Backup struct {
	Path        string            `json:"path"`
	Kind        string            `json:"kind"`
	Bytes       int64             `json:"bytes"`
	Files       map[string]string `json:"files_sha256"`
	Directories []string          `json:"directories,omitempty"`
	Error       string            `json:"error,omitempty"`
}

func (d *Deployer) snapshotTargets() []string {
	plist, tool := d.Plist, d.Tool
	if d.Tool == d.Binary {
		plist = filepath.Join(filepath.Dir(d.SupervisorPlist), PlistName)
		tool = filepath.Join(filepath.Dir(filepath.Dir(d.Binary)), "sbin", ToolName)
	}
	targets := []string{d.Binary, d.Config, plist, tool}
	for _, directory := range []string{d.Rules, d.Cache} {
		for _, name := range RuleNames {
			targets = append(targets, filepath.Join(directory, name+".json"))
		}
	}
	return targets
}

func backupKind(name string) string {
	for prefix, kind := range map[string]string{acceptancePrefix: "acceptance", installationPrefix: "installation", unifiedPrefix: "unified", softwarePrefix: "software-update"} {
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

func (d *Deployer) backupParent() (*os.Root, error) { return runtimecheck.OpenRoot(d.BackupParent) }

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
	if result.Kind == "software-update" {
		result, err = inspectSoftwareBackup(root, result)
		return result, info, err
	}
	entries, err := fs.ReadDir(root.FS(), ".")
	if err != nil {
		return result, nil, err
	}
	allowed := map[string]bool{}
	optional := map[string]bool{}
	switch result.Kind {
	case "acceptance", "unified":
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
		if result.Kind == "unified" {
			c, err := service.Load(d.layout(service.Config{}).Config, d.unifiedLayout == nil)
			if err != nil {
				return result, nil, err
			}
			legacy := c
			legacy.Version = 1
			legacy.Routes.DNSBinary = service.ProductionRoutes().DNSBinary
			native := c
			native.Version = 2
			native.Routes.DNSBinary = service.Binary
			migration := append(d.unifiedTargets(legacy, false), d.unifiedTargets(native, false)...)
			migration = append(migration, d.legacyDNSBinary(legacy))
			slices.Sort(migration)
			migration = slices.Compact(migration)
			targets = nil
			for _, candidate := range [][]string{d.unifiedTargets(legacy, true), d.unifiedTargets(legacy, false), d.unifiedTargets(native, false), migration} {
				if len(candidate) != len(records) {
					continue
				}
				matched := true
				for i := range records {
					if records[i].Target != candidate[i] {
						matched = false
						break
					}
				}
				if matched {
					targets = candidate
					break
				}
			}
			for i := range d.managedJobs(c) {
				optional[fmt.Sprintf("job-%d.plist", i)] = true
			}
			optional["parent.plist"], optional["newsyslog.conf"] = true, true
			optional["service.json"] = true
			optional["firewall.json"] = true
		}
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
		if !allowed[entry.Name()] && !optional[entry.Name()] {
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
	for required := range allowed {
		if _, ok := result.Files[required]; !ok && result.Kind != "installation" {
			return result, nil, errors.New("backup is missing a required snapshot")
		}
	}
	return result, info, nil
}

func hashFile(file *os.File) (string, int64, error) { return runtimecheck.HashFile(file) }

// This retired updater had one release directory and two previous binaries.
// Keep the recognized layout narrow; arbitrary nested backups are not removable.
func inspectSoftwareBackup(root *os.Root, result Backup) (Backup, error) {
	names, err := runtimecheck.DirectoryNames(root)
	want := []string{"previous-dnsmasq", "previous-sing-box", legacySoftwareArchive}
	if err != nil || !slices.Equal(names, want) {
		return result, errors.New("software backup must contain exactly the known previous binaries and release directory")
	}
	info, err := root.Lstat(legacySoftwareArchive)
	if err != nil || !info.IsDir() || info.Mode().Perm()&0o022 != 0 {
		return result, errors.New("software backup release directory is unsafe")
	}
	release, err := root.OpenRoot(legacySoftwareArchive)
	if err != nil {
		return result, err
	}
	defer release.Close()
	opened, err := release.Stat(".")
	if err != nil || !os.SameFile(info, opened) {
		return result, errors.New("software backup release directory changed")
	}
	names, err = runtimecheck.DirectoryNames(release)
	if err != nil || !slices.Equal(names, []string{"LICENSE", "sing-box"}) {
		return result, errors.New("unexpected software backup release contents")
	}
	for _, entry := range []struct {
		root      *os.Root
		name, key string
		limit     int64
	}{
		{root, "previous-dnsmasq", "previous-dnsmasq", 16 << 20},
		{root, "previous-sing-box", "previous-sing-box", 128 << 20},
		{release, "LICENSE", legacySoftwareArchive + "/LICENSE", 64 << 10},
		{release, "sing-box", legacySoftwareArchive + "/sing-box", 128 << 20},
	} {
		digest, size, err := hashSoftwareFile(entry.root, entry.name, entry.limit)
		if err != nil {
			return result, err
		}
		result.Files[entry.key] = digest
		result.Bytes += size
		if result.Bytes > 256<<20 {
			return result, errors.New("software backup exceeds total size limit")
		}
	}
	result.Directories = []string{legacySoftwareArchive}
	return result, nil
}

func hashSoftwareFile(root *os.Root, name string, limit int64) (string, int64, error) {
	info, err := root.Lstat(name)
	if err != nil {
		return "", 0, err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0o022 != 0 || info.Sys().(*syscall.Stat_t).Nlink != 1 || info.Size() <= 0 || info.Size() > limit {
		return "", 0, fmt.Errorf("unsafe or oversized software backup file: %s", name)
	}
	file, err := root.Open(name)
	if err != nil {
		return "", 0, err
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !os.SameFile(info, opened) {
		return "", 0, errors.New("software backup file changed while opening")
	}
	hash := sha256.New()
	size, err := io.Copy(hash, io.LimitReader(file, limit+1))
	after, statErr := file.Stat()
	if err != nil || statErr != nil || size != info.Size() || size > limit || after.Size() != info.Size() || !after.ModTime().Equal(info.ModTime()) {
		return "", 0, errors.New("software backup changed during hashing")
	}
	return hex.EncodeToString(hash.Sum(nil)), size, nil
}

// Backups inspects known layouts and reports unknown backup-like names in the
// backup parent. It neither scans other directories nor authorizes deletion.
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
			if strings.HasPrefix(name, "network-") && (strings.Contains(name, "backup") || strings.Contains(name, "software-update")) {
				result = append(result, Backup{Path: filepath.Join(d.BackupParent, name), Kind: "unrecognized", Error: "unrecognized backup candidate; contents not inspected and deletion not permitted"})
			}
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
	return runtimecheck.DirectoryNames(parent)
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

type maintenanceState = runtimecheck.State

func (d *Deployer) maintenanceState() (maintenanceState, error) {
	return runtimecheck.Inspect(d.Paths, d.Run)
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
	if backup.Kind == "software-update" && (!d.NativeDNS || d.Tool != d.Binary) {
		return errors.New("software backup removal requires the unified program with native DNS")
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
	// Remove only validated files through directory handles. Unexpected entries
	// make directory removal fail instead of expanding deletion recursively.
	root, err := parent.OpenRoot(name)
	if err != nil {
		return err
	}
	defer root.Close()
	opened, err := root.Stat(".")
	if err != nil || !os.SameFile(identity, opened) {
		return errors.New("backup directory replaced before removal")
	}
	for _, directory := range backup.Directories {
		sub, err := root.OpenRoot(directory)
		if err != nil {
			return err
		}
		for _, file := range orderedKeys(backup.Files, nil) {
			if name, ok := strings.CutPrefix(file, directory+"/"); ok {
				if err := sub.Remove(name); err != nil {
					sub.Close()
					return fmt.Errorf("backup removal incomplete at %s: %w", backup.Path, err)
				}
			}
		}
		sub.Close()
		if err := root.Remove(directory); err != nil {
			return fmt.Errorf("backup removal incomplete at %s: %w", backup.Path, err)
		}
	}
	for _, file := range orderedKeys(backup.Files, nil) {
		if strings.Contains(file, "/") {
			continue
		}
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
