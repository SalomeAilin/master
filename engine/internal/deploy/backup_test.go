package deploy

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"slices"
	"strings"
	"testing"
)

func maintenanceFixture(t *testing.T) *Deployer {
	t.Helper()
	base := t.TempDir()
	paths := Paths{
		Binary: filepath.Join(base, "libexec", EngineName),
		Tool:   filepath.Join(base, "sbin", ToolName),
		Config: filepath.Join(base, "etc", "config.json"),
		Plist:  filepath.Join(base, "launchd", PlistName),
		Rules:  filepath.Join(base, "rules"), Cache: filepath.Join(base, "cache"),
		Lock: filepath.Join(base, "deploy.lock"), BackupParent: filepath.Join(base, "backups"),
		HealthLock: filepath.Join(base, "health.flock"),
		HealthLog:  filepath.Join(base, "health.log"),
	}
	for _, dir := range []string{"libexec", "sbin", "etc", "launchd", "rules", "cache", "backups", "stage"} {
		if err := os.Mkdir(filepath.Join(base, dir), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	d := New(paths, filepath.Join(base, "stage"), &bytes.Buffer{})
	d.Chown = noChown
	files := []string{paths.Binary, paths.Tool, paths.Config, paths.Plist,
		filepath.Join(base, "etc", "dnsmasq-network-split.conf"),
		filepath.Join(base, "launchd", "com.local.network-split-dns-event-route-agent.plist"),
		filepath.Join(base, "launchd", healthPlistName)}
	for _, name := range []string{"network-split-policy", "network-split-dns-event-route-agent", "dnsmasq-network-split", "china-route.sh", "network-split-guard.sh", legacyHealthScript} {
		files = append(files, filepath.Join(base, "sbin", name))
	}
	for _, path := range files {
		writeTestFile(t, path, "live "+filepath.Base(path))
	}
	d.Run = func(args ...string) (string, error) {
		switch args[0] {
		case "/usr/bin/pgrep", "/usr/sbin/lsof":
			return "", &CommandError{Args: args, Code: 1}
		case "/bin/launchctl":
			if len(args) != 3 || args[1] != "print" {
				t.Fatal("unexpected service mutation", args)
			}
			program := map[string]string{
				Label:       d.Binary,
				healthLabel: filepath.Join(base, "sbin", "network-split-health"),
				"system/com.local.network-split-dns-event-route-agent": filepath.Join(base, "sbin", "network-split-dns-event-route-agent"),
				"system/homebrew.mxcl.dnsmasq":                         filepath.Join(base, "sbin", "dnsmasq-network-split"),
			}[args[2]]
			if program == "" {
				t.Fatal("unexpected service", args)
			}
			return fmt.Sprintf("state = running\nprogram = %s\npid = 123\nresource = {\nstate = active\n}\n", program), nil
		default:
			t.Fatal("unexpected maintenance command", args)
		}
		return "", nil
	}
	return d
}

func writeTestFile(t *testing.T, path, data string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
}

func makeBackup(t *testing.T, d *Deployer, kind string) string {
	t.Helper()
	prefix := installationPrefix
	if kind == "acceptance" {
		prefix = acceptancePrefix
	}
	path, err := os.MkdirTemp(d.BackupParent, prefix)
	if err != nil {
		t.Fatal(err)
	}
	if kind == "acceptance" {
		if _, err := d.snapshotFiles(path, d.snapshotTargets()); err != nil {
			t.Fatal(err)
		}
	} else {
		for _, name := range []string{"china-route.sh", "network-split-guard.sh", "network_split_policy.py"} {
			writeTestFile(t, filepath.Join(path, name), "retired "+name)
		}
	}
	return path
}

func TestBackupRemovalPreservesRuntimeAndOtherBackups(t *testing.T) {
	for _, kind := range []string{"acceptance", "installation"} {
		t.Run(kind, func(t *testing.T) {
			d := maintenanceFixture(t)
			path, other := makeBackup(t, d, kind), makeBackup(t, d, "installation")
			before, err := d.maintenanceState()
			if err != nil {
				t.Fatal(err)
			}
			info, err := d.InspectBackup(path)
			if err != nil || info.Kind != kind || info.Bytes == 0 || len(info.Files) == 0 {
				t.Fatal(info, err)
			}
			if err := d.RemoveBackup(filepath.Base(path)); err != nil {
				t.Fatal(err)
			}
			if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("backup retained", err)
			}
			if _, err := d.InspectBackup(other); err != nil {
				t.Fatal("other backup changed", err)
			}
			after, err := d.maintenanceState()
			if err != nil || !reflect.DeepEqual(before, after) {
				t.Fatal("runtime changed", err)
			}
		})
	}
}

func TestUnifiedMaintenanceCanInspectAnOlderAcceptanceBackup(t *testing.T) {
	d := maintenanceFixture(t)
	backup := makeBackup(t, d, "acceptance")
	d.SupervisorPlist = filepath.Join(filepath.Dir(d.Plist), "parent.plist")
	d.Plist = filepath.Join(filepath.Dir(d.Config), "jobs", PlistName)
	d.Tool = d.Binary
	if result, err := d.InspectBackup(backup); err != nil || result.Kind != "acceptance" {
		t.Fatal(result, err)
	}
}

func TestBackupInspectionRejectsUnsafeContents(t *testing.T) {
	for _, variant := range []string{"extra-file", "directory", "symlink", "hardlink", "writable-file", "public-directory", "manifest", "missing-copy", "manifest-symlink"} {
		t.Run(variant, func(t *testing.T) {
			d := maintenanceFixture(t)
			kind := "installation"
			if strings.Contains(variant, "manifest") || variant == "missing-copy" {
				kind = "acceptance"
			}
			path := makeBackup(t, d, kind)
			file := filepath.Join(path, "china-route.sh")
			var err error
			switch variant {
			case "extra-file":
				writeTestFile(t, filepath.Join(path, "unrelated.txt"), "keep")
			case "directory", "symlink", "hardlink":
				if err := os.Remove(file); err != nil {
					t.Fatal(err)
				}
				switch variant {
				case "directory":
					err = os.Mkdir(file, 0o700)
				case "symlink":
					err = os.Symlink(d.Binary, file)
				case "hardlink":
					err = os.Link(d.Binary, file)
				}
			case "writable-file":
				err = os.Chmod(file, 0o666)
			case "public-directory":
				err = os.Chmod(path, 0o755)
			case "manifest":
				writeTestFile(t, filepath.Join(path, "manifest.json"), `[{"target":"/unmanaged","copy":"../outside","present":true}]`)
			case "missing-copy":
				err = os.Remove(filepath.Join(path, "0"))
			case "manifest-symlink":
				file = filepath.Join(path, "manifest.json")
				if err := os.Remove(file); err != nil {
					t.Fatal(err)
				}
				err = os.Symlink(d.Config, file)
			}
			if err != nil {
				t.Fatal(err)
			}
			if err := d.RemoveBackup(path); err == nil {
				t.Fatal("unsafe backup accepted")
			}
			if _, err := os.Stat(path); err != nil {
				t.Fatal("backup removed despite validation error", err)
			}
			if data, _ := os.ReadFile(d.Binary); string(data) != "live "+EngineName {
				t.Fatal("live binary changed")
			}
		})
	}
}

func TestBackupRemovalRejectsAmbiguousPathsAndLinks(t *testing.T) {
	d := maintenanceFixture(t)
	path := makeBackup(t, d, "installation")
	link := filepath.Join(d.BackupParent, installationPrefix+"ABCDEF")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	for _, candidate := range []string{d.BackupParent, path + "/..", filepath.Join(t.TempDir(), filepath.Base(path)), "network-split-backup.*", link} {
		if err := d.RemoveBackup(candidate); err == nil {
			t.Fatalf("accepted %q", candidate)
		}
	}
	if _, err := d.InspectBackup(path); err != nil {
		t.Fatal(err)
	}
}

func TestBackupRemovalRefusesBusyFailedAndChangedState(t *testing.T) {
	for _, variant := range []string{"installer", "open-files", "lsof-error", "pgrep-error", "stopped-service", "changed-backup", "changed-runtime", "interrupted"} {
		t.Run(variant, func(t *testing.T) {
			d := maintenanceFixture(t)
			path := makeBackup(t, d, "installation")
			original := d.Run
			d.Run = func(args ...string) (string, error) {
				if args[0] == "/usr/bin/pgrep" {
					if variant == "installer" {
						return "123\n", nil
					}
					if variant == "pgrep-error" {
						return "", errors.New("unavailable")
					}
				}
				if args[0] == "/usr/sbin/lsof" {
					switch variant {
					case "open-files":
						return "123\n", nil
					case "lsof-error":
						return "permission denied", &CommandError{Args: args, Code: 1}
					case "changed-backup":
						writeTestFile(t, filepath.Join(path, "china-route.sh"), "changed")
					case "changed-runtime":
						writeTestFile(t, d.Binary, "changed")
					}
				}
				if args[0] == "/bin/launchctl" && variant == "stopped-service" {
					return "state = not running\n", nil
				}
				return original(args...)
			}
			d.Interrupted = func() bool { return variant == "interrupted" }
			if err := d.RemoveBackup(path); err == nil {
				t.Fatal("unsafe removal admitted")
			}
			if _, err := d.InspectBackup(path); err != nil {
				t.Fatal("backup was not preserved", err)
			}
		})
	}
}

func TestBackupsListReportsInvalidCandidateWithoutRemovingAnything(t *testing.T) {
	d := maintenanceFixture(t)
	valid, invalid := makeBackup(t, d, "acceptance"), makeBackup(t, d, "installation")
	writeTestFile(t, filepath.Join(invalid, "unrelated.txt"), "keep")
	list, err := d.Backups()
	if err != nil || len(list) != 2 {
		t.Fatal(list, err)
	}
	for _, backup := range list {
		if (backup.Path == invalid) != (backup.Error != "") {
			t.Fatal(backup)
		}
	}
	for _, path := range []string{valid, invalid} {
		if _, err := os.Stat(path); err != nil {
			t.Fatal(err)
		}
	}
}

func TestBackupDirectoryReplacementIsRejected(t *testing.T) {
	d := maintenanceFixture(t)
	path := makeBackup(t, d, "installation")
	original := d.Run
	d.Run = func(args ...string) (string, error) {
		if args[0] == "/usr/sbin/lsof" {
			if err := os.Rename(path, path+".moved"); err != nil {
				t.Fatal(err)
			}
			if err := os.Mkdir(path, 0o700); err != nil {
				t.Fatal(err)
			}
			for _, name := range []string{"china-route.sh", "network-split-guard.sh", "network_split_policy.py"} {
				writeTestFile(t, filepath.Join(path, name), "retired "+name)
			}
		}
		return original(args...)
	}
	if err := d.RemoveBackup(path); err == nil {
		t.Fatal("replacement directory accepted")
	}
	for _, candidate := range []string{path, path + ".moved"} {
		if _, err := os.Stat(candidate); err != nil {
			t.Fatal("directory removed after replacement", err)
		}
	}
}

func TestRemovalReportsFailureAfterDeletionAccurately(t *testing.T) {
	d := maintenanceFixture(t)
	path := makeBackup(t, d, "installation")
	original, prints := d.Run, 0
	d.Run = func(args ...string) (string, error) {
		if args[0] == "/bin/launchctl" {
			prints++
			if prints > 6 {
				return "", errors.New("service status unavailable")
			}
		}
		return original(args...)
	}
	if err := d.RemoveBackup(path); err == nil || !strings.Contains(err.Error(), "backup removed, but") {
		t.Fatal("post-removal uncertainty was not reported", err)
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("expected completed deletion", err)
	}
}

func TestBackupInventoryCanListProtectedMacOSParent(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("macOS system-directory compatibility")
	}
	parent, err := os.OpenRoot(Production.BackupParent)
	if err != nil {
		t.Fatal(err)
	}
	defer parent.Close()
	// Names only: do not inspect or modify any production backup or database.
	if _, err := backupDirectoryNames(parent); err != nil {
		t.Fatal("system directory enumeration requires unrelated metadata access", err)
	}
}

func softwareMaintenanceFixture(t *testing.T) *Deployer {
	t.Helper()
	d := maintenanceFixture(t)
	d.NativeDNS = true
	d.Tool = d.Binary
	d.ServiceConfig = filepath.Join(filepath.Dir(d.Config), "service.json")
	d.SupervisorPlist = filepath.Join(filepath.Dir(d.Plist), "parent.plist")
	for _, path := range []string{d.ServiceConfig, d.SupervisorPlist} {
		writeTestFile(t, path, "native fixture")
	}
	for _, name := range []string{"com.local.network-split-dns", "com.local.china-route", "com.local.network-split-guard", "com.local.network-split-log-guard"} {
		writeTestFile(t, filepath.Join(filepath.Dir(d.Plist), name+".plist"), "native worker fixture")
	}
	original := d.Run
	d.Run = func(args ...string) (string, error) {
		if args[0] == "/bin/launchctl" {
			if len(args) != 3 || args[1] != "print" || !slices.Contains([]string{Label, "system/com.local.network-split-service", "system/com.local.network-split-dns", "system/com.local.network-split-dns-event-route-agent"}, args[2]) {
				t.Fatal("unexpected runtime operation", args)
			}
			return fmt.Sprintf("state = running\nprogram = %s\npid = 123\n", d.Binary), nil
		}
		return original(args...)
	}
	return d
}

func makeSoftwareBackup(t *testing.T, d *Deployer) string {
	t.Helper()
	path, err := os.MkdirTemp(d.BackupParent, softwarePrefix)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(path, legacySoftwareArchive), 0o755); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"previous-dnsmasq", "previous-sing-box", legacySoftwareArchive + "/LICENSE", legacySoftwareArchive + "/sing-box"} {
		writeTestFile(t, filepath.Join(path, name), "retired software fixture")
	}
	return path
}

func TestSoftwareBackupInspectionAndExactRemoval(t *testing.T) {
	d := softwareMaintenanceFixture(t)
	path := makeSoftwareBackup(t, d)
	other := makeBackup(t, d, "installation")
	before, err := d.maintenanceState()
	if err != nil {
		t.Fatal(err)
	}
	b, err := d.InspectBackup(path)
	if err != nil || b.Kind != "software-update" || len(b.Files) != 4 || !slices.Equal(b.Directories, []string{legacySoftwareArchive}) {
		t.Fatal(b, err)
	}
	listed, err := d.Backups()
	if err != nil || len(listed) != 2 {
		t.Fatal(listed, err)
	}
	if err := d.RemoveBackup(path); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("backup remains", err)
	}
	if _, err := d.InspectBackup(other); err != nil {
		t.Fatal("other backup changed", err)
	}
	after, err := d.maintenanceState()
	if err != nil || !reflect.DeepEqual(before, after) {
		t.Fatal("runtime changed", err)
	}
}

func TestSoftwareBackupRejectsUnknownUnsafeAndBusyContents(t *testing.T) {
	for _, variant := range []string{"extra-file", "extra-release-file", "missing-file", "release-link", "release-writable", "file-link", "file-hardlink", "file-writable", "oversized-file", "empty-file", "busy", "changed-file", "legacy-runtime"} {
		t.Run(variant, func(t *testing.T) {
			d := softwareMaintenanceFixture(t)
			path := makeSoftwareBackup(t, d)
			release := filepath.Join(path, legacySoftwareArchive)
			file := filepath.Join(release, "sing-box")
			switch variant {
			case "extra-file":
				writeTestFile(t, filepath.Join(path, "keep.txt"), "keep")
			case "extra-release-file":
				writeTestFile(t, filepath.Join(release, "keep.txt"), "keep")
			case "missing-file":
				os.Remove(filepath.Join(path, "previous-dnsmasq"))
			case "release-link":
				outside := filepath.Join(t.TempDir(), "release")
				if err := os.Rename(release, outside); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(outside, release); err != nil {
					t.Fatal(err)
				}
			case "release-writable":
				os.Chmod(release, 0o777)
			case "file-link", "file-hardlink":
				os.Remove(file)
				var err error
				if variant == "file-link" {
					err = os.Symlink(d.Binary, file)
				} else {
					err = os.Link(d.Binary, file)
				}
				if err != nil {
					t.Fatal(err)
				}
			case "file-writable":
				os.Chmod(file, 0o666)
			case "oversized-file":
				os.Truncate(file, (128<<20)+1)
			case "empty-file":
				os.Truncate(file, 0)
			case "legacy-runtime":
				d.NativeDNS = false
			case "busy", "changed-file":
				original := d.Run
				d.Run = func(args ...string) (string, error) {
					if args[0] == "/usr/sbin/lsof" {
						if variant == "busy" {
							return "123\n", nil
						}
						writeTestFile(t, file, "changed")
					}
					return original(args...)
				}
			}
			if err := d.RemoveBackup(path); err == nil {
				t.Fatal("unsafe removal accepted")
			}
			if _, err := os.Stat(path); err != nil {
				t.Fatal("backup removed", err)
			}
		})
	}
}

func TestSoftwareBackupUsesAScopedLargerHashLimit(t *testing.T) {
	d := softwareMaintenanceFixture(t)
	path := makeSoftwareBackup(t, d)
	file := filepath.Join(path, "previous-sing-box")
	if err := os.Truncate(file, (64<<20)+1); err != nil {
		t.Fatal(err)
	}
	if b, err := d.InspectBackup(path); err != nil || b.Bytes <= 64<<20 {
		t.Fatal(b, err)
	}
	f, err := os.Open(file)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if _, _, err := hashFile(f); err == nil {
		t.Fatal("normal maintenance hash limit was weakened")
	}
}

func TestInventoryReportsUnrecognizedBackupNamesWithoutReadingOrDeleting(t *testing.T) {
	d := maintenanceFixture(t)
	for _, name := range []string{"network-unified-backup.bad!", "network-unknown-backup.ABCDEF", "network-software-update.short", "network-split-backups"} {
		if err := os.Mkdir(filepath.Join(d.BackupParent, name), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := d.RemoveBackup(name); err == nil {
			t.Fatal("unrecognized backup removable", name)
		}
	}
	writeTestFile(t, filepath.Join(d.BackupParent, "network-split-domestic-health.state"), "active")
	if err := os.Symlink(t.TempDir(), filepath.Join(d.BackupParent, "network-unknown-backup.link")); err != nil {
		t.Fatal(err)
	}
	list, err := d.Backups()
	if err != nil || len(list) != 5 {
		t.Fatal(list, err)
	}
	for _, backup := range list {
		if backup.Kind != "unrecognized" || backup.Error == "" || len(backup.Files) != 0 {
			t.Fatal(backup)
		}
		if _, err := os.Stat(backup.Path); err != nil {
			t.Fatal(err)
		}
	}
}
