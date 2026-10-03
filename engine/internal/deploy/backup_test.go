package deploy

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
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
		filepath.Join(base, "launchd", "com.local.network-split-dns-event-route-agent.plist")}
	for _, name := range []string{"network-split-policy", "network-split-dns-event-route-agent", "dnsmasq-network-split", "china-route.sh", "network-split-guard.sh", healthScript} {
		files = append(files, filepath.Join(base, "sbin", name))
	}
	for _, path := range files {
		writeTestFile(t, path, "live "+filepath.Base(path))
	}
	d.Run = func(args ...string) (string, error) {
		switch args[0] {
		case "/bin/zsh":
			if len(args) != 3 || args[1] != "-n" {
				t.Fatal("unexpected shell execution", args)
			}
			return "", nil
		case "/usr/bin/pgrep", "/usr/sbin/lsof":
			return "", &CommandError{Args: args, Code: 1}
		case "/bin/launchctl":
			if len(args) != 3 || args[1] != "print" {
				t.Fatal("unexpected service mutation", args)
			}
			program := map[string]string{
				Label: d.Binary,
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

func TestInstallToolChangesOnlyMaintenanceExecutable(t *testing.T) {
	d := maintenanceFixture(t)
	writeTestFile(t, filepath.Join(d.Root, ToolName), "new maintenance tool")
	before, err := d.maintenanceState()
	if err != nil {
		t.Fatal(err)
	}
	if err := d.InstallTool(); err != nil {
		t.Fatal(err)
	}
	after, err := d.maintenanceState()
	if err != nil || before.Files[d.Tool] == after.Files[d.Tool] {
		t.Fatal("tool was not updated", err)
	}
	before.Files[d.Tool] = after.Files[d.Tool]
	if !reflect.DeepEqual(before, after) {
		t.Fatal("unrelated runtime changed")
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

func TestInstallToolFailureKeepsInstalledExecutable(t *testing.T) {
	d := maintenanceFixture(t)
	writeTestFile(t, filepath.Join(d.Root, ToolName), "new maintenance tool")
	before, err := d.maintenanceState()
	if err != nil {
		t.Fatal(err)
	}
	d.Rename = func(string, string) error { return errors.New("simulated publication failure") }
	if err := d.InstallTool(); err == nil {
		t.Fatal("publication failure ignored")
	}
	after, err := d.maintenanceState()
	if err != nil || !reflect.DeepEqual(before, after) {
		t.Fatal("failed installation changed runtime", err)
	}
	entries, err := os.ReadDir(filepath.Dir(d.Tool))
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), ".") {
			t.Fatal("temporary installation file retained", entry.Name())
		}
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

func TestInstallToolRefusesInventoryFailureBeforePublication(t *testing.T) {
	d := maintenanceFixture(t)
	writeTestFile(t, filepath.Join(d.Root, ToolName), "new maintenance tool")
	if err := os.Chmod(d.BackupParent, 0o777); err != nil {
		t.Fatal(err)
	}
	before, err := d.maintenanceState()
	if err != nil {
		t.Fatal(err)
	}
	if err := d.InstallTool(); err == nil || !strings.Contains(err.Error(), "inventory preflight failed") {
		t.Fatal("inventory failure ignored", err)
	}
	after, err := d.maintenanceState()
	if err != nil || !reflect.DeepEqual(before, after) {
		t.Fatal("tool replaced before inventory validation", err)
	}
}
