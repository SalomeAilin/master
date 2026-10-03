package deploy

import (
	"bufio"
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func makeResidue(t *testing.T, d *Deployer, name, content string, old bool) string {
	t.Helper()
	path := filepath.Join(d.BackupParent, name)
	writeTestFile(t, path, content)
	if old {
		when := d.Now().Add(-time.Hour)
		if err := os.Chtimes(path, when, when); err != nil {
			t.Fatal(err)
		}
	}
	return path
}

func TestResidueCleanupPreservesActiveRecentAndUnrelatedFiles(t *testing.T) {
	d := maintenanceFixture(t)
	old := makeResidue(t, d, healthTempPrefix+"12345", "failure_count=0\nlast_refresh=1234567890\n", true)
	legacy := makeResidue(t, d, legacyDNSState, "{}", true)
	keep := []string{
		makeResidue(t, d, healthState, "active state", true),
		makeResidue(t, d, healthTempPrefix+"23456", "version=1\nfailure_count=0\n", false),
		makeResidue(t, d, healthTempPrefix+"34567", "unrecognized data", true),
		makeResidue(t, d, healthTempPrefix+"not-a-pid", "", true),
		makeResidue(t, d, "unrelated.tmp", "keep", true),
	}
	if err := d.CleanupResidues(false); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{old, legacy} {
		if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatal("known residue not removed", path, err)
		}
	}
	for _, path := range keep {
		if _, err := os.Stat(path); err != nil {
			t.Fatal("protected file removed", path, err)
		}
	}
}

func TestAutomaticCleanupRecoversInterruptedWritesAfterGrace(t *testing.T) {
	d := maintenanceFixture(t)
	now := time.Now()
	d.Now = func() time.Time { return now }
	paths := []string{}
	for index, content := range []string{"", "ver", "version=1\nfailure_count=", "version=1\nfailure_count=0\nprobe_samples=12,"} {
		name := healthTempPrefix + strings.Repeat("1", index+1)
		paths = append(paths, makeResidue(t, d, name, content, false))
	}
	legacy := makeResidue(t, d, legacyDNSState, "{}", true)
	if err := d.CleanupResidues(true); err != nil {
		t.Fatal(err)
	}
	for _, path := range paths {
		if _, err := os.Stat(path); err != nil {
			t.Fatal("recent temporary state removed", err)
		}
	}
	now = now.Add(residueGrace + time.Minute)
	afterRestart := New(d.Paths, d.Root, d.Out)
	afterRestart.Run, afterRestart.Now = d.Run, d.Now
	if err := afterRestart.CleanupResidues(true); err != nil {
		t.Fatal(err)
	}
	for _, path := range paths {
		if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatal("interrupted write was not recovered", err)
		}
	}
	if _, err := os.Stat(legacy); err != nil {
		t.Fatal("automatic cleanup touched legacy DNS state", err)
	}
	d.Run = func(...string) (string, error) { t.Fatal("empty automatic cleanup ran a system probe"); return "", nil }
	if err := d.CleanupResidues(true); err != nil {
		t.Fatal("repeated cleanup is not idempotent", err)
	}
}

func TestResidueCleanupRefusesLinksPermissionsAndNonemptyLegacyState(t *testing.T) {
	d := maintenanceFixture(t)
	target := makeResidue(t, d, "protected", "failure_count=0\n", true)
	link := filepath.Join(d.BackupParent, healthTempPrefix+"101")
	hard := filepath.Join(d.BackupParent, healthTempPrefix+"102")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(target, hard); err != nil {
		t.Fatal(err)
	}
	writable := makeResidue(t, d, healthTempPrefix+"103", "", true)
	if err := os.Chmod(writable, 0o666); err != nil {
		t.Fatal(err)
	}
	legacy := makeResidue(t, d, legacyDNSState, `{"routes":["preserve"]}`, true)
	if err := d.CleanupResidues(false); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{target, link, hard, writable, legacy} {
		if _, err := os.Lstat(path); err != nil {
			t.Fatal("unsafe candidate removed", path, err)
		}
	}
}

func TestResidueCleanupRefusesOpenOrChangedFiles(t *testing.T) {
	for _, variant := range []string{"open", "unavailable", "changed"} {
		t.Run(variant, func(t *testing.T) {
			d := maintenanceFixture(t)
			path := makeResidue(t, d, healthTempPrefix+"123", "failure_count=0\n", true)
			original := d.Run
			d.Run = func(args ...string) (string, error) {
				if args[0] == "/usr/sbin/lsof" {
					switch variant {
					case "open":
						return "999\n", nil
					case "unavailable":
						return "", errors.New("inspection unavailable")
					case "changed":
						writeTestFile(t, path, "failure_count=1\n")
					}
				}
				return original(args...)
			}
			if err := d.CleanupResidues(false); err == nil {
				t.Fatal("unsafe removal admitted")
			}
			if _, err := os.Stat(path); err != nil {
				t.Fatal("candidate was removed", err)
			}
		})
	}
}

func TestHealthCleanupLockInteroperatesWithZshWriter(t *testing.T) {
	d := maintenanceFixture(t)
	release, err := d.lockHealthState()
	if err != nil {
		t.Fatal(err)
	}
	command := exec.Command("/bin/zsh", "-c", `zmodload zsh/system && zsystem flock -t 0 "$1"`, "--", d.HealthLock)
	lockedOutput, err := command.CombinedOutput()
	release()
	var exit *exec.ExitError
	if !errors.As(err, &exit) || (exit.ExitCode() != 1 && exit.ExitCode() != 2) {
		t.Fatal("zsh writer was not excluded by the Go lock", err, string(lockedOutput))
	}
	unlocked := exec.Command("/bin/zsh", "-c", `zmodload zsh/system && zsystem flock -t 0 "$1"`, "--", d.HealthLock)
	if output, err := unlocked.CombinedOutput(); err != nil {
		t.Fatal("zsh could not acquire the released lock", err, string(output))
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	command = exec.CommandContext(ctx, "/bin/zsh", "-c", "zmodload zsh/system || exit 1\nzsystem flock -t 0 -f writer_lock \"$1\" || exit 1\nprint locked\nread -r release_line", "--", d.HealthLock)
	input, err := command.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	output, err := command.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { input.Close(); cancel(); command.Wait() }()
	line, err := bufio.NewReader(output).ReadString('\n')
	if err != nil || line != "locked\n" {
		t.Fatal("zsh lock was not acquired", line, err)
	}
	if release, err := d.lockHealthState(); !errors.Is(err, errHealthBusy) {
		if release != nil {
			release()
		}
		t.Fatal("Go cleanup ignored the zsh writer lock", err)
	}
}

func TestInstallHealthMaintenancePreservesRuntimeAndCleansState(t *testing.T) {
	d := maintenanceFixture(t)
	writeTestFile(t, filepath.Join(d.Root, ToolName), "new maintenance binary")
	writeTestFile(t, filepath.Join(d.Root, healthScript), "#!/bin/zsh\n/usr/local/sbin/network-domain-proxy-deploy cleanup-health-state\n")
	residue := makeResidue(t, d, healthTempPrefix+"123", "failure_count=0\nlast_refresh=0\n", true)
	active := makeResidue(t, d, healthState, "active state", true)
	before, err := d.maintenanceState()
	if err != nil {
		t.Fatal(err)
	}
	if err := d.InstallHealthMaintenance(); err != nil {
		t.Fatal(err)
	}
	after, err := d.maintenanceState()
	if err != nil {
		t.Fatal(err)
	}
	before.Files[d.Tool] = after.Files[d.Tool]
	health := filepath.Join(filepath.Dir(d.Tool), healthScript)
	before.Files[health] = after.Files[health]
	if !reflect.DeepEqual(before, after) {
		t.Fatal("unrelated runtime changed")
	}
	if _, err := os.Stat(residue); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("old residue retained", err)
	}
	if data, err := os.ReadFile(active); err != nil || string(data) != "active state" {
		t.Fatal("active state changed", err)
	}
}
