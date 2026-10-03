package deploy

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
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

func TestHealthLockChild(t *testing.T) {
	mode := os.Getenv("NETWORK_HEALTH_LOCK_TEST")
	if mode == "" {
		return
	}
	d := New(Paths{HealthLock: os.Getenv("NETWORK_HEALTH_LOCK_PATH")}, "", io.Discard)
	release, err := d.lockHealthState()
	if errors.Is(err, errHealthBusy) {
		fmt.Println("busy")
		return
	}
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	fmt.Println("locked")
	if mode == "hold" {
		var data [1]byte
		os.Stdin.Read(data[:])
	}
}

func TestHealthCleanupLockExcludesOtherNativeProcesses(t *testing.T) {
	d := maintenanceFixture(t)
	release, err := d.lockHealthState()
	if err != nil {
		t.Fatal(err)
	}
	command := exec.Command(os.Args[0], "-test.run=^TestHealthLockChild$")
	command.Env = append(os.Environ(), "NETWORK_HEALTH_LOCK_TEST=try", "NETWORK_HEALTH_LOCK_PATH="+d.HealthLock)
	lockedOutput, err := command.CombinedOutput()
	release()
	if err != nil || !strings.HasPrefix(string(lockedOutput), "busy\n") {
		t.Fatal("native writer was not excluded", err, string(lockedOutput))
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	command = exec.CommandContext(ctx, os.Args[0], "-test.run=^TestHealthLockChild$")
	command.Env = append(os.Environ(), "NETWORK_HEALTH_LOCK_TEST=hold", "NETWORK_HEALTH_LOCK_PATH="+d.HealthLock)
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
		t.Fatal("native child lock was not acquired", line, err)
	}
	if release, err := d.lockHealthState(); !errors.Is(err, errHealthBusy) {
		if release != nil {
			release()
		}
		t.Fatal("Go cleanup ignored the other native writer", err)
	}
}
