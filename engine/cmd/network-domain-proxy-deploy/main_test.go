package main

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
	"time"

	"network-owned-engine/internal/deploy"
	"network-owned-engine/internal/healthcheck"
)

func TestCommandArgumentsRejectImplicitOrBatchDeletion(t *testing.T) {
	for _, args := range [][]string{nil, {"remove-backup"}, {"remove-backup", "one", "two"}, {"remove-backup", "--all", "one"}, {"backups", "one"}, {"cleanup-residues", "arbitrary-path"}, {"unknown"}, {"rollback", "one"}} {
		if validArguments(args) {
			t.Fatal("accepted", args)
		}
	}
	for _, args := range [][]string{{"health-check"}, {"upgrade"}, {"install-tool"}, {"install-route-guard"}, {"install-health-maintenance"}, {"residues"}, {"cleanup-residues"}, {"cleanup-health-state"}, {"backups"}, {"inspect-backup", "one"}, {"remove-backup", "one"}} {
		if !validArguments(args) {
			t.Fatal("rejected", args)
		}
	}
}

func TestHealthCommandDoesNotBlockOnDeploymentLockWhenProbeIsNotDue(t *testing.T) {
	dir := t.TempDir()
	d := deploy.New(deploy.Paths{Lock: filepath.Join(dir, "deploy.lock"), HealthLock: filepath.Join(dir, "health.lock"), BackupParent: dir}, "", &bytes.Buffer{})
	d.Now = func() time.Time { return time.Unix(1000, 0) }
	state := healthcheck.State{Interval: 120, LastProbe: 1000}
	if err := os.WriteFile(filepath.Join(dir, "network-split-domestic-health.state"), state.Encode(), 0o600); err != nil {
		t.Fatal(err)
	}
	release, err := d.Lock()
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	d.Run = func(...string) (string, error) {
		t.Fatal("idle health check invoked an external command")
		return "", nil
	}
	if err := run(d, "health-check"); err != nil {
		t.Fatal(err)
	}
}

func TestBackupCommandsRespectDeploymentLock(t *testing.T) {
	dir := t.TempDir()
	out := &bytes.Buffer{}
	d := deploy.New(deploy.Paths{Lock: filepath.Join(dir, "lock"), BackupParent: dir}, "", out)
	release, err := d.Lock()
	if err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{{"backups"}, {"inspect-backup", "one"}, {"remove-backup", "one"}, {"install-tool"}, {"install-route-guard"}, {"install-health-maintenance"}, {"cleanup-residues"}, {"cleanup-health-state"}} {
		if err := run(d, args...); err == nil {
			t.Fatal("ignored active deployment", args)
		}
	}
	release()
	if err := run(d, "backups"); err != nil || out.String() != "[]\n" {
		t.Fatal(out.String(), err)
	}
}

func TestUnknownCommandNeverFallsThroughToRollback(t *testing.T) {
	dir := t.TempDir()
	lock := filepath.Join(dir, "lock")
	d := deploy.New(deploy.Paths{Lock: lock}, "", &bytes.Buffer{})
	d.Run = func(...string) (string, error) { t.Fatal("unexpected system command"); return "", nil }
	if err := run(d, "unknown"); err == nil {
		t.Fatal("unknown command accepted")
	}
	if _, err := os.Stat(lock); !os.IsNotExist(err) {
		t.Fatal("invalid invocation created a lock", err)
	}
}
