package main

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"network-owned-engine/internal/healthcheck"
	"network-owned-engine/internal/runtimecheck"
)

func TestHealthEntryRejectsEveryMaintenanceAction(t *testing.T) {
	for _, args := range [][]string{{"upgrade"}, {"install"}, {"remove-backup", "one"}, {"cleanup-residues"}, {"health-check"}} {
		if err := run(nil, args); err == nil {
			t.Fatal("accepted maintenance command", args)
		}
	}
}

func TestHealthEntryUsesExistingScheduleAndDoesNotTakeDeployLock(t *testing.T) {
	dir := t.TempDir()
	job := &healthcheck.Job{Paths: runtimecheck.Paths{HealthLock: filepath.Join(dir, "health.lock"), BackupParent: dir,
		Lock: filepath.Join(dir, "nonexistent", "deploy.lock")}, Context: context.Background(), Out: io.Discard,
		Now: func() time.Time { return time.Unix(1000, 0) }, Run: func(...string) (string, error) {
			t.Fatal("idle job invoked a command")
			return "", nil
		}}
	state := healthcheck.State{Interval: 120, LastProbe: 1000}
	if err := os.WriteFile(filepath.Join(dir, "network-split-domestic-health.state"), state.Encode(), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := run(job, nil); err != nil {
		t.Fatal(err)
	}
}
