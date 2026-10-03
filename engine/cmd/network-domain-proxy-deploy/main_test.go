package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"network-owned-engine/internal/deploy"
)

func TestCommandArgumentsRejectImplicitOrBatchDeletion(t *testing.T) {
	for _, args := range [][]string{nil, {"remove-backup"}, {"remove-backup", "one", "two"}, {"remove-backup", "--all", "one"}, {"backups", "one"}, {"cleanup-residues", "arbitrary-path"}, {"unknown"}, {"rollback", "one"}} {
		if validArguments(args) {
			t.Fatal("accepted", args)
		}
	}
	for _, args := range [][]string{{"upgrade"}, {"install-tool"}, {"install-route-guard"}, {"install-health-maintenance"}, {"residues"}, {"cleanup-residues"}, {"backups"}, {"inspect-backup", "one"}, {"remove-backup", "one"}} {
		if !validArguments(args) {
			t.Fatal("rejected", args)
		}
	}
}

func TestRetiredCommandsFailBeforeAnySideEffect(t *testing.T) {
	dir := t.TempDir()
	d := deploy.New(deploy.Paths{Lock: filepath.Join(dir, "lock")}, "", &bytes.Buffer{})
	d.Run = func(...string) (string, error) { t.Fatal("retired command invoked a system tool"); return "", nil }
	for _, args := range [][]string{{"health-check"}, {"cleanup-health-state"}, {"cleanup-policy-cache", strings.Repeat("a", 64)}} {
		if validArguments(args) {
			t.Fatal("retired command accepted", args)
		}
		if err := run(d, args...); err == nil {
			t.Fatal("retired command was silently redirected", args)
		}
		if strings.Contains(usage, args[0]) {
			t.Fatal("retired command is still advertised", args)
		}
	}
	if entries, err := os.ReadDir(dir); err != nil || len(entries) != 0 {
		t.Fatal("retired invocation created files", entries, err)
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
	for _, args := range [][]string{{"backups"}, {"inspect-backup", "one"}, {"remove-backup", "one"}, {"install-tool"}, {"install-route-guard"}, {"install-health-maintenance"}, {"cleanup-residues"}} {
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
