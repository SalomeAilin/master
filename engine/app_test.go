package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"

	"network-owned-engine/internal/deploy"
	"network-owned-engine/internal/proxyconfig"
)

func TestMaintenanceRejectsUnknownRetiredAndBatchActionsBeforeLocking(t *testing.T) {
	dir := t.TempDir()
	d := deploy.New(deploy.Paths{Lock: filepath.Join(dir, "lock")}, "", &bytes.Buffer{})
	d.Run = func(...string) (string, error) { t.Fatal("unexpected system operation"); return "", nil }
	for _, args := range [][]string{nil, {"remove-backup"}, {"remove-backup", "a", "b"}, {"backups", "a"}, {"cleanup-residues", "a"}, {"unknown"}, {"rollback", "a"}, {"health-check"}, {"install-tool"}, {"install-route-guard"}, {"cleanup-policy-cache"}} {
		if err := runMaintenance(d, args); err == nil {
			t.Fatal("accepted", args)
		}
	}
	if entries, err := os.ReadDir(dir); err != nil || len(entries) != 0 {
		t.Fatal("invalid actions wrote files", entries, err)
	}
}

func TestUnifiedMaintenanceKeepsDeploymentLock(t *testing.T) {
	dir := t.TempDir()
	out := &bytes.Buffer{}
	d := deploy.New(deploy.Paths{Lock: filepath.Join(dir, "lock"), BackupParent: dir}, "", out)
	release, err := d.Lock()
	if err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{{"backups"}, {"inspect-backup", "a"}, {"remove-backup", "a"}, {"residues"}, {"cleanup-residues"}, {"enable"}, {"rollback"}} {
		if err := runMaintenance(d, args); err == nil {
			t.Fatal("ignored deployment lock", args)
		}
	}
	release()
	if err := runMaintenance(d, []string{"backups"}); err != nil || out.String() != "[]\n" {
		t.Fatal(out.String(), err)
	}
}

func TestUnifiedConfigKeepsEncodingAndNeverOverwrites(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	c, err := proxyconfig.Build("../config", "", "")
	if err != nil {
		t.Fatal(err)
	}
	want, err := proxyconfig.Encode(c)
	if err != nil {
		t.Fatal(err)
	}
	if err := configCommand([]string{"-policy-dir", "../config", path}); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(want, got) {
		t.Fatal("configuration changed", err)
	}
	if err := configCommand([]string{"-policy-dir", "../config", path}); err == nil {
		t.Fatal("existing configuration overwritten")
	}
}

func TestWorkerCannotDispatchMaintenance(t *testing.T) {
	for _, args := range [][]string{nil, {"upgrade"}, {"remove-backup", "a"}, {"health", "cleanup-residues"}, {"routes", "-service-config", "/tmp/untrusted"}} {
		if err := worker(context.Background(), args); err == nil {
			t.Fatal("invalid worker action accepted", args)
		}
	}
}
