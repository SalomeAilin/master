package runtimecheck

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

func TestUnifiedInspectionRequiresAllWorkerDefinitions(t *testing.T) {
	base := t.TempDir()
	p := Paths{Binary: filepath.Join(base, "libexec", "engine"), Config: filepath.Join(base, "etc", "proxy.json"), Plist: filepath.Join(base, "jobs", "proxy.plist"), ServiceConfig: filepath.Join(base, "etc", "service.json"), SupervisorPlist: filepath.Join(base, "parent.plist")}
	p.Tool = p.Binary
	paths := []string{p.Binary, p.Config, p.Plist, p.ServiceConfig, p.SupervisorPlist, filepath.Join(base, "etc", "dnsmasq-network-split.conf"), filepath.Join(base, "sbin", "dnsmasq-network-split")}
	for _, name := range []string{"com.local.network-split-dns-event-route-agent", "com.local.network-split-domestic-health", "com.local.china-route", "com.local.network-split-guard", "com.local.network-split-log-guard", "homebrew.mxcl.dnsmasq"} {
		paths = append(paths, filepath.Join(base, "jobs", name+".plist"))
	}
	for _, path := range paths {
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte("fixture"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	run := func(args ...string) (string, error) {
		program := p.Binary
		if args[2] == "system/homebrew.mxcl.dnsmasq" {
			program = filepath.Join(base, "sbin", "dnsmasq-network-split")
		}
		return fmt.Sprintf("state = running\nprogram = %s\npid = 123\n", program), nil
	}
	state, err := Inspect(p, run)
	if err != nil || len(state.PIDs) != 4 || len(state.Files) != len(paths) {
		t.Fatal(state, err)
	}
	if err := os.Remove(paths[len(paths)-1]); err != nil {
		t.Fatal(err)
	}
	if _, err := Inspect(p, run); err == nil {
		t.Fatal("missing DNS definition ignored")
	}
}
