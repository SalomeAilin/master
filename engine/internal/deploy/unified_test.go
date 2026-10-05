package deploy

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"network-owned-engine/internal/dnsservice"
	"network-owned-engine/internal/healthcheck"
	"network-owned-engine/internal/service"
	"network-owned-engine/internal/statuspage"
)

type unifiedFixture struct {
	config   service.Config
	path     string
	loaded   map[string]installedJob
	fault    string
	failed   bool
	firewall map[string]string
}

func unifiedSetup(t *testing.T) (*Deployer, *unifiedFixture) {
	t.Helper()
	d := maintenanceFixture(t)
	base := filepath.Dir(d.BackupParent)
	u, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}
	if u.Uid == "0" {
		u, err = user.LookupId("501")
		if err != nil {
			t.Skip("needs a local unprivileged user")
		}
	}
	c := service.Config{Version: 1, EngineConfig: "/usr/local/etc/network-domain-proxy.json", Routes: service.ProductionRoutes(), Status: service.StatusConfig{User: u.Username, Home: u.HomeDir, Output: filepath.Join(u.HomeDir, "status-test.html"), State: filepath.Join(u.HomeDir, "status-test.state"), Log: filepath.Join(u.HomeDir, "status-test.log")}}
	c.Routes.DNS, c.Routes.WiredIP, c.Routes.WiredGateway, c.Routes.WiFiGateway = "192.0.2.10", "192.0.2.10", "192.0.2.1", "198.51.100.1"
	c.Routes.WiredInterface, c.Routes.WiFiInterface, c.Routes.WiredService, c.Routes.WiFiService = "en0", "en1", "Ethernet", "Wi-Fi"
	f := &unifiedFixture{config: c, path: filepath.Join(d.Root, "service.json"), loaded: map[string]installedJob{}, firewall: map[string]string{}}
	d.unifiedLayout = &unifiedLayout{MainPlist: filepath.Join(base, "launchd", "parent.plist"), Config: filepath.Join(base, "etc", "unified.json"), Jobs: filepath.Join(base, "jobs"), LegacyJobs: filepath.Join(base, "launchd"),
		UserPlist: filepath.Join(base, "user-agent.plist"), Newsyslog: filepath.Join(base, "newsyslog.conf"), Sbin: filepath.Join(base, "sbin"), OldStatus: filepath.Join(base, "old-status"), UserHome: base}
	encoded, _ := json.Marshal(c)
	writeTestFile(t, f.path, string(encoded))
	writeTestFile(t, filepath.Join(d.Root, EngineName), "unified executable")
	writeTestFile(t, d.Config, `{"domestic":{"interface":"en0"},"foreign":{"interface":"en1"},"rule_sources":[{"kind":"domestic"},{"kind":"foreign"},{"kind":"china"}]}`)
	writeTestFile(t, d.unifiedLayout.Newsyslog, "# existing rotation\n")
	writeTestFile(t, d.unifiedLayout.OldStatus, "old status")
	writeTestFile(t, filepath.Join(d.unifiedLayout.Sbin, "network-split-health"), "old health")
	for _, job := range d.legacyJobs(c, u.Uid) {
		writeTestFile(t, job.Path, "old job "+job.Label)
		job.Loaded = true
		f.loaded[job.Domain+"/"+job.Label] = job
	}
	d.Preflight = func(map[string]any) error {
		if f.fault == "preflight" {
			return errors.New("preflight failed")
		}
		return nil
	}
	d.acceptUnified = func(string, int64) error {
		if f.fault == "accept" || f.fault == "rollback" {
			return errors.New("acceptance failed")
		}
		return nil
	}
	d.EnsureDir = func(path string, mode os.FileMode, _ string) error { return os.MkdirAll(path, mode) }
	d.Sleep = func(time.Duration) {}
	d.ProcessAlive = func(int) (bool, error) { return false, nil }
	d.Run = func(args ...string) (string, error) {
		if args[0] == firewallTool {
			switch args[1] {
			case "--listapps":
				var paths []string
				for path := range f.firewall {
					paths = append(paths, path)
				}
				slices.Sort(paths)
				out := fmt.Sprintf("Total number of apps = %d\n", len(paths))
				for i, path := range paths {
					state := "Allow"
					if f.firewall[path] == "blocked" {
						state = "Block"
					}
					out += fmt.Sprintf("%d : %s\n (%s incoming connections)\n", i+1, path, state)
				}
				return out, nil
			case "--add":
				if _, exists := f.firewall[args[2]]; !exists {
					f.firewall[args[2]] = "blocked"
				}
			case "--remove":
				delete(f.firewall, args[2])
			case "--blockapp":
				f.firewall[args[2]] = "blocked"
			case "--unblockapp":
				if f.fault == "firewall" && args[2] == d.Binary && !f.failed {
					f.failed = true
					return "", errors.New("firewall change failed")
				}
				f.firewall[args[2]] = "allowed"
			default:
				t.Fatal("unexpected firewall operation", args)
			}
			return "", nil
		}
		if args[0] != "/bin/launchctl" {
			t.Fatal("unexpected command", args)
		}
		switch args[1] {
		case "print":
			job, ok := f.loaded[args[2]]
			if !ok {
				return "", &CommandError{Code: 113}
			}
			return fmt.Sprintf("path = %s\nprogram = %s\nstate = running\npid = 123\n", job.Path, job.Program), nil
		case "bootout":
			if f.fault == "stop" && !f.failed {
				f.failed = true
				return "", errors.New("could not stop")
			}
			delete(f.loaded, args[2])
			if args[2] == "system/"+service.Label {
				for _, job := range d.unifiedJobs(c) {
					delete(f.loaded, job.Domain+"/"+job.Label)
				}
				delete(f.loaded, "system/"+service.NativeDNSLabel)
			}
			return "", nil
		case "bootstrap":
			if args[3] == d.unifiedLayout.MainPlist {
				if f.fault == "bootstrap" {
					return "", errors.New("could not bootstrap")
				}
				f.loaded["system/"+service.Label] = installedJob{Domain: "system", Label: service.Label, Path: args[3], Program: d.Binary, Loaded: true}
				current, err := service.Load(d.unifiedLayout.Config, false)
				if err != nil {
					t.Fatal(err)
				}
				for _, job := range d.unifiedJobs(current) {
					f.loaded[job.Domain+"/"+job.Label] = job
				}
				return "", nil
			}
			for _, job := range append(d.legacyJobs(c, u.Uid), d.unifiedJobs(c)...) {
				if args[3] == job.Path {
					f.loaded[job.Domain+"/"+job.Label] = job
					return "", nil
				}
			}
		}
		t.Fatal("unexpected launch operation", args)
		return "", nil
	}
	return d, f
}

func TestNativeDNSMigrationAndRollbackPreserveThePreviousRuntime(t *testing.T) {
	if !dnsservice.SocketActivationAvailable() {
		t.Skip("requires macOS cgo")
	}
	for _, fault := range []string{"", "preflight-dns", "firewall", "accept", "retired-file-changed"} {
		t.Run(fault, func(t *testing.T) {
			d, f := unifiedSetup(t)
			if _, err := d.Consolidate(f.path); err != nil {
				t.Fatal(err)
			}
			oldDNS := d.legacyDNSBinary(f.config)
			writeTestFile(t, oldDNS, "old DNS executable")
			f.firewall[oldDNS] = "allowed"
			f.firewall["/unrelated/app"] = "blocked"
			before := fileSet(t, filepath.Dir(d.BackupParent))
			d.nativeDNS = true
			d.preflightDNS = func(string) error {
				if fault == "preflight-dns" {
					return errors.New("DNS preflight failed")
				}
				return nil
			}
			f.fault = fault
			if fault == "retired-file-changed" {
				d.acceptUnified = func(string, int64) error { writeTestFile(t, oldDNS, "changed"); return nil }
			}
			backup, err := d.Consolidate(f.path)
			if fault == "" {
				if err != nil {
					t.Fatal(err)
				}
				if _, exists := f.loaded["system/homebrew.mxcl.dnsmasq"]; exists {
					t.Fatal("legacy DNS still loaded")
				}
				if _, exists := f.loaded["system/"+service.NativeDNSLabel]; !exists {
					t.Fatal("native DNS missing")
				}
				if _, err := os.Stat(oldDNS); !os.IsNotExist(err) {
					t.Fatal("legacy DNS not retired", err)
				}
				if f.firewall[d.Binary] != "allowed" || f.firewall[oldDNS] != "" {
					t.Fatal(f.firewall)
				}
				if inventory, err := d.InspectBackup(backup); err != nil || inventory.Kind != "unified" {
					t.Fatal(inventory, err)
				}
			} else {
				if err == nil {
					t.Fatal("migration failure ignored")
				}
				if !reflect.DeepEqual(before, fileSet(t, filepath.Dir(d.BackupParent))) {
					t.Fatal("previous files not restored")
				}
				if f.firewall[oldDNS] != "allowed" || f.firewall[d.Binary] != "" {
					t.Fatal("firewall was not restored", f.firewall)
				}
				if _, exists := f.loaded["system/"+service.NativeDNSLabel]; exists {
					t.Fatal("new DNS left running")
				}
				if _, exists := f.loaded["system/homebrew.mxcl.dnsmasq"]; !exists {
					t.Fatal("previous DNS not restored")
				}
			}
			if f.firewall["/unrelated/app"] != "blocked" {
				t.Fatal("unrelated firewall entry changed")
			}
		})
	}
}

func TestFirewallInventoryRejectsUncertainState(t *testing.T) {
	d, _ := unifiedSetup(t)
	for _, output := range []string{"", "Total number of apps = 1\n", "Total number of apps = 1\n1 : /test\nunknown\n", "Total number of apps = 0\n1 : /test\n(Allow incoming connections)\n"} {
		d.Run = func(...string) (string, error) { return output, nil }
		if _, err := d.firewallStates([]string{"/test"}); err == nil {
			t.Fatal("uncertain firewall state accepted", output)
		}
	}
}

func fileSet(t *testing.T, dir string) map[string]string {
	t.Helper()
	result := map[string]string{}
	err := filepath.WalkDir(dir, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			if strings.HasPrefix(entry.Name(), "network-unified-backup.") {
				return filepath.SkipDir
			}
			return nil
		}
		data, err := os.ReadFile(path)
		if err == nil {
			relative, _ := filepath.Rel(dir, path)
			result[relative] = string(data)
		}
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func TestConsolidationPublishesOneProgramAndRetiresOldEntries(t *testing.T) {
	d, f := unifiedSetup(t)
	backup, err := d.Consolidate(f.path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(filepath.Base(backup), "network-unified-backup.") {
		t.Fatal(backup)
	}
	if len(f.loaded) != 8 {
		t.Fatal("missing parent or workers", f.loaded)
	}
	for _, job := range d.unifiedJobs(f.config) {
		if _, err := os.Stat(job.Path); err != nil {
			t.Fatal(err)
		}
		if job.Label != "homebrew.mxcl.dnsmasq" && job.Program != d.Binary {
			t.Fatal("extra executable", job)
		}
	}
	for _, path := range []string{d.Tool, d.unifiedLayout.OldStatus, filepath.Join(d.unifiedLayout.Sbin, "network-split-health"), d.unifiedLayout.UserPlist} {
		if _, err := os.Lstat(path); !os.IsNotExist(err) {
			t.Fatal("legacy entry retained", path, err)
		}
	}
	if data, _ := os.ReadFile(d.Binary); string(data) != "unified executable" {
		t.Fatal("candidate not installed")
	}
	if inventory, err := d.InspectBackup(backup); err != nil || inventory.Kind != "unified" || inventory.Bytes == 0 {
		t.Fatal("migration backup is not inspectable", inventory, err)
	}
	writeTestFile(t, filepath.Join(backup, "unknown"), "keep")
	if _, err := d.InspectBackup(backup); err == nil {
		t.Fatal("unrecognized backup content accepted")
	}
	if data, _ := os.ReadFile(d.Config); string(data) != `{"domestic":{"interface":"en0"},"foreign":{"interface":"en1"},"rule_sources":[{"kind":"domestic"},{"kind":"foreign"},{"kind":"china"}]}` {
		t.Fatal("proxy configuration changed")
	}
}

func TestConsolidationRestoresFilesAndLoadedJobsOnFailure(t *testing.T) {
	for _, fault := range []string{"preflight", "stop", "publication", "bootstrap", "accept"} {
		t.Run(fault, func(t *testing.T) {
			d, f := unifiedSetup(t)
			f.fault = fault
			before := fileSet(t, filepath.Dir(d.BackupParent))
			jobs := map[string]installedJob{}
			for key, value := range f.loaded {
				value.PID = 0
				jobs[key] = value
			}
			if fault == "publication" {
				d.Rename = func(from, to string) error {
					if to == d.Binary && !f.failed {
						f.failed = true
						return errors.New("publication failed")
					}
					return os.Rename(from, to)
				}
			}
			if _, err := d.Consolidate(f.path); err == nil {
				t.Fatal("failure ignored")
			}
			after := fileSet(t, filepath.Dir(d.BackupParent))
			if !reflect.DeepEqual(before, after) {
				t.Fatal("files not restored")
			}
			if len(jobs) != len(f.loaded) {
				t.Fatal("loaded job set changed", f.loaded)
			}
			for key, want := range jobs {
				got, ok := f.loaded[key]
				if !ok || got.Path != want.Path || got.Program != want.Program {
					t.Fatal("job not restored", key, got)
				}
			}
		})
	}
}

func TestConsolidationRetainsRecoveryFilesWhenRollbackFails(t *testing.T) {
	d, f := unifiedSetup(t)
	f.fault = "rollback"
	d.Restore = func(string, []Record) error { return errors.New("restore denied") }
	backup, err := d.Consolidate(f.path)
	if err == nil || !strings.Contains(err.Error(), "rollback failed") {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(backup, "manifest.json")); err != nil {
		t.Fatal("recovery data lost", err)
	}
}

func TestConsolidationPreflightLeavesInstalledStateUntouched(t *testing.T) {
	d, f := unifiedSetup(t)
	d.preflightOnly = true
	before := fileSet(t, filepath.Dir(d.BackupParent))
	calls := 0
	d.Run = func(...string) (string, error) {
		calls++
		return "", errors.New("preflight must not control launchd")
	}
	backup, err := d.Consolidate(f.path)
	if err != nil || backup != "" || calls != 0 {
		t.Fatal(backup, err, calls)
	}
	if !reflect.DeepEqual(before, fileSet(t, filepath.Dir(d.BackupParent))) {
		t.Fatal("preflight changed installed files")
	}
	entries, err := os.ReadDir(d.BackupParent)
	if err != nil || len(entries) != 0 {
		t.Fatal("preflight left a backup", entries, err)
	}
}

func TestConsolidationRejectsDuplicateRuleKindsBeforePreflight(t *testing.T) {
	d, f := unifiedSetup(t)
	data, _ := os.ReadFile(d.Config)
	writeTestFile(t, d.Config, strings.Replace(string(data), `"kind":"china"`, `"kind":"foreign"`, 1))
	d.Preflight = func(map[string]any) error { t.Fatal("invalid rules reached preflight"); return nil }
	if _, err := d.Consolidate(f.path); err == nil {
		t.Fatal("duplicate kinds accepted")
	}
}

func TestUnifiedStatusAcceptanceRequiresFreshOwnedHealthyReceipt(t *testing.T) {
	home := t.TempDir()
	c := service.Config{Status: service.StatusConfig{Home: home, Output: filepath.Join(home, "status.html"), State: filepath.Join(home, "state")}}
	start := time.Now().Add(-time.Second)
	r := statuspage.Report{Updated: time.Now(), State: "OK", Checks: []statuspage.Row{{State: "ok"}}, Domains: []statuspage.Row{{State: "wired"}}}
	if err := r.Publish(c.Status.Output, c.Status.State, filepath.Join(home, "log")); err != nil {
		t.Fatal(err)
	}
	if err := acceptStatusReport(c, start); err != nil {
		t.Fatal(err)
	}
	if err := acceptStatusReport(c, time.Now().Add(time.Second)); err == nil {
		t.Fatal("stale receipt accepted")
	}
	data, _ := os.ReadFile(c.Status.State)
	var valid statuspage.Snapshot
	if err := json.Unmarshal(data, &valid); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{"state", "digest", "path", "size", "checked", "published", "missing-checks"} {
		snapshot := valid
		switch bad {
		case "state":
			snapshot.State = "BAD"
		case "digest":
			snapshot.HTMLSHA256 = "wrong"
		case "path":
			snapshot.HTMLPath = filepath.Join(home, "other.html")
		case "size":
			snapshot.HTMLBytes = 0
		case "checked":
			snapshot.Checked = start.Add(-time.Second)
		case "published":
			snapshot.Published = start.Add(-time.Second)
		case "missing-checks":
			snapshot.Checks = nil
		}
		encoded, _ := json.Marshal(snapshot)
		writeTestFile(t, c.Status.State, string(encoded))
		if err := acceptStatusReport(c, start); err == nil {
			t.Fatal("invalid receipt accepted", bad)
		}
	}
	writeTestFile(t, c.Status.State, `{"State":"OK","Checks":[{"State":"ok"}],"Domains":[{"State":"wired"}]}`)
	if err := acceptStatusReport(c, time.Time{}); err != nil {
		t.Fatal("legacy preflight rejected", err)
	}
	if err := acceptStatusReport(c, start); err == nil {
		t.Fatal("legacy state accepted as a new publication")
	}
	os.Remove(c.Status.State)
	outside := filepath.Join(t.TempDir(), "other.state")
	writeTestFile(t, outside, string(data))
	if err := os.Symlink(outside, c.Status.State); err != nil {
		t.Fatal(err)
	}
	if err := acceptStatusReport(c, start); err == nil {
		t.Fatal("external receipt accepted")
	}
}

func TestUnifiedMigrationCapturesProbeAfterOldWriterStops(t *testing.T) {
	d, f := unifiedSetup(t)
	d.Now = func() time.Time { return time.Unix(1000, 0) }
	original := d.Run
	d.Run = func(args ...string) (string, error) {
		if len(args) == 3 && args[1] == "bootout" && args[2] == healthLabel {
			state := healthcheck.State{Interval: 120, LastProbe: 999}
			writeTestFile(t, filepath.Join(d.BackupParent, healthState), string(state.Encode()))
		}
		return original(args...)
	}
	d.acceptUnified = func(_ string, previous int64) error {
		if previous != 999 {
			return fmt.Errorf("old writer sample was not captured: %d", previous)
		}
		return nil
	}
	if _, err := d.Consolidate(f.path); err != nil {
		t.Fatal(err)
	}
}

func TestUnifiedStopIsBoundedAndWaitsForTheOwnedProcess(t *testing.T) {
	d, f := unifiedSetup(t)
	job := d.unifiedJobs(f.config)[1]
	f.loaded[job.Domain+"/"+job.Label] = job
	checks := 0
	d.ProcessAlive = func(pid int) (bool, error) {
		if pid != 123 {
			t.Fatal("unrelated PID", pid)
		}
		checks++
		return checks < 3, nil
	}
	if err := d.stopInstalledJob(job); err != nil || checks != 3 {
		t.Fatal(checks, err)
	}
	f.loaded[job.Domain+"/"+job.Label] = job
	checks = 0
	d.ProcessAlive = func(int) (bool, error) { checks++; return true, nil }
	if err := d.stopInstalledJob(job); err == nil || checks != 150 {
		t.Fatal(checks, err)
	}
}

func TestUnifiedBootstrapRetriesOnlyKnownUnloadRace(t *testing.T) {
	d, f := unifiedSetup(t)
	for _, code := range []int{5, 113} {
		calls := 0
		d.Run = func(...string) (string, error) {
			calls++
			if calls == 1 {
				return "", &CommandError{Code: code}
			}
			return "", nil
		}
		err := d.bootstrapJob(d.unifiedJobs(f.config)[0])
		if code == 5 && (err != nil || calls != 2) || code == 113 && (err == nil || calls != 1) {
			t.Fatal(code, calls, err)
		}
	}
}

func TestUnifiedAcceptanceImmediatelyReportsAWorkerStartupFailure(t *testing.T) {
	d, f := unifiedSetup(t)
	d.acceptUnified = nil
	d.Sleep = func(time.Duration) { t.Fatal("known startup failure was retried") }
	d.Run = func(args ...string) (string, error) {
		for _, job := range d.unifiedJobs(f.config) {
			if args[2] != job.Domain+"/"+job.Label {
				continue
			}
			state, exit, pid := "not running", "0", 0
			if job.Label == "homebrew.mxcl.dnsmasq" || job.Label == "com.local.network-domain-proxy" || job.Label == "com.local.network-split-dns-event-route-agent" {
				state, pid = "running", 123
			}
			if job.Label == "com.local.network-split-log-guard" {
				exit = "78: EX_CONFIG"
			}
			var arguments []string
			for _, definition := range d.managedJobs(f.config) {
				if definition.Label == job.Label {
					arguments = definition.Arguments()
				}
			}
			return fmt.Sprintf("path = %s\nprogram = %s\narguments = {\n%s\n}\nstate = %s\npid = %d\nlast exit code = %s\n", job.Path, job.Program, strings.Join(arguments, "\n"), state, pid, exit), nil
		}
		t.Fatal("unexpected operation", args)
		return "", nil
	}
	err := d.waitUnified(f.config, 0, time.Now())
	if err == nil || !strings.Contains(err.Error(), "78: EX_CONFIG") {
		t.Fatal(err)
	}
}
