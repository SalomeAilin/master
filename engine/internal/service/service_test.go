package service

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"network-owned-engine/internal/runtimecheck"
)

func testConfig(t *testing.T) Config {
	t.Helper()
	account, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}
	if account.Uid == "0" {
		account, err = user.LookupId("501")
		if err != nil {
			t.Skip("needs an unprivileged macOS user")
		}
	}
	r := ProductionRoutes()
	r.DNS, r.WiredIP, r.WiredGateway, r.WiFiGateway = "192.0.2.10", "192.0.2.10", "192.0.2.1", "198.51.100.1"
	r.WiredInterface, r.WiFiInterface, r.WiredService, r.WiFiService = "en0", "en1", "Ethernet", "Wi-Fi"
	return Config{Version: 1, EngineConfig: "/usr/local/etc/network-domain-proxy.json", Routes: r, Status: StatusConfig{User: account.Username, Home: account.HomeDir,
		Output: filepath.Join(account.HomeDir, "status & test.html"), State: filepath.Join(account.HomeDir, "status.state"), Log: filepath.Join(account.HomeDir, "status.log")}}
}

func TestDefinitionsUseOneProjectExecutableAndPreservePrivileges(t *testing.T) {
	c := testConfig(t)
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	jobs := Jobs(c)
	if len(jobs) != 7 {
		t.Fatal("missing worker roles")
	}
	for _, job := range jobs {
		if job.Label == "homebrew.mxcl.dnsmasq" {
			if job.Program() != c.Routes.DNSBinary {
				t.Fatal(job)
			}
		} else if job.Program() != Binary {
			t.Fatal("separate project executable", job)
		}
		if strings.HasPrefix(job.Path(), "/Library/LaunchDaemons/") {
			t.Fatal("worker would auto-start independently", job)
		}
		data, err := Plist(job.Definition)
		if err != nil {
			t.Fatal(err)
		}
		file := filepath.Join(t.TempDir(), job.Label+".plist")
		if err := os.WriteFile(file, data, 0o600); err != nil {
			t.Fatal(err)
		}
		if output, err := exec.Command("/usr/bin/plutil", "-lint", file).CombinedOutput(); err != nil {
			t.Fatal(string(output), err)
		}
		if output, err := exec.Command("/usr/bin/plutil", "-convert", "json", "-o", "-", file).Output(); err != nil {
			t.Fatal(err)
		} else {
			var got map[string]any
			if err := json.Unmarshal(output, &got); err != nil {
				t.Fatal(err)
			}
			wantJSON, _ := json.Marshal(job.Definition)
			var want map[string]any
			json.Unmarshal(wantJSON, &want)
			if !reflect.DeepEqual(want, got) {
				t.Fatal("plist roundtrip changed settings", job.Label)
			}
		}
		if job.Label == "com.local.network-domain-proxy" && job.Definition["UserName"] != "nobody" {
			t.Fatal("proxy privilege increased")
		}
		if job.Label == "com.local.network-split-log-guard" && (job.Definition["UserName"] != c.Status.User || job.Definition["StartInterval"] != 300) {
			t.Fatal("status identity or cadence changed")
		}
		if job.Label == "com.local.network-split-domestic-health" && job.Definition["StartInterval"] != 30 {
			t.Fatal("health cadence changed")
		}
	}
	if MainDefinition()["Label"] != Label {
		t.Fatal("wrong parent")
	}
}

func TestPlistBooleansUseLaunchdCompatibleEmptyElements(t *testing.T) {
	data, err := Plist(map[string]any{"enabled": true, "disabled": false, "literal": "<true></true>"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "<true/>") || !strings.Contains(string(data), "<false/>") || strings.Contains(string(data), "</true>") || strings.Contains(string(data), "</false>") {
		t.Fatal(string(data))
	}
	if !strings.Contains(string(data), "&lt;true&gt;&lt;/true&gt;") {
		t.Fatal("literal string was changed", string(data))
	}
}

func TestConfigurationRejectsUnsafePathsAndRootStatus(t *testing.T) {
	for _, variant := range []string{"version", "same-interface", "root-status", "outside-home", "duplicate-output", "routing-path-alias"} {
		t.Run(variant, func(t *testing.T) {
			c := testConfig(t)
			switch variant {
			case "version":
				c.Version = 2
			case "same-interface":
				c.Routes.WiFiInterface = c.Routes.WiredInterface
			case "root-status":
				c.Status.User = "root"
				c.Status.Home = "/var/root"
			case "outside-home":
				c.Status.Output = "/etc/hosts"
			case "duplicate-output":
				c.Status.State = c.Status.Output
			case "routing-path-alias":
				c.Routes.ChinaList = c.Routes.ExtraList
			}
			if err := c.Validate(); err == nil {
				t.Fatal("unsafe configuration accepted", variant)
			}
		})
	}
}

func TestConfigurationLoadingIsBoundedAndNeverFollowsLinks(t *testing.T) {
	c := testConfig(t)
	data, _ := json.Marshal(c)
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path, false); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link")
	os.Symlink(path, link)
	if _, err := Load(link, false); err == nil {
		t.Fatal("link accepted")
	}
	for _, bad := range []string{string(data) + " {}", strings.Repeat("x", (64<<10)+1), `{"Version":1,"unexpected":true}`} {
		os.WriteFile(path, []byte(bad), 0o600)
		if _, err := Load(path, false); err == nil {
			t.Fatal("invalid data accepted")
		}
	}
	os.WriteFile(path, data, 0o600)
	os.Chmod(path, 0o666)
	if _, err := Load(path, false); err == nil {
		t.Fatal("writable config accepted")
	}
}

func launchText(job Job) string {
	return fmt.Sprintf("path = %s\nprogram = %s\narguments = {\n%s\n}\nstate = running\npid = 123\nresource = {\nstate = active\n}\n", job.Path(), job.Program(), strings.Join(job.Arguments(), "\n"))
}

func TestSupervisorAdoptsAndStopsOnlyOwnedJobs(t *testing.T) {
	jobs := Jobs(testConfig(t))[:3]
	loaded := map[string]bool{jobs[0].Label: true}
	var operations []string
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	s := Supervisor{Jobs: jobs, Log: func(string, ...any) {}, Wait: func(context.Context, time.Duration) error { cancel(); return ctx.Err() }}
	s.Run = func(args ...string) (string, error) {
		for _, job := range jobs {
			if args[1] == "print" && args[2] == "system/"+job.Label {
				if !loaded[job.Label] {
					return "", &runtimecheck.CommandError{Code: 113}
				}
				return launchText(job), nil
			}
			if args[1] == "bootstrap" && args[3] == job.Path() {
				loaded[job.Label] = true
				operations = append(operations, "start:"+job.Label)
				return "", nil
			}
			if args[1] == "bootout" && args[2] == "system/"+job.Label {
				loaded[job.Label] = false
				operations = append(operations, "stop:"+job.Label)
				return "", nil
			}
		}
		t.Fatal("unexpected command", args)
		return "", errors.New("unexpected")
	}
	if err := s.RunUntilCancelled(ctx); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	want := []string{"start:" + jobs[1].Label, "start:" + jobs[2].Label, "stop:" + jobs[2].Label, "stop:" + jobs[1].Label, "stop:" + jobs[0].Label}
	if !reflect.DeepEqual(operations, want) {
		t.Fatal(operations)
	}
}

func TestSupervisorRefusesLegacyJobBeforeAnyChanges(t *testing.T) {
	jobs := Jobs(testConfig(t))
	s := Supervisor{Jobs: jobs, Log: func(string, ...any) {}}
	s.Run = func(args ...string) (string, error) {
		if args[1] != "print" {
			t.Fatal("changed a conflicting service", args)
		}
		return "path = /Library/LaunchDaemons/legacy.plist\nprogram = /legacy\n", nil
	}
	if err := s.RunUntilCancelled(context.Background()); err == nil {
		t.Fatal("legacy job adopted")
	}
}

func TestSupervisorStartupFailurePreservesAdoptedJobs(t *testing.T) {
	jobs := Jobs(testConfig(t))[:3]
	loaded := map[string]bool{jobs[0].Label: true}
	s := Supervisor{Jobs: jobs, Log: func(string, ...any) {}}
	s.Run = func(args ...string) (string, error) {
		for i, job := range jobs {
			if args[1] == "print" && args[2] == "system/"+job.Label {
				if !loaded[job.Label] {
					return "", &runtimecheck.CommandError{Code: 113}
				}
				return launchText(job), nil
			}
			if args[1] == "bootstrap" && args[3] == job.Path() {
				if i == 2 {
					return "", errors.New("start failed")
				}
				loaded[job.Label] = true
				return "", nil
			}
			if args[1] == "bootout" && args[2] == "system/"+job.Label {
				if i == 0 {
					t.Fatal("adopted worker stopped during failed startup")
				}
				loaded[job.Label] = false
				return "", nil
			}
		}
		t.Fatal(args)
		return "", nil
	}
	if err := s.RunUntilCancelled(context.Background()); err == nil {
		t.Fatal("startup failure ignored")
	}
	if !loaded[jobs[0].Label] || loaded[jobs[1].Label] {
		t.Fatal(loaded)
	}
}

func TestCancelledSupervisorDoesNotStartAnything(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	s := Supervisor{Jobs: Jobs(testConfig(t)), Run: func(...string) (string, error) { t.Fatal("started after cancellation"); return "", nil }}
	if err := s.RunUntilCancelled(ctx); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}

func TestWorkerDependencyRefusesWrongModeLinksAndOwner(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "dns")
	if err := os.WriteFile(file, []byte("fixture"), 0o555); err != nil {
		t.Fatal(err)
	}
	uid := uint32(os.Geteuid())
	if err := trustedFile(file, 0o555, uid); err != nil {
		t.Fatal(err)
	}
	if err := trustedFile(file, 0o755, uid); err == nil {
		t.Fatal("wrong mode accepted")
	}
	if err := trustedFile(file, 0o555, uid+1); err == nil {
		t.Fatal("wrong owner accepted")
	}
	link := filepath.Join(dir, "link")
	if err := os.Link(file, link); err != nil {
		t.Fatal(err)
	}
	if err := trustedFile(file, 0o555, uid); err == nil {
		t.Fatal("hardlink accepted")
	}
	os.Remove(link)
	if err := os.Symlink(file, link); err != nil {
		t.Fatal(err)
	}
	if err := trustedFile(link, 0o555, uid); err == nil {
		t.Fatal("symlink accepted")
	}
}

func TestWorkerBootstrapRetriesTheKnownLaunchdUnloadRace(t *testing.T) {
	job := Jobs(testConfig(t))[0]
	calls := 0
	s := Supervisor{Wait: func(context.Context, time.Duration) error { return nil }}
	s.Run = func(args ...string) (string, error) {
		if args[1] == "print" {
			return launchText(job), nil
		}
		calls++
		if calls == 1 {
			return "", &runtimecheck.CommandError{Code: 5}
		}
		return "", nil
	}
	if created, err := s.bootstrap(context.Background(), job); err != nil || !created || calls != 2 {
		t.Fatal(created, calls, err)
	}
}

// This opt-in test registers inert jobs in the GUI domain, or system as root.
// It never runs a worker or touches a production label or startup directory.
func TestLaunchdAcceptsGeneratedDefinitions(t *testing.T) {
	if os.Getenv("NETWORK_SPLIT_LAUNCHD_TEST") != "1" {
		t.Skip("set NETWORK_SPLIT_LAUNCHD_TEST=1 for the native launchd parser")
	}
	domain := fmt.Sprintf("gui/%d", os.Getuid())
	if os.Getuid() == 0 {
		domain = "system"
	}
	jobs := append(Jobs(testConfig(t)), Job{Definition: MainDefinition()})
	for i, job := range jobs {
		label := fmt.Sprintf("com.local.network-split-test.%d.%d.%d", os.Getpid(), time.Now().UnixNano(), i)
		job.Definition["Label"] = label
		job.Definition["ProgramArguments"] = []string{"/usr/bin/true"}
		job.Definition["RunAtLoad"], job.Definition["KeepAlive"] = false, false
		for _, key := range []string{"UserName", "StartInterval", "EnvironmentVariables", "StandardOutPath", "StandardErrorPath"} {
			delete(job.Definition, key)
		}
		data, err := Plist(job.Definition)
		if err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(t.TempDir(), label+".plist")
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}
		if out, err := exec.Command("/usr/bin/plutil", "-lint", path).CombinedOutput(); err != nil {
			t.Fatal(string(out), err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		out, err := exec.CommandContext(ctx, "/bin/launchctl", "bootstrap", domain, path).CombinedOutput()
		cancel()
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 5*time.Second)
		cleanupOut, cleanupErr := exec.CommandContext(cleanupCtx, "/bin/launchctl", "bootout", domain+"/"+label).CombinedOutput()
		cleanupCancel()
		if err != nil {
			t.Fatalf("launchd rejected definition %d: %v %s", i, err, out)
		}
		if cleanupErr != nil {
			t.Fatalf("could not remove test job %s: %v %s", label, cleanupErr, cleanupOut)
		}
		t.Logf("accepted and removed %s/%s", domain, label)
	}
}
