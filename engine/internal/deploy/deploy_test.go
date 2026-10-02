package deploy

import (
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"network-owned-engine/internal/proxyconfig"
)

func noChown(string, uint32, uint32) error { return nil }

// sequence returns successive results, repeating the last one.
func sequence[T any](values ...T) func() T {
	return func() T {
		value := values[0]
		if len(values) > 1 {
			values = values[1:]
		}
		return value
	}
}

type fakeRun struct {
	calls   [][]string
	results []func([]string) (string, error)
}

func (f *fakeRun) run(args ...string) (string, error) {
	f.calls = append(f.calls, args)
	if len(f.results) == 0 {
		return "", nil
	}
	result := f.results[0]
	if len(f.results) > 1 {
		f.results = f.results[1:]
	}
	return result(args)
}

func output(text string) func([]string) (string, error) {
	return func([]string) (string, error) { return text, nil }
}

func failure(code int) func([]string) (string, error) {
	return func(args []string) (string, error) { return "", &CommandError{Args: args, Code: code} }
}

func TestAtomicInstallCleansStagingOnSuccessAndFailure(t *testing.T) {
	root := t.TempDir()
	source, target := filepath.Join(root, "source"), filepath.Join(root, "target")
	os.WriteFile(source, []byte("new"), 0o644)
	os.WriteFile(target, []byte("old"), 0o644)
	d := New(Paths{}, root, io.Discard)
	d.Chown = noChown
	d.Rename = func(string, string) error { return errors.New("simulated rename") }
	if err := d.InstallFile(source, target, 0o600); err == nil || !strings.Contains(err.Error(), "simulated") {
		t.Fatal(err)
	}
	entries := func() []string {
		list, _ := os.ReadDir(root)
		var names []string
		for _, entry := range list {
			names = append(names, entry.Name())
		}
		return names
	}
	if data, _ := os.ReadFile(target); string(data) != "old" || !slices.Equal(entries(), []string{"source", "target"}) {
		t.Fatal(string(data), entries())
	}
	d.Rename = os.Rename
	if err := d.InstallFile(source, target, 0o600); err != nil {
		t.Fatal(err)
	}
	info, _ := os.Stat(target)
	if data, _ := os.ReadFile(target); string(data) != "new" || info.Mode().Perm() != 0o600 || !slices.Equal(entries(), []string{"source", "target"}) {
		t.Fatal(string(data), info.Mode(), entries())
	}
}

func TestDeploymentLockExcludesOverlapAndReleasesAfterError(t *testing.T) {
	d := New(Paths{Lock: filepath.Join(t.TempDir(), "deploy.lock")}, "", io.Discard)
	release, err := d.Lock()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := d.Lock(); err == nil || !strings.Contains(err.Error(), "another") {
		t.Fatal("overlapping deployment admitted", err)
	}
	release()
	release, err = d.Lock()
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	if info, _ := os.Stat(d.Paths.Lock); info.Mode().Perm() != 0o600 {
		t.Fatal(info.Mode())
	}
}

func TestDeploymentLockRejectsSymlink(t *testing.T) {
	dir := t.TempDir()
	target, link := filepath.Join(dir, "private"), filepath.Join(dir, "lock")
	os.WriteFile(target, []byte("unchanged"), 0o600)
	os.Symlink(target, link)
	if _, err := New(Paths{Lock: link}, "", io.Discard).Lock(); err == nil {
		t.Fatal("symlink accepted")
	}
	if data, _ := os.ReadFile(target); string(data) != "unchanged" {
		t.Fatal(string(data))
	}
}

func stopFixture() (*Deployer, *fakeRun) {
	run := &fakeRun{results: []func([]string) (string, error){output("pid = 123\n"), output("")}}
	d := New(Paths{}, "", io.Discard)
	d.Run, d.Sleep = run.run, func(time.Duration) {}
	return d, run
}

func TestStopWaitsForWriterExit(t *testing.T) {
	d, run := stopFixture()
	checks := 0
	alive := sequence(true, false)
	d.ProcessAlive = func(pid int) (bool, error) { checks++; return alive(), nil }
	if err := d.stopService(); err != nil {
		t.Fatal(err)
	}
	if checks != 2 || !slices.Equal(run.calls[len(run.calls)-1], []string{"/bin/launchctl", "bootout", Label}) {
		t.Fatal(checks, run.calls)
	}
}

func TestCandidateStopDoesNotIgnoreUnknownLaunchdError(t *testing.T) {
	for _, code := range []int{5, 113} {
		run := &fakeRun{results: []func([]string) (string, error){failure(code)}}
		d := New(Paths{}, "", io.Discard)
		d.Run = run.run
		if err := d.stopCandidate(); (err == nil) != (code == 113) {
			t.Fatal(code, err)
		}
	}
}

func TestStopTimeoutIsBoundedAndNeverKillsArbitraryProcess(t *testing.T) {
	d, _ := stopFixture()
	d.Now = sequence(time.Unix(0, 0), time.Unix(16, 0))
	d.ProcessAlive = func(int) (bool, error) { t.Fatal("process signalled"); return false, nil }
	restarts := 0
	d.StartService = func() error { restarts++; return nil }
	if err := d.stopService(); err == nil || !strings.Contains(err.Error(), "still exiting") || restarts != 1 {
		t.Fatal(err, restarts)
	}
}

func TestBootoutFailureDoesNotDuplicateService(t *testing.T) {
	run := &fakeRun{results: []func([]string) (string, error){output("pid = 123\n"), failure(5)}}
	d := New(Paths{}, "", io.Discard)
	d.Run = run.run
	d.StartService = func() error { t.Fatal("service restarted after failed bootout"); return nil }
	if err := d.stopService(); err == nil {
		t.Fatal("bootout failure ignored")
	}
}

func TestStopTimeoutReportsRegistrationRecoveryFailure(t *testing.T) {
	d, _ := stopFixture()
	d.Now = sequence(time.Unix(0, 0), time.Unix(16, 0))
	d.StartService = func() error { return errors.New("bootstrap failure") }
	if err := d.stopService(); err == nil || !strings.Contains(err.Error(), "registration recovery failed") {
		t.Fatal(err)
	}
}

func TestLaunchdUnloadRaceIsRetried(t *testing.T) {
	run := &fakeRun{results: []func([]string) (string, error){failure(5), output("started")}}
	d := New(Paths{Plist: "plist"}, "", io.Discard)
	d.Run, d.Sleep = run.run, func(time.Duration) {}
	if err := d.startService(); err != nil || len(run.calls) != 2 {
		t.Fatal(err, run.calls)
	}
}

type closer struct{}

func (closer) Close() error { return nil }

func TestHealthWaitsForListenerBeforeHTTPSProbes(t *testing.T) {
	run := &fakeRun{}
	d := New(Paths{}, "", io.Discard)
	d.Run = run.run
	var sleeps []time.Duration
	d.Sleep = func(duration time.Duration) { sleeps = append(sleeps, duration) }
	var dials []string
	refused := sequence(true, false)
	d.Dial = func(address string, timeout time.Duration) (io.Closer, error) {
		dials = append(dials, address+"/"+timeout.String())
		if refused() {
			return nil, errors.New("connection refused")
		}
		return closer{}, nil
	}
	if err := d.health(17891); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(dials, []string{"127.0.0.1:17891/250ms", "127.0.0.1:17891/250ms"}) ||
		!slices.Equal(sleeps, []time.Duration{100 * time.Millisecond}) || len(run.calls) != 2 {
		t.Fatal(dials, sleeps, run.calls)
	}
}

func TestListenerReadinessTimeoutSkipsHTTPSProbes(t *testing.T) {
	run := &fakeRun{}
	d := New(Paths{}, "", io.Discard)
	d.Run = run.run
	d.Now = sequence(time.Unix(0, 0), time.Unix(16, 0))
	d.Dial = func(string, time.Duration) (io.Closer, error) { return nil, errors.New("connection refused") }
	if err := d.health(ProxyPort); err == nil || !strings.Contains(err.Error(), "listener did not become ready") || len(run.calls) != 0 {
		t.Fatal(err, run.calls)
	}
}

// exercise mirrors a live upgrade with every service interaction faked and
// every file in a temporary tree.
func exercise(t *testing.T, failing string) {
	root := t.TempDir()
	paths := Paths{Binary: filepath.Join(root, "active-binary"), Plist: filepath.Join(root, "active.plist"),
		Config: filepath.Join(root, "active.json"), Tool: filepath.Join(root, "active-tool"),
		Rules: filepath.Join(root, "rules"), Cache: filepath.Join(root, "cache"), LogDir: filepath.Join(root, "logs"),
		State: filepath.Join(root, "state"), Lock: filepath.Join(root, "lock"), BackupParent: root}
	for _, dir := range []string{paths.Rules, paths.Cache, paths.LogDir} {
		os.Mkdir(dir, 0o700)
	}
	originals := map[string]string{paths.Binary: "old binary", paths.Plist: "old plist", paths.Config: "old config", paths.Tool: "old tool"}
	for path, data := range originals {
		os.WriteFile(path, []byte(data), 0o644)
	}
	for _, name := range RuleNames {
		os.WriteFile(filepath.Join(paths.Rules, name+".json"), []byte("old seed"), 0o644)
		os.WriteFile(filepath.Join(paths.Cache, name+".json"), []byte("old cache"), 0o600)
		os.WriteFile(filepath.Join(root, name+".json"), []byte("new seed"), 0o644)
	}
	staged := map[string]string{EngineName: "new binary", PlistName: "new plist", "config.json": "new config", ToolName: "new tool"}
	for name, data := range staged {
		os.WriteFile(filepath.Join(root, name), []byte(data), 0o644)
	}
	d := New(paths, root, io.Discard)
	simulated := func(step string) error { return errors.New("simulated " + step + " failure") }
	d.Chown = noChown
	d.ValidateStage = func() (map[string]any, error) { return map[string]any{}, nil }
	d.Preflight = func(map[string]any) error {
		if failing == "preflight" {
			return simulated("preflight")
		}
		return nil
	}
	d.Snapshot = func(backup string, targets []string) ([]Record, error) {
		if failing == "snapshot" {
			return nil, simulated("snapshot")
		}
		return d.snapshotFiles(backup, targets)
	}
	d.Restore = func(backup string, records []Record) error {
		if failing == "rollback" {
			return simulated("rollback")
		}
		return d.restoreFiles(backup, records)
	}
	d.EnsureDir = func(string, os.FileMode, string) error { return nil }
	stops, candidateStops, starts := 0, 0, 0
	d.StopService = func() error {
		stops++
		if failing == "stop" {
			return simulated("stop")
		}
		return nil
	}
	d.StopCandidate = func() error { candidateStops++; return nil }
	d.StartService = func() error { starts++; return nil }
	var commands [][]string
	d.Run = func(args ...string) (string, error) {
		commands = append(commands, args)
		if args[0] == "/usr/bin/curl" && (failing == "activation" || failing == "rollback") {
			os.WriteFile(filepath.Join(paths.Cache, "domestic.json"), []byte("candidate cache"), 0o600)
			return "", simulated("activation")
		}
		return "program = " + paths.Binary + "\nstate = running\n", nil
	}
	d.Dial = func(string, time.Duration) (io.Closer, error) { return closer{}, nil }

	backup, err := d.Upgrade(false)
	if failing == "" {
		if err != nil {
			t.Fatal(err)
		}
		if _, err := os.Stat(filepath.Join(backup, "manifest.json")); err != nil {
			t.Fatal(err)
		}
		for name, target := range map[string]string{EngineName: paths.Binary, "config.json": paths.Config, ToolName: paths.Tool} {
			if data, _ := os.ReadFile(target); string(data) != staged[name] {
				t.Fatal(target, string(data))
			}
		}
	} else if err == nil || !strings.Contains(err.Error(), "simulated") {
		t.Fatal(failing, err)
	}
	for _, args := range commands {
		if args[0] == "/usr/sbin/networksetup" {
			t.Fatal("upgrade changed macOS proxy settings")
		}
	}
	var backups int
	entries, _ := os.ReadDir(root)
	for _, entry := range entries {
		if entry.IsDir() && !slices.Contains([]string{"rules", "cache", "logs"}, entry.Name()) {
			backups++
		}
	}
	if want := map[bool]int{true: 1, false: 0}[failing == "" || failing == "rollback"]; backups != want {
		t.Fatalf("%s: %d backups, want %d", failing, backups, want)
	}
	if failing != "" && failing != "rollback" {
		for path, data := range originals {
			if got, _ := os.ReadFile(path); string(got) != data {
				t.Fatalf("%s: %s = %q", failing, path, got)
			}
		}
		for _, name := range RuleNames {
			seed, _ := os.ReadFile(filepath.Join(paths.Rules, name+".json"))
			cache, _ := os.ReadFile(filepath.Join(paths.Cache, name+".json"))
			if string(seed) != "old seed" || string(cache) != "old cache" {
				t.Fatalf("%s: %s seed %q cache %q", failing, name, seed, cache)
			}
		}
	}
	wantStarts := map[string]int{"preflight": 0, "stop": 0, "activation": 2}
	if want, ok := wantStarts[failing]; (ok && starts != want) || (!ok && starts != 1) {
		t.Fatalf("%s: %d starts", failing, starts)
	}
	if want := map[bool]int{true: 0, false: 1}[failing == "preflight"]; stops != want {
		t.Fatalf("%s: %d stops", failing, stops)
	}
	if want := map[bool]int{true: 1, false: 0}[failing == "activation" || failing == "rollback"]; candidateStops != want {
		t.Fatalf("%s: %d candidate stops", failing, candidateStops)
	}
}

func TestUpgradeSuccessKeepsAcceptanceBackup(t *testing.T)     { exercise(t, "") }
func TestPreflightFailureDoesNotStopOrWrite(t *testing.T)      { exercise(t, "preflight") }
func TestStopFailureDoesNotReplaceFiles(t *testing.T)          { exercise(t, "stop") }
func TestSnapshotFailureRestartsUnchangedService(t *testing.T) { exercise(t, "snapshot") }
func TestActivationFailureRestoresFilesAndCache(t *testing.T)  { exercise(t, "activation") }
func TestRollbackFailureRetainsPrivateBackup(t *testing.T)     { exercise(t, "rollback") }

func TestUpgradeRefusesUnexpectedActiveProgram(t *testing.T) {
	d := New(Production, t.TempDir(), io.Discard)
	d.Run = func(...string) (string, error) { return "program = /usr/local/libexec/other\n", nil }
	d.ValidateStage = func() (map[string]any, error) { t.Fatal("stage validated"); return nil, nil }
	if _, err := d.Upgrade(false); err == nil || !strings.Contains(err.Error(), "unexpected active proxy program") {
		t.Fatal(err)
	}
}

func TestStageRejectsWrongInterfaceBeforePreflight(t *testing.T) {
	root := t.TempDir()
	os.WriteFile(filepath.Join(root, "config.json"), []byte(`{"version":1,"listen":"0.0.0.0:17890"}`), 0o644)
	if _, err := New(Production, root, io.Discard).validateStage(); err == nil || !strings.Contains(err.Error(), "configuration") {
		t.Fatal(err)
	}
}

// The real repository stage must pass validation through the real plutil.
func TestStageAcceptsRepositoryConfigurationAndService(t *testing.T) {
	root := t.TempDir()
	config, err := proxyconfig.Build("../../../config", "", "")
	if err != nil {
		t.Fatal(err)
	}
	data, _ := proxyconfig.Encode(config)
	os.WriteFile(filepath.Join(root, "config.json"), data, 0o644)
	plist, _ := os.ReadFile("../../../config/launchd/" + PlistName)
	os.WriteFile(filepath.Join(root, PlistName), plist, 0o644)
	paths := Production
	paths.Plist = filepath.Join(root, "not-installed.plist")
	if _, err := New(paths, root, io.Discard).validateStage(); err != nil {
		t.Fatal(err)
	}
	paths.Plist = filepath.Join(root, "installed.plist")
	changed := strings.Replace(string(plist), "<key>ThrottleInterval</key><integer>5</integer>", "<key>ThrottleInterval</key><integer>1</integer>", 1)
	if changed == string(plist) {
		t.Fatal("fixture did not change a service setting")
	}
	os.WriteFile(paths.Plist, []byte(changed), 0o644)
	if _, err := New(paths, root, io.Discard).validateStage(); err == nil || !strings.Contains(err.Error(), "other than engine arguments") {
		t.Fatal(err)
	}
}

func TestSnapshotRefusesSymlinks(t *testing.T) {
	root := t.TempDir()
	original, link := filepath.Join(root, "original"), filepath.Join(root, "link")
	os.WriteFile(original, []byte("unchanged"), 0o644)
	os.Symlink(original, link)
	if _, err := New(Paths{}, root, io.Discard).snapshotFiles(root, []string{link}); err == nil || !strings.Contains(err.Error(), "symlink") {
		t.Fatal(err)
	}
	if data, _ := os.ReadFile(original); string(data) != "unchanged" {
		t.Fatal(string(data))
	}
}

func TestEnableSavesSettingsOnceAndRollbackRestoresThem(t *testing.T) {
	root := t.TempDir()
	d := New(Paths{State: filepath.Join(root, "previous.json")}, root, io.Discard)
	d.Dial = func(string, time.Duration) (io.Closer, error) { return closer{}, nil }
	var sets [][]string
	d.Run = func(args ...string) (string, error) {
		if args[0] == "/usr/sbin/networksetup" && strings.HasPrefix(args[1], "-get") {
			if args[2] == "Wi-Fi" {
				return "Enabled: Yes\nServer: 10.0.0.2\nPort: 3128\nAuthenticated Proxy Enabled: 0\n", nil
			}
			return "Enabled: No\nServer: \nPort: 0\nAuthenticated Proxy Enabled: 0\n", nil
		}
		if args[0] == "/usr/sbin/networksetup" {
			sets = append(sets, args[1:])
		}
		return "", nil
	}
	if err := d.Enable(); err != nil {
		t.Fatal(err)
	}
	if len(sets) != 8 || !slices.Equal(sets[0], []string{"-setwebproxy", "Wi-Fi", "127.0.0.1", "17890"}) {
		t.Fatal(sets)
	}
	var saved proxySettings
	data, _ := os.ReadFile(d.State)
	if json.Unmarshal(data, &saved) != nil || saved["Wi-Fi"]["webproxy"]["Server"] != "10.0.0.2" {
		t.Fatalf("%s", data)
	}
	if err := d.Enable(); err == nil {
		t.Fatal("second enable overwrote the saved settings")
	}
	sets = nil
	if err := d.Rollback(); err != nil {
		t.Fatal(err)
	}
	want := [][]string{{"-setwebproxy", "Wi-Fi", "10.0.0.2", "3128"}, {"-setwebproxystate", "Wi-Fi", "on"},
		{"-setsecurewebproxy", "Wi-Fi", "10.0.0.2", "3128"}, {"-setsecurewebproxystate", "Wi-Fi", "on"},
		{"-setwebproxystate", "Ethernet", "off"}, {"-setsecurewebproxystate", "Ethernet", "off"}}
	if len(sets) != len(want) {
		t.Fatal(sets)
	}
	for i := range want {
		if !slices.Equal(sets[i], want[i]) {
			t.Fatal(sets)
		}
	}
}

func TestEnableRefusesAuthenticatedProxy(t *testing.T) {
	root := t.TempDir()
	d := New(Paths{State: filepath.Join(root, "previous.json")}, root, io.Discard)
	d.Dial = func(string, time.Duration) (io.Closer, error) { return closer{}, nil }
	d.Run = func(args ...string) (string, error) {
		return "Enabled: Yes\nServer: proxy\nPort: 8080\nAuthenticated Proxy Enabled: 1\n", nil
	}
	if err := d.Enable(); err == nil || !strings.Contains(err.Error(), "authenticated proxy") {
		t.Fatal(err)
	}
	if _, err := os.Stat(d.State); err == nil {
		t.Fatal("state written for a refused enable")
	}
}
