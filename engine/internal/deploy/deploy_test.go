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
	if !slices.Contains(run.calls[1], "--head") || slices.Contains(run.calls[0], "--head") {
		t.Fatal("foreign probe must avoid full-page download; domestic HEAD may be unsupported", run.calls)
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
