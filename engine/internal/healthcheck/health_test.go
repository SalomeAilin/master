package healthcheck

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestScheduleBaselineRegressionCooldownAndOutliers(t *testing.T) {
	s, now := Initial(), int64(1000)
	for i := 0; i < 6; i++ {
		now += 30
		s.Record(now, 100, true, "ok")
	}
	if s.Interval != 60 || s.Baseline != 100 {
		t.Fatal(s)
	}
	for i := 0; i < 6; i++ {
		now += 60
		s.Record(now, 100, true, "ok")
	}
	if s.Interval != 120 {
		t.Fatal(s)
	}
	for i := 0; i < 2; i++ {
		now += 120
		s.Record(now, 500, true, "ok")
	}
	if s.Interval != 120 {
		t.Fatal("rolled back on fewer than three regressions", s)
	}
	now += 120
	s.Record(now, 500, true, "ok")
	if s.Interval != 30 || s.Cooldown != now+600 || s.Baseline != 0 {
		t.Fatal(s)
	}
	for i := 0; i < 19; i++ {
		now += 30
		s.Record(now, 100, true, "ok")
		if s.Interval != 30 {
			t.Fatal(s)
		}
	}
	now += 30
	s.Record(now, 100, true, "ok")
	if s.Interval != 60 {
		t.Fatal(s)
	}
	s = Initial()
	for i := 0; i < 6; i++ {
		now += 30
		s.Record(now, 100, true, "ok")
	}
	for _, sample := range []int64{500, 100, 100, 100, 100, 100} {
		now += 60
		s.Record(now, sample, true, "ok")
		if s.Interval == 30 {
			t.Fatal("one outlier caused rollback")
		}
	}
	for _, sample := range []int64{500, 500, 100, 500, 500, 100} {
		now += 120
		s.Record(now, sample, true, "ok")
	}
	if s.Interval != 30 {
		t.Fatal("bad median accepted", s)
	}
	s = Initial()
	for i := 0; i < 6; i++ {
		now += 30
		s.Record(now, 1000, true, "ok")
	}
	for i := 0; i < 6; i++ {
		now += 60
		s.Record(now, 1400, true, "ok")
	}
	if s.Interval != 120 {
		t.Fatal("relative and absolute margins were not both applied", s)
	}
}

func TestStateValidationAndPrivateAtomicPublication(t *testing.T) {
	s := State{Interval: 30, LastProbe: 1000, Cooldown: 1600}
	valid := string(s.Encode())
	for _, data := range []string{"failure_count=2", "version=$(touch forbidden)",
		valid + "version=1\n", strings.Repeat("x", 4097),
		strings.Replace(valid, "probe_interval=30", "probe_interval=999", 1),
		strings.Replace(valid, "failure_count=0", "failure_count=1000001", 1),
		strings.Replace(valid, "slow_count=0", "slow_count=3", 1),
		strings.Replace(valid, "baseline_ms=0", "baseline_ms=10001", 1),
		strings.Replace(valid, "probe_samples=", "probe_samples=1,,2", 1),
		strings.Replace(valid, "probe_samples=", "probe_samples=1,", 1),
		strings.Replace(valid, "probe_samples=", "probe_samples=1,2,3,4,5,6,7", 1),
		strings.Replace(valid, "probe_samples=", "probe_samples=10001", 1)} {
		if _, err := Decode([]byte(data), 1000); err == nil {
			t.Fatal("invalid state accepted", data)
		}
	}
	for _, now := range []int64{999, 1601} {
		if _, err := Decode(s.Encode(), now); err == nil {
			t.Fatal("clock/sleep reset missing", now)
		}
	}
	path := filepath.Join(t.TempDir(), "state")
	if err := Save(path, s, os.Rename); err != nil {
		t.Fatal(err)
	}
	info, _ := os.Stat(path)
	if info.Mode().Perm() != 0o600 {
		t.Fatal(info.Mode())
	}
	decoded, err := Decode(s.Encode(), 1000)
	if err != nil || !reflect.DeepEqual(s, decoded) {
		t.Fatal(decoded, err)
	}
	changed := s
	changed.Failures = 5
	if err := Save(path, changed, func(string, string) error { return errors.New("rename failed") }); err == nil {
		t.Fatal("failure ignored")
	}
	if data, _ := os.ReadFile(path); string(data) != valid {
		t.Fatal("old state changed")
	}
	if _, err := os.Stat(path + ".tmp." + strconv.Itoa(os.Getpid())); !os.IsNotExist(err) {
		t.Fatal("temporary state retained", err)
	}
	link := filepath.Join(filepath.Dir(path), "link")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if err := Save(link, s, os.Rename); err == nil {
		t.Fatal("symlink state accepted")
	}
}

func runnerFixture(t *testing.T) (*Runner, *int64, *Result, *int, *int) {
	t.Helper()
	dir := t.TempDir()
	now := int64(1000)
	result := Result{Status: 200, ElapsedMS: 100, RemoteIP: "192.0.2.10", LocalIP: "192.0.2.20"}
	probes, repairs := 0, 0
	r := &Runner{StatePath: filepath.Join(dir, "state"), LogPath: filepath.Join(dir, "health.log"),
		Now:   func() time.Time { return time.Unix(now, 0) },
		Probe: func(context.Context) Result { probes++; return result },
		Route: func(string) (bool, error) { return true, nil },
		Run: func(args ...string) (string, error) {
			if !reflect.DeepEqual(args, []string{"/bin/launchctl", "kickstart", GuardService}) {
				t.Fatal("unexpected mutation", args)
			}
			repairs++
			return "", nil
		}}
	return r, &now, &result, &probes, &repairs
}

func readState(t *testing.T, r *Runner, now int64) State {
	t.Helper()
	data, err := os.ReadFile(r.StatePath)
	if err != nil {
		t.Fatal(err)
	}
	s, err := Decode(data, now)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestOneHourReplayAndFailureRecovery(t *testing.T) {
	r, now, result, probes, repairs := runnerFixture(t)
	for value := int64(1000); value <= 4600; value += 30 {
		*now = value
		if err := r.RunOnce(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	if *probes != 37 || *repairs != 0 || readState(t, r, *now).Interval != 120 {
		t.Fatal(*probes, *repairs)
	}
	*now = 4720
	result.Err = errors.New("timeout")
	result.Status = 0
	result.ElapsedMS = 10000
	if err := r.RunOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if readState(t, r, *now).Interval != 30 || *repairs != 0 {
		t.Fatal("timeout triggered route repair")
	}
	result.Err = nil
	result.Status = 403
	result.ElapsedMS = 10
	for value := int64(4750); value <= 5500; value += 30 {
		*now = value
		if err := r.RunOnce(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	if readState(t, r, *now).Interval != 30 || *repairs != 0 {
		t.Fatal("challenge became a tuning baseline")
	}
	*now = 5530
	result.Status = 200
	result.ElapsedMS = 100
	r.Route = func(string) (bool, error) { return false, nil }
	if err := r.RunOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if *repairs != 1 {
		t.Fatal("confirmed drift did not request exactly one recovery", *repairs)
	}
	*now = 5560
	r.Route = func(string) (bool, error) { return false, errors.New("route query failed") }
	if err := r.RunOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if *repairs != 1 {
		t.Fatal("unknown route state triggered repair")
	}
	*now = 5590
	r.Route = func(string) (bool, error) { return true, nil }
	result.ElapsedMS = -1
	if err := r.RunOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if *repairs != 1 || readState(t, r, *now).Interval != 30 {
		t.Fatal("invalid timing changed routes")
	}
	*now = 6300
	result.ElapsedMS = 100
	if err := r.RunOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(readState(t, r, *now).Samples) != 1 {
		t.Fatal("stale state did not reset")
	}
}

func TestCancelledProbeCannotOverwriteState(t *testing.T) {
	r, now, _, _, _ := runnerFixture(t)
	if err := r.RunOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(r.StatePath)
	*now += 30
	ctx, cancel := context.WithCancel(context.Background())
	r.Probe = func(context.Context) Result { cancel(); return Result{Err: context.Canceled} }
	if err := r.RunOnce(ctx); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if after, _ := os.ReadFile(r.StatePath); string(after) != string(before) {
		t.Fatal("cancelled probe replaced state")
	}
}

func TestNativeHTTPProbeUsesDirectIPv4AndBoundsBody(t *testing.T) {
	for _, oversized := range []bool{false, true} {
		t.Run(strconv.FormatBool(oversized), func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodGet {
					t.Error(r.Method)
				}
				if oversized {
					fmt.Fprint(w, strings.Repeat("x", (4<<20)+1))
				} else {
					fmt.Fprint(w, "healthy")
				}
			}))
			defer server.Close()
			t.Setenv("HTTP_PROXY", "http://127.0.0.1:1")
			result := Probe(context.Background(), server.URL)
			if result.Status != 200 || result.RemoteIP != "127.0.0.1" || result.LocalIP != "127.0.0.1" || (result.Err != nil) != oversized {
				t.Fatal(result)
			}
		})
	}
}

func TestNativeProbeVerifiesTLS(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "healthy") }))
	defer server.Close()
	if result := Probe(context.Background(), server.URL); result.Err == nil {
		t.Fatal("untrusted certificate accepted")
	}
}

func TestRouteCheckUsesConfiguredInterfaceAndScopedGateway(t *testing.T) {
	r, _, _, _, _ := runnerFixture(t)
	r.ConfigPath = filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(r.ConfigPath, []byte(`{"domestic":{"interface":"en-test"}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	calls := 0
	r.Run = func(args ...string) (string, error) {
		calls++
		if calls == 1 && !reflect.DeepEqual(args, []string{"/sbin/route", "-n", "get", "-ifscope", "en-test", "default"}) {
			t.Fatal(args)
		}
		if calls == 2 && !reflect.DeepEqual(args, []string{"/sbin/route", "-n", "get", "192.0.2.10"}) {
			t.Fatal(args)
		}
		return "gateway: 192.0.2.1\ninterface: en-test\n", nil
	}
	if ok, err := r.wiredRoute("192.0.2.10"); err != nil || !ok || calls != 2 {
		t.Fatal(ok, err, calls)
	}
}
