package statuspage

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"network-owned-engine/internal/dnsservice"
	"network-owned-engine/internal/runtimecheck"
)

func fixture(t *testing.T, scenario string) *Collector {
	t.Helper()
	dir := t.TempDir()
	c := &Collector{Etc: dir, Sbin: dir, Launchd: dir, Now: func() time.Time { return time.Unix(1000, 0) }, Metadata: func(string, os.FileMode) bool { return true }}
	for name, data := range map[string]string{
		"network-domain-proxy.json":  `{"domestic":{"interface":"wired-test"},"foreign":{"interface":"wifi-test"}}`,
		"dnsmasq-network-split.conf": "listen-address=127.0.0.1,192.0.2.10\nno-resolv\nfilter-AAAA\ndomain-needed\nbogus-priv\nstop-dns-rebind\ndns-loop-detect\nlocal-service\n",
		"china_ip_list.txt":          "223.5.5.0/24\n", "domestic_extra_routes.txt": "223.5.5.5/32\n", "domestic_domains.conf": "domestic.test\n",
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(data), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if scenario == "broken-policy" {
		os.Remove(filepath.Join(dir, "china_ip_list.txt"))
	}
	if scenario == "fallback-baseline-failure" {
		os.WriteFile(filepath.Join(dir, "dnsmasq-network-split.conf"), []byte("listen-address=127.0.0.1,192.0.2.10\nno-resolv\nfilter-AAAA\ndomain-needed\nbogus-priv\ndns-loop-detect\nlocal-service\n"), 0o600)
	}
	// The negative probe goes to a foreign upstream. While Wi-Fi is down that
	// upstream is unreachable and the local listener answers SERVFAIL.
	servfail := &net.DNSError{Err: "server misbehaving", IsTemporary: true}
	foreignDNSDown := map[string]bool{"fallback-blocked-dns": true, "fallback-control-failure": true, "fallback-baseline-failure": true, "unblocked-down-dns": true, "foreign-dns-failure": true}
	c.Lookup = func(_ context.Context, name string) ([]netip.Addr, error) {
		if strings.HasSuffix(name, ".invalid.") {
			if scenario == "fallback-dns-hijack" {
				return []netip.Addr{netip.MustParseAddr("198.51.100.7")}, nil
			}
			if foreignDNSDown[scenario] {
				return nil, servfail
			}
			return nil, &net.DNSError{IsNotFound: true}
		}
		if name == "baidu.com" && scenario == "fallback-control-failure" {
			return nil, servfail
		}
		ip := "9.9.9.9"
		if name == "domestic.test" || name == "baidu.com" {
			ip = "223.5.5.5"
		}
		if name == "domestic.test" {
			switch scenario {
			case "excluded":
				ip = "8.8.8.8"
			case "private":
				ip = "127.0.0.1"
			case "lookup-failure":
				return nil, errors.New("lookup failed")
			}
		}
		return []netip.Addr{netip.MustParseAddr(ip)}, nil
	}
	wired := "gateway: 192.0.2.1\ninterface: wired-test\nflags: <UP,GATEWAY>\n"
	wifi := "gateway: 198.51.100.1\ninterface: wifi-test\nflags: <UP,GATEWAY>\n"
	fallback := strings.HasPrefix(scenario, "fallback")
	wifiDown := fallback || strings.HasPrefix(scenario, "unblocked-down")
	c.Run = func(_ context.Context, args ...string) (string, error) {
		switch args[0] {
		case "/sbin/route":
			if len(args) < 4 || args[1] != "-n" || args[2] != "get" {
				t.Fatal("route mutation", args)
			}
			target := args[len(args)-1]
			if len(args) > 4 {
				if args[4] == "wired-test" {
					return wired, nil
				}
				if wifiDown {
					return "", errors.New("down")
				}
				return wifi, nil
			}
			if fallback {
				if target == "1.1.1.1" || target == "208.67.222.222" {
					return "gateway: 127.0.0.1\ninterface: lo0\nflags: <UP,REJECT>\n", nil
				}
				if target == "default" {
					return wired, nil
				}
			}
			if target == "223.5.5.5" && scenario != "drift" {
				return wired, nil
			}
			return wifi, nil
		case "/bin/launchctl":
			if args[1] != "print" {
				t.Fatal("service mutation", args)
			}
			name := "network-split-dns-event-route-agent"
			if strings.Contains(args[2], "dnsmasq") {
				name = "dnsmasq-network-split"
			}
			return "state = running\nprogram = " + filepath.Join(dir, name) + "\n", nil
		case "/usr/sbin/networksetup":
			if args[1] != "-getdnsservers" {
				t.Fatal("DNS mutation", args)
			}
			return "192.0.2.10\n", nil
		case "/usr/sbin/scutil":
			return "nameserver[0] : 192.0.2.10\n", nil
		case "/usr/bin/plutil":
			data, _ := json.Marshal(map[string]any{"ProgramArguments": []string{filepath.Join(dir, "dnsmasq-network-split"), "--conf-file=" + filepath.Join(dir, "dnsmasq-network-split.conf")}})
			return string(data), nil
		default:
			t.Fatal("unexpected command", args)
			return "", errors.New("unexpected")
		}
	}
	c.HTTP = func(_ context.Context, iface, url string) (string, bool) {
		if iface != "wifi-test" {
			t.Fatal("wrong interface", iface)
		}
		if fallback {
			t.Fatal("foreign HTTP during fallback")
		}
		return "HTTP 204; 1 ms; interface=wifi-test", scenario != "http-failure"
	}
	return c
}

func TestUnifiedObserverUsesTheSharedExecutable(t *testing.T) {
	c := fixture(t, "normal")
	c.ObserverProgram = "/usr/local/libexec/network-domain-engine"
	base := c.Run
	c.Run = func(ctx context.Context, args ...string) (string, error) {
		if args[0] == "/bin/launchctl" && strings.Contains(args[2], "dns-event-route") {
			return "state = running\nprogram = " + c.ObserverProgram + "\n", nil
		}
		return base(ctx, args...)
	}
	if report := c.Collect(context.Background()); report.State != "OK" {
		t.Fatal(report)
	}
}

func TestNativeDNSStatusChecksTheNewPrivilegeAndSocketBoundary(t *testing.T) {
	c := fixture(t, "normal")
	c.NativeDNSProgram = "/usr/local/libexec/network-domain-engine"
	path := filepath.Join(c.Etc, "dnsmasq-network-split.conf")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	data = append(data, []byte("bind-interfaces\nserver=1.1.1.1\nserver=/cn/223.5.5.5\nlog-queries=extra\nlog-facility=/var/log/dnsmasq-network-split-query.log\n")...)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	p, err := dnsservice.Parse(data)
	if err != nil {
		t.Fatal(err)
	}
	definition := map[string]any{"ProgramArguments": []string{c.NativeDNSProgram, "worker", "dns", "-policy", path, "-wired-interface", "wired-test", "-wifi-interface", "wifi-test"}, "UserName": "nobody", "Sockets": p.SocketDefinition()}
	base := c.Run
	c.Run = func(ctx context.Context, args ...string) (string, error) {
		if args[0] == "/usr/bin/plutil" {
			b, _ := json.Marshal(definition)
			return string(b), nil
		}
		if args[0] == "/bin/launchctl" && args[2] == "system/"+runtimecheck.NativeDNSLabel {
			return "state = running\nprogram = " + c.NativeDNSProgram + "\n", nil
		}
		return base(ctx, args...)
	}
	c.Metadata = func(path string, mode os.FileMode) bool {
		if path == c.NativeDNSProgram {
			return mode == 0o755
		}
		return true
	}
	if report := c.Collect(context.Background()); report.State != "OK" {
		t.Fatal(report)
	}
	for _, field := range []string{"UserName", "Sockets", "ProgramArguments"} {
		before := definition[field]
		definition[field] = nil
		if report := c.Collect(context.Background()); report.State != "BAD" {
			t.Fatal("invalid native definition accepted", field, report)
		}
		definition[field] = before
	}
}

func TestFailureUsesExistingBoundedPrivateUserLog(t *testing.T) {
	dir := t.TempDir()
	state, log := filepath.Join(dir, "state"), filepath.Join(dir, "status.log")
	if err := RecordFailure(state, log, errors.New("publish failed\n"+strings.Repeat("x", 10000))); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(log)
	if err != nil || len(data) > 8192 || !strings.Contains(string(data), "state=ERROR") || strings.Count(string(data), "\n") != 1 {
		t.Fatal(len(data), err)
	}
	info, err := os.Stat(log)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatal(info, err)
	}
	if err := RecordFailure(state, state, errors.New("bad path")); err == nil {
		t.Fatal("shared state and log accepted")
	}
}

func TestStatusPolicyAndFallback(t *testing.T) {
	for _, scenario := range []string{"healthy", "excluded", "drift", "private", "lookup-failure", "broken-policy", "fallback", "unblocked-down", "http-failure"} {
		t.Run(scenario, func(t *testing.T) {
			r := fixture(t, scenario).Collect(context.Background())
			want := "BAD"
			if scenario == "healthy" || scenario == "excluded" {
				want = "OK"
			}
			if scenario == "fallback" {
				want = "FALLBACK"
			}
			if r.State != want {
				t.Fatalf("got %s want %s: %+v", r.State, want, r.Checks)
			}
			if scenario == "excluded" && r.Domains[0].State != "policy-excluded" {
				t.Fatal(r.Domains)
			}
		})
	}
}

// Only a verified fallback, with the local listener still answering domestic
// names, may excuse a failed negative probe. Every other case keeps alarming.
func TestNegativeDNSIsBlockedOnlyInVerifiedFallback(t *testing.T) {
	for scenario, want := range map[string]struct{ state, negative, alsoBad string }{
		"fallback-blocked-dns":      {"FALLBACK", "blocked", ""},
		"fallback":                  {"FALLBACK", "ok", ""},
		"fallback-dns-hijack":       {"BAD", "bad", ""},
		"fallback-control-failure":  {"BAD", "bad", "baidu.com"},
		"fallback-baseline-failure": {"BAD", "blocked", "dns-security-baseline"},
		"unblocked-down-dns":        {"BAD", "bad", "foreign-route"},
		"foreign-dns-failure":       {"BAD", "bad", ""},
	} {
		t.Run(scenario, func(t *testing.T) {
			r := fixture(t, scenario).Collect(context.Background())
			states := map[string]string{}
			for _, check := range r.Checks {
				states[check.Name] = check.State
			}
			if r.State != want.state || states["negative-dns"] != want.negative || want.alsoBad != "" && states[want.alsoBad] != "bad" {
				t.Fatalf("state %s, want %+v: %+v", r.State, want, r.Checks)
			}
		})
	}
}

func TestStatusPublicationEscapesAndBoundsHistory(t *testing.T) {
	dir := t.TempDir()
	html, state, log := filepath.Join(dir, "status.html"), filepath.Join(dir, "state"), filepath.Join(dir, "log")
	r := Report{Updated: time.Unix(1000, 0), State: "BAD", Checks: []Row{{Name: "<script>alert(1)</script>", State: "bad", Detail: "<img src=x onerror=alert(1)>"}}}
	if err := r.Publish(html, state, log); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(html)
	if strings.Contains(string(data), "<script>") || !strings.Contains(string(data), "&lt;script&gt;") {
		t.Fatal("unsafe HTML")
	}
	before, _ := os.ReadFile(log)
	if !strings.Contains(string(before), "issues=1") || !strings.Contains(string(before), "alert(1)") {
		t.Fatal("failure cause missing from bounded history")
	}
	if err := r.Publish(html, state, log); err != nil {
		t.Fatal(err)
	}
	after, _ := os.ReadFile(log)
	if string(before) != string(after) {
		t.Fatal("unchanged sample logged again")
	}
	for i := 0; i < 10; i++ {
		if err := appendLog(log, strings.Repeat("x", 8192)); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(log, []byte(strings.Repeat("x", logLimit-1)), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := appendLog(log, "rotate\n"); err != nil {
		t.Fatal(err)
	}
	for i := 0; i <= 3; i++ {
		path := log
		if i > 0 {
			path = fmt.Sprintf("%s.%d", log, i)
		}
		if info, err := os.Stat(path); err == nil && info.Size() > logLimit {
			t.Fatal("oversized history")
		}
	}
	entries, _ := os.ReadDir(dir)
	for _, entry := range entries {
		if strings.Contains(entry.Name(), ".tmp.") {
			t.Fatal("temporary output retained", entry.Name())
		}
	}
}

func TestPublicationReceiptRefreshesWithoutRepeatingUnchangedLog(t *testing.T) {
	dir := t.TempDir()
	html, state, log := filepath.Join(dir, "page"), filepath.Join(dir, "state"), filepath.Join(dir, "log")
	r := Report{Updated: time.Unix(1000, 0), State: "OK"}
	if err := r.Publish(html, state, log); err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(log)
	r.Updated = r.Updated.Add(time.Second)
	if err := r.Publish(html, state, log); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(state)
	var snapshot Snapshot
	if err := json.Unmarshal(data, &snapshot); err != nil {
		t.Fatal(err)
	}
	body, _ := os.ReadFile(html)
	digest := sha256.Sum256(body)
	if snapshot.HTMLPath != html || snapshot.HTMLSHA256 != fmt.Sprintf("%x", digest) || snapshot.HTMLBytes != int64(len(body)) || !snapshot.Checked.Equal(r.Updated) || snapshot.Published.IsZero() {
		t.Fatal(snapshot)
	}
	after, _ := os.ReadFile(log)
	if string(before) != string(after) {
		t.Fatal("receipt refresh grew the unchanged log")
	}
}

func TestStatusPublicationPreservesSymlinkTargets(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "user-file")
	os.WriteFile(target, []byte("keep"), 0o600)
	link := filepath.Join(dir, "page")
	os.Symlink(target, link)
	r := Report{Updated: time.Now(), State: "OK"}
	if err := r.Publish(link, filepath.Join(dir, "state"), filepath.Join(dir, "log")); err == nil {
		t.Fatal("symlink accepted")
	}
	data, _ := os.ReadFile(target)
	if string(data) != "keep" {
		t.Fatal("user content overwritten")
	}
}

func TestFailureDetailsRemainBoundedAfterJSONEscaping(t *testing.T) {
	dir := t.TempDir()
	r := Report{Updated: time.Now(), State: "BAD"}
	for i := 0; i < 10; i++ {
		r.Checks = append(r.Checks, Row{Name: strings.Repeat("\x00", 1000), State: "bad", Detail: strings.Repeat("\x01", 1000)})
	}
	log := filepath.Join(dir, "log")
	if err := r.Publish(filepath.Join(dir, "page"), filepath.Join(dir, "state"), log); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(log)
	if err != nil || len(data) > 8192 || !strings.Contains(string(data), "issues=10") {
		t.Fatal("unbounded or missing failure history", err)
	}
}

func TestForeignProbeUsesHEADAndNeverFallsBack(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.Method != http.MethodHead {
			t.Error("not HEAD", r.Method)
		}
		w.WriteHeader(204)
	}))
	defer server.Close()
	if _, ok := Head(context.Background(), "lo0", server.URL); !ok {
		t.Fatal("local HEAD failed")
	}
	if _, ok := Head(context.Background(), "interface-that-does-not-exist", server.URL); ok || calls.Load() != 1 {
		t.Fatal("interface fallback", calls.Load())
	}
	tlsServer := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Error("untrusted TLS request accepted") }))
	defer tlsServer.Close()
	if _, ok := Head(context.Background(), "lo0", tlsServer.URL); ok {
		t.Fatal("untrusted TLS accepted")
	}
}

func TestDNSConfigurationArgumentForms(t *testing.T) {
	for _, tail := range [][]string{{"-C", "/config"}, {"--conf-file", "/config"}, {"--conf-file=/config"}} {
		if !dnsArgumentsOK(append([]string{"/binary", "--keep-in-foreground"}, tail...), "/binary", "/config") {
			t.Fatal("valid arguments rejected", tail)
		}
	}
	for _, args := range [][]string{{"/other", "-C", "/config"}, {"/binary", "-C"}, {"/binary", "-C", "/other"}, {"/binary", "-C", "/config", "--conf-dir=/other"}, {"/binary", "-C", "/config", "--conf-file=/config"}} {
		if dnsArgumentsOK(args, "/binary", "/config") {
			t.Fatal("unsafe arguments accepted", args)
		}
	}
}
