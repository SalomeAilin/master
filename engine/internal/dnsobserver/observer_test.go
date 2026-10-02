package dnsobserver

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"network-owned-engine/internal/policy"
)

type binding struct{ domain, ip string }

type clock struct{ now time.Time }

func (c *clock) Now() time.Time { return c.now }

func correlator() (*Correlator, *[]binding, *clock) {
	var bound []binding
	tick := &clock{now: time.Unix(100, 0)}
	c := NewCorrelator(map[string]bool{"cn": true}, func(domain, ip string) { bound = append(bound, binding{domain, ip}) })
	c.Now = tick.Now
	return c, &bound, tick
}

func line(c *Correlator, value string, key ...string) {
	pid, id, client := "1", "7", "client"
	if len(key) > 0 {
		id = key[0]
	}
	if len(key) > 1 {
		pid = key[1]
	}
	if len(key) > 2 {
		client = key[2]
	}
	c.ProcessLine("dnsmasq[" + pid + "]: " + id + " " + client + " " + value)
}

func TestCNAMEChainStaysWithItsQueryNotSharedCDN(t *testing.T) {
	c, bound, _ := correlator()
	line(c, "query[A] good.cn from client")
	line(c, "reply good.cn is shared.example")
	line(c, "reply shared.example is 223.5.5.5")
	if !reflect.DeepEqual(*bound, []binding{{"good.cn", "223.5.5.5"}}) {
		t.Fatal(*bound)
	}
	*bound = nil
	line(c, "query[A] foreign.example from client", "8")
	line(c, "reply shared.example is 223.5.5.5", "8")
	if len(*bound) != 0 {
		t.Fatal("shared CDN alias inherited a domestic classification", *bound)
	}
}

func TestReusedQueryIDIsNotInheritedByForeignQuery(t *testing.T) {
	c, bound, _ := correlator()
	line(c, "query[A] good.cn from client")
	line(c, "query[A] foreign.example from client")
	line(c, "reply shared.example is 223.5.5.5")
	if len(*bound) != 0 || len(c.Pending()) != 0 {
		t.Fatal(*bound, c.Pending())
	}
}

func TestPIDAndClientArePartOfQueryIdentity(t *testing.T) {
	c, bound, _ := correlator()
	line(c, "query[A] good.cn from client")
	line(c, "reply shared.example is 223.5.5.5", "7", "2")
	line(c, "reply shared.example is 223.5.5.5", "7", "1", "other")
	if len(*bound) != 0 {
		t.Fatal(*bound)
	}
}

func TestExpiredQueryCannotClassifyALateCNAMEAnswer(t *testing.T) {
	c, bound, tick := correlator()
	line(c, "query[A] good.cn from client")
	tick.now = tick.now.Add(QueryTTL)
	line(c, "reply shared.example is 223.5.5.5")
	if len(*bound) != 0 || len(c.Pending()) != 0 {
		t.Fatal(*bound, c.Pending())
	}
}

func TestCacheIsBoundedAndUpdatedQueriesExpireInOrder(t *testing.T) {
	c, bound, tick := correlator()
	c.Max = 2
	for _, id := range []string{"1", "2", "1", "3"} {
		line(c, "query[A] good.cn from client", id)
		tick.now = tick.now.Add(time.Second)
	}
	if got := c.Pending(); !reflect.DeepEqual(got, []string{"1/1/client", "1/3/client"}) {
		t.Fatal(got)
	}
	tick.now = time.Unix(132, 0)
	line(c, "reply shared.example is 223.5.5.5", "1")
	if len(*bound) != 0 || len(c.Pending()) != 1 {
		t.Fatal(*bound, c.Pending())
	}
}

func TestDomesticSuffixesNeedLabelBoundaries(t *testing.T) {
	c, _, _ := correlator()
	c.Suffixes = map[string]bool{"cn": true, "douyin.com": true}
	for name, want := range map[string]bool{"douyin.com": true, "v.douyin.com.": true, "WWW.DOUYIN.COM": true,
		"notdouyin.com": false, "douyin.com.attacker.test": false, "example.cn": true, "cn.example": false} {
		if c.Domestic(name) != want {
			t.Error(name, !want)
		}
	}
}

type recorder struct {
	calls  [][]string
	routes []string // successive "route get" outputs
}

func (r *recorder) command(_ time.Duration, name string, args ...string) (string, string, int, error) {
	r.calls = append(r.calls, append([]string{name}, args...))
	if len(args) > 1 && args[1] == "get" && len(r.routes) > 0 {
		out := r.routes[0]
		r.routes = r.routes[1:]
		return out, "", 0, nil
	}
	return "", "", 0, nil
}

func router(t *testing.T, rec *recorder) *Router {
	return &Router{Policy: policy.New("../../../config/china_ip_list.txt", "../../../config/domestic_extra_routes.txt"),
		Command: rec.command, Log: NewLogger(filepath.Join(t.TempDir(), "agent.log")), Gateway: "192.168.1.1", Interface: "en0"}
}

const wired = "gateway: 192.168.1.1\ninterface: en0\n"
const wifi = "gateway: 172.20.10.1\ninterface: en1\n"

func TestHostileDNSAndAliasDoNotTouchRoutes(t *testing.T) {
	rec := &recorder{}
	r := router(t, rec)
	c := NewCorrelator(map[string]bool{"cn": true}, r.Bind)
	c.ProcessLine("dnsmasq[1]: 7 client query[A] evil.cn from client")
	c.ProcessLine("dnsmasq[1]: 7 client reply evil.cn is 8.8.8.8")
	c.ProcessLine("dnsmasq[1]: 7 client reply alias.example is 1.1.1.1")
	if len(rec.calls) != 0 {
		t.Fatal(rec.calls)
	}
}

func TestEventSinkEnforcesPolicyBeforeRouteLookup(t *testing.T) {
	for _, ip := range []string{"8.8.8.8", "127.0.0.1", "999.1.1.1"} {
		rec := &recorder{}
		router(t, rec).Bind("evil.cn", ip)
		if len(rec.calls) != 0 {
			t.Fatal(ip, rec.calls)
		}
	}
}

func TestLegitimateBindStillUsesIfp(t *testing.T) {
	rec := &recorder{routes: []string{wifi, wired}}
	router(t, rec).Bind("good.cn", "223.5.5.5")
	want := []string{"/sbin/route", "-n", "add", "-host", "223.5.5.5", "192.168.1.1", "-ifp", "en0"}
	for _, call := range rec.calls {
		if reflect.DeepEqual(call, want) {
			return
		}
	}
	t.Fatal(rec.calls)
}

func TestDeniedAnswerDoesNotBlockLaterDomesticAnswer(t *testing.T) {
	rec := &recorder{routes: []string{wired}}
	r := router(t, rec)
	c := NewCorrelator(map[string]bool{"cn": true}, r.Bind)
	c.ProcessLine("dnsmasq[1]: 7 client query[A] good.cn from client")
	c.ProcessLine("dnsmasq[1]: 7 client reply good.cn is 8.8.8.8")
	if len(rec.calls) != 0 || !reflect.DeepEqual(c.Pending(), []string{"1/7/client"}) {
		t.Fatal(rec.calls, c.Pending())
	}
	c.ProcessLine("dnsmasq[1]: 7 client reply good.cn is 223.5.5.5")
	if !reflect.DeepEqual(rec.calls, [][]string{{"/sbin/route", "-n", "get", "223.5.5.5"}}) {
		t.Fatal(rec.calls)
	}
}

func TestBindLogsFailedRouteChange(t *testing.T) {
	rec := &recorder{routes: []string{wifi, wifi}}
	r := router(t, rec)
	r.Bind("good.cn", "223.5.5.5")
	r.Log.Close()
	data, _ := os.ReadFile(r.Log.path)
	if !strings.Contains(string(data), " ERROR route bind failed domain=good.cn ip=223.5.5.5 exit=0 error=") {
		t.Fatalf("%q", data)
	}
}

func TestEventLogFollowsNewFileAfterExternalRotation(t *testing.T) {
	dir := t.TempDir()
	current, archive := filepath.Join(dir, "event.log"), filepath.Join(dir, "event.log.0")
	log := NewLogger(current)
	defer log.Close()
	log.Info("before rotation")
	os.Rename(current, archive)
	os.WriteFile(current, nil, 0644)
	log.Info("after rotation")
	old, _ := os.ReadFile(archive)
	fresh, _ := os.ReadFile(current)
	if !strings.Contains(string(old), "before rotation") || strings.Contains(string(old), "after rotation") ||
		!strings.Contains(string(fresh), "INFO after rotation") {
		t.Fatalf("archive %q current %q", old, fresh)
	}
	if info, _ := os.Stat(current); info.Mode().Perm() != 0644 {
		t.Fatal(info.Mode())
	}
}

func follower(t *testing.T) (*Follower, *[]binding, string, string) {
	t.Helper()
	dir := t.TempDir()
	queryLog, config := filepath.Join(dir, "query.log"), filepath.Join(dir, "dnsmasq.conf")
	os.WriteFile(config, []byte("server=/douyin.com/223.5.5.5\nno-resolv\n"), 0644)
	os.WriteFile(queryLog, []byte("dnsmasq[1]: 1 c query[A] old.cn from c\ndnsmasq[1]: 1 c reply old.cn is 223.5.5.5\n"), 0644)
	var bound []binding
	f := &Follower{LogPath: queryLog, ConfigPath: config, MaxBytes: 1 << 20,
		Correlator: NewCorrelator(nil, func(d, ip string) { bound = append(bound, binding{d, ip}) }),
		Log:        NewLogger(filepath.Join(dir, "agent.log")), Sleep: func(time.Duration) {}}
	t.Cleanup(func() { f.closeLog(); f.Log.Close() })
	return f, &bound, queryLog, config
}

func appendLine(t *testing.T, path, text string) {
	t.Helper()
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0)
	if err != nil {
		t.Fatal(err)
	}
	file.WriteString(text)
	file.Close()
}

func drain(f *Follower) {
	for i := 0; i < 20; i++ {
		f.Step()
	}
}

func TestFollowerStartsAtEndAndHandlesRotationAndPartialLines(t *testing.T) {
	f, bound, queryLog, config := follower(t)
	suffixes, _ := LoadSuffixes(config)
	info, _ := os.Stat(config)
	f.Correlator.Suffixes, f.configTime = suffixes, info.ModTime()
	drain(f)
	if len(*bound) != 0 {
		t.Fatal("history before startup was replayed", *bound)
	}
	appendLine(t, queryLog, "dnsmasq[1]: 2 c query[A] v.douyin.com from c\ndnsmasq[1]: 2 c reply cdn.example is 1.2.3.")
	drain(f)
	if len(*bound) != 0 {
		t.Fatal("partial line processed", *bound)
	}
	appendLine(t, queryLog, "4\n")
	drain(f)
	if !reflect.DeepEqual(*bound, []binding{{"v.douyin.com", "1.2.3.4"}}) {
		t.Fatal(*bound)
	}
	os.Rename(queryLog, queryLog+".1")
	os.WriteFile(queryLog, []byte("dnsmasq[1]: 3 c reply new.cn is 223.5.5.6\n"), 0644)
	drain(f)
	appendLine(t, queryLog, "dnsmasq[1]: 4 c reply after.cn is 223.5.5.7\n")
	drain(f)
	if got := (*bound)[1:]; !reflect.DeepEqual(got, []binding{{"after.cn", "223.5.5.7"}}) {
		t.Fatal("rotation should reopen at the end of the new file", got)
	}
}

func TestFollowerCompactsAndReloadsConfiguration(t *testing.T) {
	f, bound, queryLog, config := follower(t)
	f.MaxBytes = 64
	suffixes, _ := LoadSuffixes(config)
	info, _ := os.Stat(config)
	f.Correlator.Suffixes, f.configTime = suffixes, info.ModTime()
	drain(f)
	if info, _ := os.Stat(queryLog); info.Size() != 0 {
		t.Fatal("query log read past the limit was not compacted", info.Size())
	}
	appendLine(t, queryLog, "dnsmasq[1]: 5 c reply example.org is 223.5.5.8\n")
	drain(f)
	if len(*bound) != 0 {
		t.Fatal("non-domestic name bound", *bound)
	}
	os.WriteFile(config, []byte("server=/example.org/223.5.5.5\n"), 0644)
	os.Chtimes(config, time.Time{}, time.Now().Add(time.Minute))
	drain(f)
	appendLine(t, queryLog, "dnsmasq[1]: 6 c reply example.org is 223.5.5.8\n")
	drain(f)
	if !reflect.DeepEqual(*bound, []binding{{"example.org", "223.5.5.8"}}) {
		t.Fatal(*bound)
	}
	f.Log.Close()
	data, _ := os.ReadFile(f.Log.path)
	if !strings.Contains(string(data), "INFO query log compacted limit_bytes=64") || !strings.Contains(string(data), "INFO reloaded suffixes=2") {
		t.Fatalf("%q", data)
	}
}

func TestRunFailsWhenConfigurationIsMissingAtStartup(t *testing.T) {
	f, _, _, config := follower(t)
	os.Remove(config)
	if err := f.Run(context.Background()); err == nil {
		t.Fatal("missing configuration accepted at startup")
	}
}
