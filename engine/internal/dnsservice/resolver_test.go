package dnsservice

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func question(name string, kind uint16) *dns.Msg {
	q := new(dns.Msg)
	q.SetQuestion(name, kind)
	return q
}

func TestDNSPreservesCommonAndUnknownResourceRecords(t *testing.T) {
	for _, record := range []string{
		"example.cn. 120 IN MX 10 mail.example.cn.",
		"example.cn. 120 IN TXT \"site verification\"",
		"example.cn. 120 IN SRV 1 2 443 service.example.cn.",
		"example.cn. 120 IN HTTPS 1 . alpn=h2 ipv4hint=223.5.5.5",
		"example.cn. 120 IN CAA 0 issue \"example.net\"",
		"example.cn. 120 IN TYPE65280 \\# 4 DEADBEEF",
	} {
		rr, err := dns.NewRR(record)
		if err != nil {
			t.Fatal(err)
		}
		q := question("example.cn.", rr.Header().Rrtype)
		m := responseFor(q, 0)
		m.Answer = []dns.RR{rr}
		got, err := cleanResponse(q, m, 60)
		if err != nil {
			t.Fatal(err)
		}
		want := dns.Copy(rr)
		want.Header().Ttl = 60
		if got.Answer[0].String() != want.String() {
			t.Fatal(got)
		}
		b, err := got.Pack()
		if err != nil {
			t.Fatal(err)
		}
		var decoded dns.Msg
		if err := decoded.Unpack(b); err != nil {
			t.Fatal(decoded, err)
		}
		again, err := decoded.Pack()
		if err != nil || !bytes.Equal(b, again) {
			t.Fatal("resource data changed", err)
		}
	}
}

func TestCacheBoundsAndEDNSIsolation(t *testing.T) {
	c := newCache(2)
	now := time.Now()
	q := question("example.cn.", dns.TypeA)
	for i := 0; i < 3; i++ {
		c.put(fmt.Sprint(i), answer(q, 60), 60, now)
	}
	if c.get("0", q, now) != nil || c.order.Len() != 2 || c.bytes > cacheByteLimit {
		t.Fatal("cache did not evict")
	}
	if c.get("1", q, now) == nil {
		t.Fatal("cache entry missing")
	}
	c.put("3", answer(q, 60), 60, now)
	if c.get("2", q, now) != nil {
		t.Fatal("cache did not honor recent use")
	}
	plain := queryKey(q)
	q.SetEdns0(1232, false)
	if queryKey(q) == plain {
		t.Fatal("OPT could be sent to a client without EDNS")
	}
	m := answer(q, 60)
	m.SetEdns0(1232, false)
	m.IsEdns0().Option = []dns.EDNS0{&dns.EDNS0_COOKIE{Code: dns.EDNS0COOKIE, Cookie: "0123456789abcdef"}}
	if lifetime(m, 60) != 0 {
		t.Fatal("client-specific upstream options cached")
	}
	for _, name := range []string{"10.in-addr.arpa.", "20.172.in-addr.arpa.", "168.192.in-addr.arpa.", "c.f.ip6.arpa.", "8.e.f.ip6.arpa."} {
		if !privateReverse(name) {
			t.Fatal("private reverse zone leaked", name)
		}
	}
	if privateReverse("8.8.8.8.in-addr.arpa.") {
		t.Fatal("public reverse rejected")
	}
}

func TestQueryLogRejectsLinksAndWorldWritableFiles(t *testing.T) {
	path := filepath.Join(t.TempDir(), "log")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	q := question("example.cn.", dns.TypeA)
	l := &QueryLogger{Path: path}
	if err := os.Chmod(path, 0o666); err != nil {
		t.Fatal(err)
	}
	if err := l.Write(q, answer(q, 60), "127.0.0.1:123", false, nil); err == nil {
		t.Fatal("unsafe log accepted")
	}
	os.Chmod(path, 0o600)
	link := path + ".link"
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	l.Path = link
	if err := l.Write(q, answer(q, 60), "127.0.0.1:123", false, nil); err == nil {
		t.Fatal("symlink accepted")
	}
}

func FuzzDNSPolicyAndResponseValidation(f *testing.F) {
	q := question("example.cn.", dns.TypeA)
	b, _ := answer(q, 60).Pack()
	f.Add(b)
	f.Add([]byte(policyFixture))
	f.Fuzz(func(t *testing.T, b []byte) {
		if len(b) > 65535 {
			return
		}
		if p, err := Parse(b); err == nil {
			if _, err := Parse(p.Encode()); err != nil {
				t.Fatal("policy roundtrip", err)
			}
		}
		var m dns.Msg
		if err := m.Unpack(b); err != nil {
			return
		}
		if clean, err := cleanResponse(q, &m, 60); err == nil {
			if _, err := clean.Pack(); err != nil {
				t.Fatal(err)
			}
			AnswerAddresses(q, clean)
		}
	})
}
func answer(q *dns.Msg, ttl uint32) *dns.Msg {
	m := responseFor(q, dns.RcodeSuccess)
	m.Answer = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: q.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: ttl}, A: net.ParseIP("223.5.5.5")}}
	return m
}
func resolverFixture(t *testing.T) *Resolver {
	t.Helper()
	c, err := Parse([]byte(policyFixture))
	if err != nil {
		t.Fatal(err)
	}
	r, err := NewResolver(c, "wired-test", "wifi-test", []byte("127.0.0.1 localhost\n192.0.2.3 private.local\n::1 localhost\n"))
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestResolverCacheTTLAndClientIdentity(t *testing.T) {
	r := resolverFixture(t)
	now := time.Now()
	r.Now = func() time.Time { return now }
	calls := 0
	r.Exchange = func(_ context.Context, q *dns.Msg, _ netip.Addr, iface, network string) (*dns.Msg, error) {
		calls++
		if iface != "wired-test" || network != "udp4" {
			t.Fatal(iface, network)
		}
		return answer(q, 300), nil
	}
	q := question("www.example.cn.", dns.TypeA)
	m, cached, err := r.Resolve(context.Background(), q)
	if err != nil || cached || m.Answer[0].Header().Ttl != 60 {
		t.Fatal(m, cached, err)
	}
	now = now.Add(10 * time.Second)
	q.Id++
	q.Question[0].Name = "WWW.EXAMPLE.CN."
	m, cached, err = r.Resolve(context.Background(), q)
	if err != nil || !cached || m.Id != q.Id || m.Question[0] != q.Question[0] || m.Answer[0].Header().Ttl != 50 || calls != 1 {
		t.Fatal(m, cached, calls, err)
	}
	m.Answer[0].Header().Ttl = 999
	now = now.Add(51 * time.Second)
	if _, hit, err := r.Resolve(context.Background(), q); err != nil || hit || calls != 2 {
		t.Fatal(hit, calls, err)
	}
}

func TestResolverKeepsRetriesWithinTheChosenInterface(t *testing.T) {
	r := resolverFixture(t)
	r.Config.Servers = append(r.Config.Servers, netip.MustParseAddr("8.8.8.8"))
	var calls []string
	r.Exchange = func(_ context.Context, _ *dns.Msg, _ netip.Addr, iface, network string) (*dns.Msg, error) {
		calls = append(calls, iface+"/"+network)
		return nil, errors.New("unavailable")
	}
	if _, _, err := r.Resolve(context.Background(), question("github.com.", dns.TypeA)); err == nil {
		t.Fatal("foreign failure hidden")
	}
	if len(calls) != 2 || strings.Join(calls, ",") != "wifi-test/udp4,wifi-test/udp4" {
		t.Fatal(calls)
	}
	r.Exchange = func(_ context.Context, q *dns.Msg, _ netip.Addr, iface, network string) (*dns.Msg, error) {
		if iface != "wired-test" {
			t.Fatal("foreign failure broke domestic lookup")
		}
		return answer(q, 60), nil
	}
	if _, _, err := r.Resolve(context.Background(), question("www.example.cn.", dns.TypeA)); err != nil {
		t.Fatal(err)
	}
}

func TestResolverRetriesTruncatedUDPOverTCP(t *testing.T) {
	r := resolverFixture(t)
	var networks []string
	r.Exchange = func(_ context.Context, q *dns.Msg, _ netip.Addr, _, network string) (*dns.Msg, error) {
		networks = append(networks, network)
		m := answer(q, 60)
		m.Truncated = network == "udp4"
		return m, nil
	}
	m, _, err := r.Resolve(context.Background(), question("example.cn.", dns.TypeA))
	if err != nil || m.Truncated || strings.Join(networks, ",") != "udp4,tcp4" {
		t.Fatal(m, networks, err)
	}
}

func TestResolverReusesTheSuccessfulUpstreamWithoutChangingEgress(t *testing.T) {
	r := resolverFixture(t)
	good := netip.MustParseAddr("8.8.8.8")
	r.Config.Servers = append(r.Config.Servers, good)
	var seen []netip.Addr
	r.Exchange = func(_ context.Context, q *dns.Msg, ip netip.Addr, iface, _ string) (*dns.Msg, error) {
		seen = append(seen, ip)
		if iface != r.WiFi {
			t.Fatal("changed egress", iface)
		}
		if ip != good {
			return nil, errors.New("upstream unavailable")
		}
		return answer(q, 60), nil
	}
	for _, name := range []string{"first.test.", "second.test."} {
		if _, _, err := r.Resolve(context.Background(), question(name, dns.TypeA)); err != nil {
			t.Fatal(err)
		}
	}
	if len(seen) != 3 || seen[1] != good || seen[2] != good {
		t.Fatal(seen)
	}
}

func TestDNSResponseValidationFilteringAndHints(t *testing.T) {
	q := question("example.cn.", dns.TypeA)
	for _, kind := range []string{"id", "question", "private", "hint"} {
		m := answer(q, 60)
		switch kind {
		case "id":
			m.Id++
		case "question":
			m.Question[0].Name = "other.test."
		case "private":
			m.Answer[0].(*dns.A).A = net.ParseIP("127.0.0.1")
		case "hint":
			m.Answer = []dns.RR{&dns.HTTPS{SVCB: dns.SVCB{Hdr: dns.RR_Header{Name: q.Question[0].Name, Rrtype: dns.TypeHTTPS, Class: 1, Ttl: 60}, Target: ".", Value: []dns.SVCBKeyValue{&dns.SVCBIPv4Hint{Hint: []net.IP{net.ParseIP("192.168.0.1")}}}}}}
		}
		if _, err := cleanResponse(q, m, 60); err == nil {
			t.Fatal("invalid DNS response accepted", kind)
		}
	}
	m := answer(q, 300)
	m.AuthenticatedData = true
	m.Answer = append(m.Answer, &dns.AAAA{Hdr: dns.RR_Header{Name: q.Question[0].Name, Rrtype: dns.TypeAAAA, Class: 1, Ttl: 300}, AAAA: net.ParseIP("2001:4860::8888")})
	got, err := cleanResponse(q, m, 60)
	if err != nil || got.AuthenticatedData || len(got.Answer) != 1 || got.Answer[0].Header().Ttl != 60 {
		t.Fatal(got, err)
	}
	if len(m.Answer) != 2 {
		t.Fatal("upstream message mutated")
	}
}

func TestNegativeSOALifetimeAndUncacheableErrors(t *testing.T) {
	r := resolverFixture(t)
	now := time.Now()
	r.Now = func() time.Time { return now }
	calls := 0
	r.Exchange = func(_ context.Context, q *dns.Msg, _ netip.Addr, _, _ string) (*dns.Msg, error) {
		calls++
		m := responseFor(q, dns.RcodeNameError)
		m.Ns = []dns.RR{&dns.SOA{Hdr: dns.RR_Header{Name: "example.cn.", Rrtype: dns.TypeSOA, Class: 1, Ttl: 120}, Ns: "ns.example.cn.", Mbox: "hostmaster.example.cn.", Minttl: 10}}
		return m, nil
	}
	q := question("missing.example.cn.", dns.TypeA)
	m, _, err := r.Resolve(context.Background(), q)
	if err != nil || m.Ns[0].Header().Ttl != 10 {
		t.Fatal(m, err)
	}
	now = now.Add(4 * time.Second)
	m, hit, err := r.Resolve(context.Background(), q)
	if err != nil || !hit || m.Ns[0].Header().Ttl != 6 {
		t.Fatal(m, hit, err)
	}
	now = now.Add(7 * time.Second)
	r.Resolve(context.Background(), q)
	if calls != 2 {
		t.Fatal(calls)
	}
	r.Exchange = func(_ context.Context, q *dns.Msg, _ netip.Addr, _, _ string) (*dns.Msg, error) {
		calls++
		return responseFor(q, dns.RcodeServerFailure), nil
	}
	for i := 0; i < 2; i++ {
		if _, _, err := r.Resolve(context.Background(), question("error.example.cn.", dns.TypeA)); err == nil {
			t.Fatal("server failure accepted")
		}
	}
	if calls != 4 {
		t.Fatal("error was cached", calls)
	}
}

func TestHostsPlainNamesAndPrivatePTRStayLocal(t *testing.T) {
	r := resolverFixture(t)
	r.Exchange = func(context.Context, *dns.Msg, netip.Addr, string, string) (*dns.Msg, error) {
		t.Fatal("local lookup escaped")
		return nil, nil
	}
	for _, q := range []*dns.Msg{question("localhost.", dns.TypeA), question("localhost.", dns.TypeAAAA), question("private.local.", dns.TypeA), question("printer.", dns.TypeA), question("1.1.168.192.in-addr.arpa.", dns.TypePTR)} {
		if m, _, err := r.Resolve(context.Background(), q); err != nil || m == nil {
			t.Fatal(m, err)
		}
	}
}

func TestConcurrentRequestsShareOnlyCacheableWork(t *testing.T) {
	r := resolverFixture(t)
	var calls atomic.Int32
	entered := make(chan struct{})
	release := make(chan struct{})
	r.Exchange = func(ctx context.Context, q *dns.Msg, _ netip.Addr, _, _ string) (*dns.Msg, error) {
		if calls.Add(1) == 1 {
			close(entered)
		}
		select {
		case <-release:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
		return answer(q, 60), nil
	}
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			q := question("example.cn.", dns.TypeA)
			q.Id = uint16(id)
			m, _, err := r.Resolve(context.Background(), q)
			if err != nil || m.Id != q.Id {
				t.Error(m, err)
			}
		}(i)
	}
	<-entered
	time.Sleep(20 * time.Millisecond)
	close(release)
	wg.Wait()
	if calls.Load() != 1 {
		t.Fatal(calls.Load())
	}
	q := question("example.cn.", dns.TypeA)
	q.SetEdns0(1232, false)
	q.IsEdns0().Option = []dns.EDNS0{&dns.EDNS0_SUBNET{Code: dns.EDNS0SUBNET, Family: 1, SourceNetmask: 24, Address: net.ParseIP("192.0.2.0")}}
	if queryKey(q) != "" {
		t.Fatal("client-specific DNS options shared a cache key")
	}
}

func TestQueryLogBoundsGrowthAndRestrictsCNAMEAttribution(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "query.log")
	os.WriteFile(path, nil, 0o600)
	q := question("example.cn.", dns.TypeA)
	m := responseFor(q, 0)
	m.Answer = []dns.RR{&dns.CNAME{Hdr: dns.RR_Header{Name: "example.cn.", Rrtype: dns.TypeCNAME, Class: 1, Ttl: 60}, Target: "cdn.test."}, &dns.A{Hdr: dns.RR_Header{Name: "cdn.test.", Rrtype: dns.TypeA, Class: 1, Ttl: 60}, A: net.ParseIP("223.5.5.5")}, &dns.A{Hdr: dns.RR_Header{Name: "unrelated.test.", Rrtype: dns.TypeA, Class: 1, Ttl: 60}, A: net.ParseIP("119.29.29.29")}}
	l := &QueryLogger{Path: path}
	if err := l.Write(q, m, "127.0.0.1:1234", false, nil); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(path)
	if !strings.Contains(string(b), "223.5.5.5") || strings.Contains(string(b), "119.29.29.29") {
		t.Fatal(string(b))
	}
	if err := os.Truncate(path, QueryLogLimit); err != nil {
		t.Fatal(err)
	}
	if err := l.Write(q, m, "127.0.0.1:1234", false, nil); err != nil {
		t.Fatal(err)
	}
	info, _ := os.Stat(path)
	if info.Size() != QueryLogLimit {
		t.Fatal("query log grew without its consumer")
	}
}
