package dnsservice

import (
	"context"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func TestDNSUDPAndTCPServeAndCancel(t *testing.T) {
	udp, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	tcp, err := net.Listen("tcp4", udp.LocalAddr().String())
	if err != nil {
		udp.Close()
		t.Fatal(err)
	}
	r := resolverFixture(t)
	r.Exchange = func(_ context.Context, q *dns.Msg, _ netip.Addr, _, _ string) (*dns.Msg, error) {
		m := responseFor(q, 0)
		for i := 0; i < 20; i++ {
			m.Answer = append(m.Answer, &dns.TXT{Hdr: dns.RR_Header{Name: q.Question[0].Name, Rrtype: dns.TypeTXT, Class: 1, Ttl: 60}, Txt: []string{strings.Repeat("x", 100)}})
		}
		return m, nil
	}
	s := &Server{Resolver: r, Allowed: []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")}}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- s.Serve(ctx, &Listeners{UDP: []net.PacketConn{udp}, TCP: []net.Listener{tcp}}) }()
	defer func() {
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Error(err)
			}
		case <-time.After(10 * time.Second):
			t.Error("DNS process did not stop")
		}
	}()
	q := question("text.example.cn.", dns.TypeTXT)
	for _, network := range []string{"udp4", "tcp4"} {
		client := &dns.Client{Net: network, Timeout: 2 * time.Second}
		m, _, err := client.Exchange(q, udp.LocalAddr().String())
		if err != nil {
			t.Fatal(err)
		}
		if m.Truncated != (network == "udp4") {
			t.Fatal(network, m)
		}
		if network == "tcp4" && len(m.Answer) != 20 {
			t.Fatal(len(m.Answer))
		}
	}
}

func TestEscapedLabelsCannotImpersonateDomesticSuffix(t *testing.T) {
	r := resolverFixture(t)
	_, domestic := r.Config.Select(`evil\.cn.`)
	if domestic {
		t.Fatal("escaped label matched cn suffix")
	}
	_, domestic = r.Config.Select(`label\.part.example.cn.`)
	if !domestic {
		t.Fatal("real domestic suffix missed")
	}
}

func TestLoopDetectionDisablesOnlyTheAffectedUpstream(t *testing.T) {
	r := resolverFixture(t)
	key := upstream{r.Config.Servers[0], r.WiFi}
	r.loops["token.test."] = key
	if _, _, err := r.Resolve(context.Background(), question("token.test.", dns.TypeTXT)); err == nil {
		t.Fatal("loop not detected")
	}
	r.Exchange = func(_ context.Context, q *dns.Msg, _ netip.Addr, iface, _ string) (*dns.Msg, error) {
		if iface == r.WiFi {
			t.Fatal("blocked upstream called")
		}
		return answer(q, 60), nil
	}
	if _, _, err := r.Resolve(context.Background(), question("foreign.test.", dns.TypeA)); err == nil {
		t.Fatal("blocked group succeeded")
	}
	if _, _, err := r.Resolve(context.Background(), question("example.cn.", dns.TypeA)); err != nil {
		t.Fatal(err)
	}
}

func TestLocalClientACLAndMalformedHeaders(t *testing.T) {
	s := Server{Allowed: []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8"), netip.MustParsePrefix("192.0.2.0/24")}}
	for _, tc := range []struct {
		ip      string
		allowed bool
	}{{"127.0.0.1", true}, {"192.0.2.1", true}, {"198.51.100.1", false}, {"8.8.8.8", false}} {
		if s.allowed(&net.UDPAddr{IP: net.ParseIP(tc.ip), Port: 123}) != tc.allowed {
			t.Fatal(tc)
		}
	}
	for _, h := range []dns.Header{{}, {Qdcount: 2}, {Qdcount: 1, Ancount: 1}, {Qdcount: 1, Nscount: 1}, {Qdcount: 1, Arcount: 2}, {Qdcount: 1, Bits: 0x8000}} {
		if acceptMessage(h) == dns.MsgAccept {
			t.Fatal("bad DNS header accepted", h)
		}
	}
}
