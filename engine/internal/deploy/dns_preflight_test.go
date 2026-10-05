package deploy

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
	"network-owned-engine/internal/dnsservice"
	"network-owned-engine/internal/service"
)

func TestNativePreflightCanonicalizesPathsAndRemovesItsJob(t *testing.T) {
	d := maintenanceFixture(t)
	parent := d.BackupParent
	alias := filepath.Join(t.TempDir(), "db-alias")
	if err := os.Symlink(parent, alias); err != nil {
		t.Fatal(err)
	}
	d.BackupParent = alias
	c := service.Config{Routes: service.ProductionRoutes()}
	c.Routes.DNS = "192.0.2.10"
	c.Routes.WiredInterface, c.Routes.WiFiInterface = "wired-test", "wifi-test"
	c.Routes.DNSConfig = filepath.Join(d.Root, "dns.conf")
	p := dnsservice.Config{Port: 53, Listen: []netip.Addr{netip.MustParseAddr("127.0.0.1"), netip.MustParseAddr(c.Routes.DNS)}, Servers: []netip.Addr{netip.MustParseAddr("1.1.1.1")}, Domains: map[string][]netip.Addr{"cn": {netip.MustParseAddr("223.5.5.5")}}, QueryLog: filepath.Join(d.Root, "unused.log"), CacheEntries: 10, MaxTTL: 60, CacheTTL: 60}
	writeTestFile(t, c.Routes.DNSConfig, string(p.Encode()))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	started, loaded := false, false
	var jobPath, label string
	t.Cleanup(func() {
		cancel()
		if started {
			select {
			case err := <-done:
				if err != nil {
					t.Error(err)
				}
			case <-time.After(10 * time.Second):
				t.Error("DNS fixture did not exit")
			}
		}
	})
	d.ProcessAlive = func(int) (bool, error) { return false, nil }
	d.Run = func(args ...string) (string, error) {
		if args[0] == "/bin/ps" {
			return "nobody\n", nil
		}
		if args[0] != "/bin/launchctl" {
			t.Fatal(args)
		}
		switch args[1] {
		case "bootstrap":
			jobPath = args[3]
			label = strings.TrimSuffix(filepath.Base(jobPath), ".plist")
			policy, err := dnsservice.Load(filepath.Join(filepath.Dir(jobPath), "policy.conf"))
			if err != nil {
				return "", err
			}
			address := net.JoinHostPort("127.0.0.1", fmt.Sprint(policy.Port))
			udp, err := net.ListenPacket("udp4", address)
			if err != nil {
				return "", err
			}
			tcp, err := net.Listen("tcp4", address)
			if err != nil {
				udp.Close()
				return "", err
			}
			r, err := dnsservice.NewResolver(policy, "wired-test", "wifi-test", []byte("127.0.0.1 localhost\n"))
			if err != nil {
				udp.Close()
				tcp.Close()
				return "", err
			}
			r.Exchange = func(_ context.Context, q *dns.Msg, _ netip.Addr, _, _ string) (*dns.Msg, error) {
				m := new(dns.Msg)
				m.SetReply(q)
				if strings.HasSuffix(q.Question[0].Name, ".invalid.") {
					m.Rcode = dns.RcodeNameError
				} else if q.Question[0].Qtype == dns.TypeA {
					m.Answer = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: q.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60}, A: net.ParseIP("223.5.5.5")}}
				}
				return m, nil
			}
			s := &dnsservice.Server{Resolver: r, Allowed: []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")}}
			started, loaded = true, true
			go func() {
				done <- s.Serve(ctx, &dnsservice.Listeners{UDP: []net.PacketConn{udp}, TCP: []net.Listener{tcp}})
			}()
			return "", nil
		case "print":
			if !loaded {
				return "", &CommandError{Code: 113}
			}
			canonical, err := filepath.EvalSymlinks(jobPath)
			if err != nil {
				return "", err
			}
			return fmt.Sprintf("path = %s\nprogram = %s\nstate = running\npid = 123\n", canonical, filepath.Join(d.Root, EngineName)), nil
		case "bootout":
			if args[2] != "system/"+label {
				t.Fatal("unrelated job stopped", args)
			}
			loaded = false
			cancel()
			return "", nil
		}
		t.Fatal(args)
		return "", nil
	}
	if err := d.nativePreflight(c); err != nil {
		t.Fatal(err)
	}
	if loaded {
		t.Fatal("temporary job still loaded")
	}
	if entries, err := os.ReadDir(parent); err != nil || len(entries) != 0 {
		t.Fatal("temporary files remain", entries, err)
	}
}
