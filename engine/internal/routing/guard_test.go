package routing

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

type kernel struct {
	defaultRoute Route
	wifi         bool
	blocks       [2]bool
	hosts        map[string]Route
	fault        string
	calls        [][]string
}

func fixture(t *testing.T) (*Guard, *kernel) {
	t.Helper()
	dir := t.TempDir()
	c := Config{DNS: "192.0.2.10", WiredIP: "192.0.2.10", WiredGateway: "192.0.2.1", WiFiGateway: "198.51.100.1", WiredInterface: "en0", WiFiInterface: "en1", WiredService: "Ethernet", WiFiService: "Wi-Fi",
		ChinaList: filepath.Join(dir, "china"), ExtraList: filepath.Join(dir, "extra"), DomainList: filepath.Join(dir, "domains"), DNSConfig: filepath.Join(dir, "dns.conf"), DNSBinary: filepath.Join(dir, "dns"), GuardLock: filepath.Join(dir, "guard.lock"), ChinaLock: filepath.Join(dir, "china.lock"), ForceRebuild: filepath.Join(dir, "force"), GuardLog: filepath.Join(dir, "guard.log")}
	for path, data := range map[string]string{c.ChinaList: "223.5.5.0/24\n119.29.29.0/24\n", c.ExtraList: "223.5.5.5/32\n", c.DomainList: "one.test\ntwo.test\n"} {
		if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	g := New(c)
	k := &kernel{defaultRoute: Route{Gateway: c.WiredGateway, Interface: c.WiredInterface}, hosts: map[string]Route{}}
	g.HasIPv4 = func(iface, expected string) bool {
		if iface == c.WiFiInterface {
			return k.wifi
		}
		return iface == c.WiredInterface
	}
	g.Log = func(string, ...any) {}
	g.Sleep = func(ctx context.Context, _ time.Duration) error { return ctx.Err() }
	g.Lookup = func(context.Context, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("223.5.5.5")}, nil
	}
	g.Run = func(args ...string) (string, error) {
		k.calls = append(k.calls, append([]string(nil), args...))
		if args[0] == "/usr/sbin/ipconfig" {
			return "router (ip_mult): {198.51.100.1}\n", nil
		}
		if args[0] != "/sbin/route" {
			t.Fatalf("unexpected command %v", args)
		}
		if len(args) < 4 || args[1] != "-n" {
			t.Fatal(args)
		}
		op, target := args[2], args[3]
		if op == "get" {
			r := k.defaultRoute
			switch target {
			case c.WiFiGateway:
				if k.wifi {
					r = Route{Gateway: c.WiFiGateway, Interface: c.WiFiInterface}
				} else {
					return "", errors.New("down")
				}
			case c.WiredGateway:
				r = Route{Gateway: c.WiredGateway, Interface: c.WiredInterface}
			default:
				if host, ok := k.hosts[target]; ok {
					r = host
				}
				for i, sample := range blockSamples {
					if target == sample && k.blocks[i] {
						r = Route{Gateway: "127.0.0.1", Interface: "lo0", Reject: true}
					}
				}
			}
			flags := "UP,GATEWAY"
			if r.Reject {
				flags += ",REJECT"
			}
			return fmt.Sprintf("gateway: %s\ninterface: %s\nflags: <%s>\n", r.Gateway, r.Interface, flags), nil
		}
		if target == "default" {
			if op == "delete" {
				return "", nil
			}
			if k.fault == "repair" {
				return "", errors.New("repair failed")
			}
			k.defaultRoute = Route{Gateway: args[4], Interface: args[len(args)-1]}
			return "", nil
		}
		if target == "-net" {
			for i, network := range blockNetworks {
				if args[4] == network {
					if k.fault == "block" && op == "add" || k.fault == "unblock" && op == "delete" {
						return "", errors.New("block transition failed")
					}
					if op == "add" && !slices.Equal(args, []string{"/sbin/route", "-n", "add", "-net", network, "127.0.0.1", "-reject"}) {
						t.Fatal("reject route is not a gateway route", args)
					}
					k.blocks[i] = op == "add"
					return "", nil
				}
			}
		}
		if target == "-host" && op == "add" {
			k.hosts[args[4]] = Route{Gateway: args[5], Interface: args[len(args)-1]}
		}
		return "", nil
	}
	return g, k
}

func actions(k *kernel) []string {
	var out []string
	for _, args := range k.calls {
		if args[0] != "/sbin/route" || args[2] == "get" {
			continue
		}
		switch args[3] {
		case "default":
			out = append(out, "default:"+args[2])
		case "-net":
			out = append(out, "block:"+args[2])
		}
	}
	return out
}

func TestForeignTransitionOrder(t *testing.T) {
	for _, scenario := range []string{"down", "block", "recover", "repair", "unblock", "already-restored"} {
		t.Run(scenario, func(t *testing.T) {
			g, k := fixture(t)
			k.wifi = scenario != "down" && scenario != "block"
			if scenario == "down" {
				k.defaultRoute = Route{Gateway: g.WiFiGateway, Interface: g.WiFiInterface}
			}
			if scenario == "block" || scenario == "repair" || scenario == "unblock" {
				k.fault = scenario
			}
			if scenario == "already-restored" {
				k.defaultRoute = Route{Gateway: g.WiFiGateway, Interface: g.WiFiInterface}
				k.blocks = [2]bool{true, true}
			}
			online, err := g.Foreign()
			trace := actions(k)
			switch scenario {
			case "down":
				if err != nil || online || !slices.Equal(trace, []string{"block:add", "block:add", "default:change"}) || !g.blocksActive() {
					t.Fatal(online, err, trace)
				}
			case "block":
				if err == nil || !slices.Equal(trace, []string{"block:add", "block:add"}) {
					t.Fatal(err, trace)
				}
			case "recover":
				if err != nil || !online || !slices.Equal(trace, []string{"block:add", "block:add", "default:change", "block:delete", "block:delete"}) {
					t.Fatal(online, err, trace)
				}
			case "repair":
				if err == nil || !g.blocksActive() || slices.Contains(trace, "block:delete") {
					t.Fatal(err, trace)
				}
			case "unblock":
				if err == nil || !g.blocksActive() {
					t.Fatal(err, trace)
				}
			case "already-restored":
				if err != nil || !online || !slices.Equal(trace, []string{"block:delete", "block:delete"}) {
					t.Fatal(err, trace)
				}
			}
		})
	}
}

func TestDomainBindingUsesOneSnapshotAndPolicy(t *testing.T) {
	g, k := fixture(t)
	for _, ip := range []string{"8.8.8.8", "127.0.0.1", "999.1.1.1"} {
		if err := g.Bind("untrusted.test", ip); err != nil {
			t.Fatal(err)
		}
	}
	if len(k.calls) != 0 {
		t.Fatal("denied address reached a route command", k.calls)
	}
	if err := g.Bind("domestic.test", "223.5.5.5"); err != nil {
		t.Fatal(err)
	}
	if len(k.calls) != 1 {
		t.Fatal("already correct route was mutated", k.calls)
	}
	k.defaultRoute = Route{Gateway: g.WiFiGateway, Interface: g.WiFiInterface}
	k.calls = nil
	if err := g.Bind("domestic.test", "223.5.5.5"); err != nil {
		t.Fatal(err)
	}
	if !g.matches("223.5.5.5", g.WiredGateway, g.WiredInterface) {
		t.Fatal("route not verified")
	}
	for _, args := range k.calls {
		if slices.Contains(args, "add") && !slices.Contains(args, "-ifp") {
			t.Fatal("binding is scoped instead of ordinary", args)
		}
	}
}

func TestFailedDNSDoesNotStopLaterDomains(t *testing.T) {
	g, k := fixture(t)
	k.defaultRoute = Route{Gateway: g.WiFiGateway, Interface: g.WiFiInterface}
	var names []string
	g.Lookup = func(_ context.Context, name string) ([]netip.Addr, error) {
		names = append(names, name)
		if name == "one.test" {
			return nil, errors.New("DNS unavailable")
		}
		return []netip.Addr{netip.MustParseAddr("223.5.5.5")}, nil
	}
	if err := g.domains(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(names, []string{"one.test", "two.test"}) || !g.matches("223.5.5.5", g.WiredGateway, g.WiredInterface) {
		t.Fatal(names)
	}
}

func TestRebuildRejectsCorruptInputBeforeMutating(t *testing.T) {
	g, k := fixture(t)
	if err := os.WriteFile(g.ExtraList, []byte("223.5.5.5/32\nnot-a-prefix\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := g.Rebuild(context.Background()); err == nil {
		t.Fatal("invalid list accepted")
	}
	if len(k.calls) != 0 {
		t.Fatal("invalid list mutated routes", k.calls)
	}
}

func TestNativeGuardLockBlocksAnOverlappingRun(t *testing.T) {
	g, k := fixture(t)
	// File ownership and the cross-process POSIX behavior are tested by the
	// shared health lock tests; this checks that the routing entry acquires it.
	if err := os.Symlink(g.ChinaList, g.GuardLock); err != nil {
		t.Fatal(err)
	}
	if err := g.RunOnce(context.Background()); err == nil {
		t.Fatal("unsafe lock accepted")
	}
	if len(k.calls) != 0 {
		t.Fatal("network access before locking")
	}
}

func TestDNSRecoveryNeverImportsAnUnsafeBinary(t *testing.T) {
	for _, kind := range []string{"missing", "link", "directory", "writable"} {
		t.Run(kind, func(t *testing.T) {
			g, _ := fixture(t)
			switch kind {
			case "link":
				os.Symlink("/usr/bin/true", g.DNSBinary)
			case "directory":
				os.Mkdir(g.DNSBinary, 0o755)
			case "writable":
				os.WriteFile(g.DNSBinary, []byte("untrusted"), 0o777)
			}
			g.Run = func(...string) (string, error) { t.Fatal("unsafe DNS program executed"); return "", nil }
			if err := g.restartDNS(); err == nil {
				t.Fatal("unsafe DNS binary accepted")
			}
		})
	}
}

func TestExactRouteFieldsAndRejectFlags(t *testing.T) {
	r := ParseRoute("gateway: 192.0.2.100\ninterface: en01\nflags: <UP,GATEWAY,REJECT>\n")
	if r.Gateway == "192.0.2.1" || r.Interface == "en0" || !r.Reject {
		t.Fatal(r)
	}
	if ParseRoute("flags: <UP,GATEWAY>\n").Reject {
		t.Fatal("false reject flag")
	}
	if len(HealthTargets) != 5 || strings.Contains(strings.Join(HealthTargets, ","), " ") {
		t.Fatal(HealthTargets)
	}
}

func TestGuardReconcilesRecoveryAfterDomainScanWithoutFalseRebuild(t *testing.T) {
	g, k := fixture(t)
	for _, ip := range append(append([]string(nil), HealthTargets...), "163.181.253.200") {
		k.hosts[ip] = Route{Gateway: g.WiredGateway, Interface: g.WiredInterface}
	}
	base := g.Run
	g.Run = func(args ...string) (string, error) {
		switch args[0] {
		case "/usr/sbin/networksetup":
			return "", nil
		case "/usr/bin/dig":
			return ";; flags: qr ra; QUERY: 1", nil
		case "/bin/launchctl":
			t.Fatal("DNS lookup failure incorrectly requested a rebuild", args)
		}
		return base(args...)
	}
	g.Lookup = func(context.Context, string) ([]netip.Addr, error) {
		k.wifi = true
		k.defaultRoute = Route{Gateway: g.WiFiGateway, Interface: g.WiFiInterface}
		return nil, errors.New("DNS unavailable")
	}
	if err := g.RunOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if k.blocks != [2]bool{} {
		t.Fatal("recovered Wi-Fi remained blocked")
	}
	if _, err := os.Lstat(g.ForceRebuild); !os.IsNotExist(err) {
		t.Fatal("false rebuild marker", err)
	}
}

func TestRebuildRetainsHealthyStaticRoutes(t *testing.T) {
	g, k := fixture(t)
	if err := g.Rebuild(context.Background()); err != nil {
		t.Fatal(err)
	}
	if trace := actions(k); len(trace) != 0 {
		t.Fatal("healthy routes rebuilt", trace)
	}
}

func TestMixedDNSAnswersAndUnavailablePolicyStayFailClosed(t *testing.T) {
	g, k := fixture(t)
	g.Lookup = func(context.Context, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("8.8.8.8"), netip.MustParseAddr("223.5.5.5"), netip.MustParseAddr("127.0.0.1"), netip.MustParseAddr("119.29.29.29")}, nil
	}
	if err := g.domains(context.Background()); err != nil {
		t.Fatal(err)
	}
	for _, args := range k.calls {
		if args[2] != "get" || (args[3] != "223.5.5.5" && args[3] != "119.29.29.29") {
			t.Fatal("denied answer reached routes", args)
		}
	}
	os.Remove(g.ChinaList)
	k.calls = nil
	if err := g.domains(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(k.calls) != 0 {
		t.Fatal("missing policy retained old authorization", k.calls)
	}
}
