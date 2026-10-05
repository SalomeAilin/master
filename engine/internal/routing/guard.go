// Package routing maintains the existing dual-interface policy without a shell.
package routing

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"slices"
	"strings"
	"syscall"
	"time"

	"network-owned-engine/internal/healthcheck"
	"network-owned-engine/internal/policy"
	"network-owned-engine/internal/runtimecheck"
)

const DNSLabel = "system/homebrew.mxcl.dnsmasq"
const ChinaLabel = "system/com.local.china-route"

var HealthTargets = []string{"223.5.5.5", "119.29.29.29", "124.237.177.164", "139.159.241.37", "8.134.50.24"}
var blockSamples = []string{"8.8.8.8", "208.67.222.222"}
var blockNetworks = []string{"0.0.0.0/1", "128.0.0.0/1"}

type Route struct {
	Gateway, Interface string
	Reject             bool
}

func ParseRoute(raw string) Route {
	r := Route{}
	for _, line := range strings.Split(raw, "\n") {
		key, value, ok := strings.Cut(strings.TrimSpace(line), ":")
		if !ok {
			continue
		}
		switch key {
		case "gateway":
			r.Gateway = strings.TrimSpace(value)
		case "interface":
			r.Interface = strings.TrimSpace(value)
		case "flags":
			r.Reject = slices.Contains(strings.Split(strings.Trim(value, "<> "), ","), "REJECT")
		}
	}
	return r
}

type Config struct {
	DNS                                                    string `json:"dns"`
	WiredIP                                                string `json:"wired_ip"`
	WiredGateway                                           string `json:"wired_gateway"`
	WiFiGateway                                            string `json:"wifi_gateway"`
	WiredInterface                                         string `json:"wired_interface"`
	WiFiInterface                                          string `json:"wifi_interface"`
	WiredService                                           string `json:"wired_service"`
	WiFiService                                            string `json:"wifi_service"`
	ChinaList, ExtraList, DomainList, DNSConfig, DNSBinary string `json:"-"`
	GuardLock, ChinaLock, ForceRebuild, GuardLog, ChinaLog string `json:"-"`
}

func (c Config) Validate() error {
	for _, value := range []string{c.DNS, c.WiredIP, c.WiredGateway, c.WiFiGateway} {
		a, err := netip.ParseAddr(value)
		if err != nil || !a.Is4() || a.IsUnspecified() || a.IsMulticast() {
			return errors.New("invalid routing address")
		}
	}
	for _, value := range []string{c.WiredInterface, c.WiFiInterface} {
		if value == "" || strings.HasPrefix(value, "-") || strings.ContainsAny(value, " /\t\r\n") {
			return errors.New("invalid routing interface")
		}
	}
	if c.WiredInterface == c.WiFiInterface {
		return errors.New("routing interfaces must differ")
	}
	if c.WiredService == "" || c.WiFiService == "" {
		return errors.New("missing network service name")
	}
	return nil
}

type Guard struct {
	Config
	Run     func(...string) (string, error)
	Lookup  func(context.Context, string) ([]netip.Addr, error)
	HasIPv4 func(string, string) bool
	Sleep   func(context.Context, time.Duration) error
	Log     func(string, ...any)
	Policy  interface{ Allowed(string) bool }
}

func New(c Config) *Guard {
	g := &Guard{Config: c, Run: runtimecheck.Run, Policy: policy.New(c.ChinaList, c.ExtraList)}
	g.HasIPv4 = func(iface, expected string) bool {
		device, err := net.InterfaceByName(iface)
		if err != nil || device.Flags&net.FlagUp == 0 {
			return false
		}
		addresses, err := device.Addrs()
		if err != nil {
			return false
		}
		for _, address := range addresses {
			prefix, err := netip.ParsePrefix(address.String())
			if err == nil && prefix.Addr().Is4() && (expected == "" || prefix.Addr().String() == expected) {
				return true
			}
		}
		return false
	}
	g.Sleep = func(ctx context.Context, d time.Duration) error {
		timer := time.NewTimer(d)
		defer timer.Stop()
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-timer.C:
			return nil
		}
	}
	resolver := &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
		dialer := net.Dialer{Timeout: 2 * time.Second}
		return dialer.DialContext(ctx, network, net.JoinHostPort(c.DNS, "53"))
	}}
	g.Lookup = func(ctx context.Context, name string) ([]netip.Addr, error) {
		ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		return resolver.LookupNetIP(ctx, "ip4", name)
	}
	g.Log = func(format string, args ...any) {
		logger := healthcheck.Runner{LogPath: c.GuardLog, Now: time.Now}
		if err := logger.Logf(format, args...); err != nil {
			fmt.Fprintln(os.Stderr, err)
		}
	}
	return g
}

func (g *Guard) route(target string) Route {
	out, err := g.Run("/sbin/route", "-n", "get", target)
	if err != nil {
		return Route{}
	}
	return ParseRoute(out)
}
func (g *Guard) matches(target, gateway, iface string) bool {
	r := g.route(target)
	return !r.Reject && r.Gateway == gateway && r.Interface == iface
}
func (g *Guard) blocked(target string) bool {
	r := g.route(target)
	return r.Reject && r.Gateway == "127.0.0.1" && r.Interface == "lo0"
}
func (g *Guard) blocksActive() bool { return g.blocked(blockSamples[0]) && g.blocked(blockSamples[1]) }

// These must remain gateway reject routes: scoped inbound replies can bypass
// them. An interface route to lo0 would change the remote-access behavior.
func (g *Guard) block() error {
	if g.blocksActive() {
		return nil
	}
	for _, network := range blockNetworks {
		g.Run("/sbin/route", "-n", "add", "-net", network, "127.0.0.1", "-reject")
	}
	if !g.blocksActive() {
		return errors.New("could not install foreign fallback blocks")
	}
	g.Log("foreign fallback blocked while Wi-Fi is unavailable")
	return nil
}
func (g *Guard) unblock() error {
	changed := false
	for i, target := range blockSamples {
		if g.blocked(target) {
			changed = true
			g.Run("/sbin/route", "-n", "delete", "-net", blockNetworks[i], "127.0.0.1")
		}
	}
	if g.blocked(blockSamples[0]) || g.blocked(blockSamples[1]) {
		return errors.New("could not remove foreign fallback blocks")
	}
	if changed {
		g.Log("foreign fallback blocks removed after Wi-Fi recovered")
	}
	return nil
}

func (g *Guard) wifiGateway() string {
	if !g.HasIPv4(g.WiFiInterface, "") {
		return ""
	}
	var candidates []string
	packet, _ := g.Run("/usr/sbin/ipconfig", "getpacket", g.WiFiInterface)
	for _, line := range strings.Split(packet, "\n") {
		if !strings.Contains(line, "router (ip_mult)") {
			continue
		}
		_, values, ok := strings.Cut(line, "{")
		if !ok {
			continue
		}
		values, _, _ = strings.Cut(values, "}")
		candidates = append(candidates, strings.FieldsFunc(values, func(r rune) bool { return r == ',' || r == ' ' || r == '\t' })...)
	}
	candidates = append(candidates, g.WiFiGateway)
	if current := g.route("default"); current.Interface == g.WiFiInterface {
		candidates = append(candidates, current.Gateway)
	}
	for _, value := range candidates {
		a, err := netip.ParseAddr(value)
		if err == nil && a.Is4() && g.route(value).Interface == g.WiFiInterface {
			return value
		}
	}
	return ""
}

func (g *Guard) rebuildDefault(gateway, iface string) error {
	previous := g.route("default")
	g.Run("/sbin/route", "-n", "change", "default", gateway, "-ifp", iface)
	if g.matches("default", gateway, iface) {
		return nil
	}
	seen := map[string]bool{}
	for _, old := range []string{previous.Gateway, g.WiFiGateway, g.WiredGateway} {
		if old != "" && !seen[old] {
			seen[old] = true
			g.Run("/sbin/route", "-n", "delete", "default", old)
		}
	}
	g.Run("/sbin/route", "-n", "delete", "default")
	g.Run("/sbin/route", "-n", "add", "default", gateway, "-ifp", iface)
	if !g.matches("default", gateway, iface) {
		return fmt.Errorf("default route was not restored on %s", iface)
	}
	g.Log("default route restored interface=%s", iface)
	return nil
}

// Foreign applies blocks before any fallback and removes them only after a
// verified Wi-Fi default. Its false result means domestic fallback mode.
func (g *Guard) Foreign() (bool, error) {
	gateway := g.wifiGateway()
	if gateway == "" {
		if err := g.block(); err != nil {
			return false, err
		}
		if g.HasIPv4(g.WiredInterface, g.WiredIP) && g.route(g.WiredGateway).Interface == g.WiredInterface && !g.matches("default", g.WiredGateway, g.WiredInterface) {
			return false, g.rebuildDefault(g.WiredGateway, g.WiredInterface)
		}
		return false, nil
	}
	if !g.matches("default", gateway, g.WiFiInterface) {
		if err := g.block(); err != nil {
			return false, err
		}
		if err := g.rebuildDefault(gateway, g.WiFiInterface); err != nil {
			return false, err
		}
	}
	return true, g.unblock()
}

func (g *Guard) Bind(domain, ip string) error {
	address, ok := policy.ParseIPv4(ip)
	if !ok || !g.Policy.Allowed(address.String()) {
		return nil
	}
	if g.matches(ip, g.WiredGateway, g.WiredInterface) {
		return nil
	}
	g.Run("/sbin/route", "-n", "delete", "-host", "-ifscope", g.WiFiInterface, ip, g.WiFiGateway)
	g.Run("/sbin/route", "-n", "delete", "-host", ip, g.WiFiGateway)
	g.Run("/sbin/route", "-n", "delete", "-host", ip)
	g.Run("/sbin/route", "-n", "add", "-host", ip, g.WiredGateway, "-ifp", g.WiredInterface)
	if !g.matches(ip, g.WiredGateway, g.WiredInterface) {
		return fmt.Errorf("domestic route not restored domain=%s ip=%s", domain, ip)
	}
	g.Log("domestic route restored domain=%s ip=%s", domain, ip)
	return nil
}

func ReadLines(path string) ([]string, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() > 4<<20 {
		return nil, errors.New("invalid routing input")
	}
	data, err := io.ReadAll(io.LimitReader(file, (4<<20)+1))
	if err != nil || len(data) > 4<<20 {
		return nil, errors.New("could not read bounded routing input")
	}
	var lines []string
	for _, line := range strings.Split(string(data), "\n") {
		line, _, _ = strings.Cut(line, "#")
		if line = strings.TrimSpace(line); line != "" {
			lines = append(lines, line)
		}
	}
	return lines, nil
}

func (g *Guard) domains(ctx context.Context) error {
	domains, err := ReadLines(g.DomainList)
	if err != nil {
		return err
	}
	var failures []error
	for _, domain := range domains {
		if err := ctx.Err(); err != nil {
			return err
		}
		ips, err := g.Lookup(ctx, domain)
		if err != nil || len(ips) == 0 {
			g.Log("domain lookup unavailable domain=%s", domain)
			continue
		}
		for _, ip := range ips {
			if err := g.Bind(domain, ip.String()); err != nil {
				failures = append(failures, err)
			}
		}
	}
	return errors.Join(failures...)
}

func (g *Guard) fixedRoutesHealthy() bool {
	for _, ip := range HealthTargets {
		if !g.matches(ip, g.WiredGateway, g.WiredInterface) {
			return false
		}
	}
	lines, err := ReadLines(g.ExtraList)
	if err != nil {
		return false
	}
	for _, line := range lines {
		prefix, err := policy.ParsePrefix(line)
		if err != nil || !g.matches(prefix.Addr().String(), g.WiredGateway, g.WiredInterface) {
			return false
		}
	}
	return true
}

func (g *Guard) ensureDNS() {
	services, err := g.Run("/usr/sbin/networksetup", "-listallnetworkservices")
	if err != nil {
		return
	}
	for _, service := range []string{g.WiFiService, g.WiredService} {
		if !slices.Contains(strings.Split(strings.TrimSpace(services), "\n"), service) {
			continue
		}
		current, err := g.Run("/usr/sbin/networksetup", "-getdnsservers", service)
		if err == nil && strings.Join(strings.Fields(current), " ") == g.DNS {
			continue
		}
		if _, err := g.Run("/usr/sbin/networksetup", "-setdnsservers", service, g.DNS); err != nil {
			g.Log("could not restore DNS service=%s", service)
		}
	}
}

func (g *Guard) dnsReady() bool {
	out, err := g.Run("/usr/bin/dig", "+time=2", "+tries=1", "+norecurse", "+noall", "+comments", "A", "@"+g.DNS, "localhost.")
	if err != nil {
		return false
	}
	for _, line := range strings.Split(out, "\n") {
		if strings.HasPrefix(line, ";; flags:") {
			flags, _, _ := strings.Cut(strings.TrimPrefix(line, ";; flags:"), ";")
			return slices.Contains(strings.Fields(flags), "qr")
		}
	}
	return false
}

func (g *Guard) restartDNS() error {
	info, err := os.Lstat(g.DNSBinary)
	native := g.DNSBinary == runtimecheck.Production.Binary
	mode := os.FileMode(0o555)
	if native {
		mode = 0o755
	}
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != mode {
		return errors.New("fixed DNS binary missing or unsafe; no automatic import")
	}
	stat := info.Sys().(*syscall.Stat_t)
	if stat.Uid != 0 || stat.Gid != 0 {
		return errors.New("DNS binary is not root:wheel")
	}
	if native {
		if _, err := g.Run(g.DNSBinary, "check-service", "-c", runtimecheck.ServiceConfigPath); err != nil {
			return err
		}
		_, err := g.Run("/bin/launchctl", "kickstart", "-k", "system/"+runtimecheck.NativeDNSLabel)
		return err
	}
	if _, err := g.Run(g.DNSBinary, "--test", "--conf-file="+g.DNSConfig); err != nil {
		return err
	}
	_, err = g.Run("/bin/launchctl", "kickstart", "-k", DNSLabel)
	return err
}

func (g *Guard) RunOnce(ctx context.Context) error {
	if err := g.Config.Validate(); err != nil {
		return err
	}
	release, err := healthcheck.LockState(g.GuardLock)
	if errors.Is(err, healthcheck.ErrBusy) {
		return nil
	}
	if err != nil {
		return err
	}
	defer release()
	g.ensureDNS()
	if _, err := g.Foreign(); err != nil {
		g.Log("foreign route repair failed: %v", err)
	}
	for attempt := 0; attempt <= 20; attempt++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		_, err := g.Foreign()
		if err == nil && g.HasIPv4(g.WiredInterface, g.WiredIP) && g.route(g.WiredGateway).Interface == g.WiredInterface {
			break
		}
		if attempt == 20 {
			return errors.New("network not ready after 60 seconds")
		}
		if err := g.Sleep(ctx, 3*time.Second); err != nil {
			return err
		}
	}
	ready := false
	for attempt := 0; attempt < 3; attempt++ {
		if g.dnsReady() {
			ready = true
			break
		}
		if attempt == 0 {
			if err := g.restartDNS(); err != nil {
				g.Log("DNS recovery refused or failed: %v", err)
			}
		}
		if err := g.Sleep(ctx, 2*time.Second); err != nil {
			return err
		}
	}
	if !ready {
		return errors.New("local DNS listener did not respond")
	}
	bad := !g.fixedRoutesHealthy()
	if !g.matches("163.181.253.200", g.WiredGateway, g.WiredInterface) {
		bad = true
	}
	if err := g.domains(ctx); err != nil {
		bad = true
		g.Log("domestic scan incomplete: %v", err)
	}
	// Recheck foreign routing after a possibly long domain scan.
	if err := ctx.Err(); err != nil {
		return err
	}
	if _, err := g.Foreign(); err != nil {
		return err
	}
	if bad {
		marker, err := syscall.Open(g.ForceRebuild, syscall.O_WRONLY|syscall.O_CREAT|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0o600)
		if err != nil {
			return err
		}
		file := os.NewFile(uintptr(marker), g.ForceRebuild)
		info, statErr := file.Stat()
		file.Close()
		if statErr != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 || info.Sys().(*syscall.Stat_t).Nlink != 1 || info.Sys().(*syscall.Stat_t).Uid != uint32(os.Geteuid()) {
			return errors.New("unsafe rebuild marker")
		}
		details, _ := g.Run("/bin/launchctl", "print", ChinaLabel)
		if !strings.Contains(details, "state = running") {
			if _, err := g.Run("/bin/launchctl", "kickstart", ChinaLabel); err != nil {
				return err
			}
		}
	}
	_, err = g.Foreign()
	return err
}

func (g *Guard) Rebuild(ctx context.Context) error {
	if err := g.Config.Validate(); err != nil {
		return err
	}
	release, err := healthcheck.LockState(g.ChinaLock)
	if errors.Is(err, healthcheck.ErrBusy) {
		return nil
	}
	if err != nil {
		return err
	}
	defer release()
	var prefixes []netip.Prefix
	for _, path := range []string{g.ChinaList, g.ExtraList} {
		lines, err := ReadLines(path)
		if err != nil {
			return err
		}
		for _, line := range lines {
			p, err := policy.ParsePrefix(line)
			if err != nil {
				return err
			}
			prefixes = append(prefixes, p)
		}
	}
	for attempt := 0; !g.HasIPv4(g.WiredInterface, g.WiredIP) || g.route(g.WiredGateway).Interface != g.WiredInterface; attempt++ {
		if attempt == 24 {
			return errors.New("wired network not ready after 120 seconds")
		}
		if err := g.Sleep(ctx, 5*time.Second); err != nil {
			return err
		}
	}
	_, forceErr := os.Lstat(g.ForceRebuild)
	if forceErr != nil && !os.IsNotExist(forceErr) {
		return forceErr
	}
	if forceErr != nil && g.fixedRoutesHealthy() {
		return g.domains(ctx)
	}
	if forceErr == nil {
		if err := os.Remove(g.ForceRebuild); err != nil {
			return err
		}
	}
	failed := 0
	for _, prefix := range prefixes {
		if err := ctx.Err(); err != nil {
			return err
		}
		kind, target := "-net", prefix.String()
		if prefix.Bits() == 32 {
			kind, target = "-host", prefix.Addr().String()
		}
		g.Run("/sbin/route", "-n", "delete", kind, "-ifscope", g.WiFiInterface, target, g.WiredGateway)
		g.Run("/sbin/route", "-n", "delete", kind, target, g.WiredGateway)
		if _, err := g.Run("/sbin/route", "-n", "add", kind, target, g.WiredGateway, "-ifp", g.WiredInterface); err != nil {
			failed++
		}
	}
	if err := g.domains(ctx); err != nil {
		return err
	}
	g.Log("domestic rebuild completed prefixes=%d failures=%d", len(prefixes), failed)
	if failed > 0 {
		return fmt.Errorf("%d domestic route additions failed", failed)
	}
	return nil
}
