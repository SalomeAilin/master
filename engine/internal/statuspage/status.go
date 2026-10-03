// Package statuspage collects bounded, read-only evidence for the existing
// local status page. It never changes routes, DNS settings or service state.
package statuspage

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"time"

	"network-owned-engine/internal/policy"
)

type Row struct{ Name, Address, State, Detail string }
type Report struct {
	Updated         time.Time
	State           string
	Checks, Domains []Row
}
type Route struct {
	Gateway, Interface string
	Reject             bool
}

func (r Route) String() string { return r.Gateway + "/" + r.Interface }
func (r Route) Matches(other Route) bool {
	return !r.Reject && !other.Reject && r.Gateway != "" && r.Interface != "" && r.Gateway == other.Gateway && r.Interface == other.Interface
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

type Collector struct {
	Etc, Sbin, Launchd string
	ObserverProgram    string
	Run                func(context.Context, ...string) (string, error)
	Lookup             func(context.Context, string) ([]netip.Addr, error)
	HTTP               func(context.Context, string, string) (string, bool)
	Now                func() time.Time
	Metadata           func(string, os.FileMode) bool
}

func New() *Collector {
	return &Collector{Etc: "/usr/local/etc", Sbin: "/usr/local/sbin", Launchd: "/Library/LaunchDaemons", Now: time.Now,
		Run: func(ctx context.Context, args ...string) (string, error) {
			ctx, cancel := context.WithTimeout(ctx, 4*time.Second)
			defer cancel()
			out, err := exec.CommandContext(ctx, args[0], args[1:]...).CombinedOutput()
			return string(out), err
		}}
}
func boundedRead(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() > 4<<20 {
		return nil, errors.New("invalid status input")
	}
	data, err := io.ReadAll(io.LimitReader(f, (4<<20)+1))
	if len(data) > 4<<20 {
		return nil, errors.New("status input too large")
	}
	return data, err
}
func lines(data []byte) []string {
	var result []string
	for _, line := range strings.Split(string(data), "\n") {
		line, _, _ = strings.Cut(line, "#")
		if line = strings.TrimSpace(line); line != "" {
			result = append(result, line)
		}
	}
	return result
}
func (c *Collector) route(ctx context.Context, args ...string) Route {
	out, err := c.Run(ctx, append([]string{"/sbin/route", "-n", "get"}, args...)...)
	if err != nil {
		return Route{}
	}
	return ParseRoute(out)
}
func privateMetadata(path string, mode os.FileMode) bool {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != mode {
		return false
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && stat.Uid == 0 && stat.Gid == 0
}

func dnsArgumentsOK(args []string, binary, config string) bool {
	if len(args) == 0 || args[0] != binary {
		return false
	}
	files := 0
	for i := 1; i < len(args); i++ {
		switch args[i] {
		case "--keep-in-foreground", "--no-daemon", "-k", "-d":
		case "-C", "--conf-file":
			i++
			if i == len(args) || args[i] != config {
				return false
			}
			files++
		default:
			if args[i] != "--conf-file="+config {
				return false
			}
			files++
		}
	}
	return files == 1
}
func (c *Collector) Collect(ctx context.Context) Report {
	r := Report{Updated: c.Now(), State: "OK"}
	routes := map[string]Route{}
	route := func(args ...string) Route {
		key := strings.Join(args, "\x00")
		if r, ok := routes[key]; ok {
			return r
		}
		r := c.route(ctx, args...)
		routes[key] = r
		return r
	}
	add := func(name, detail string, ok bool) {
		state := "ok"
		if !ok {
			state = "bad"
			r.State = "BAD"
		}
		r.Checks = append(r.Checks, Row{Name: name, State: state, Detail: detail})
	}
	var cfg struct {
		Domestic, Foreign struct {
			Interface string `json:"interface"`
		}
	}
	data, err := boundedRead(filepath.Join(c.Etc, "network-domain-proxy.json"))
	if err != nil || json.Unmarshal(data, &cfg) != nil || cfg.Domestic.Interface == "" || cfg.Foreign.Interface == "" || cfg.Domestic.Interface == cfg.Foreign.Interface {
		add("configuration", "missing or invalid proxy interfaces", false)
		return r
	}
	configPath := filepath.Join(c.Etc, "dnsmasq-network-split.conf")
	dnsData, err := boundedRead(configPath)
	if err != nil {
		add("dns-configuration", err.Error(), false)
		return r
	}
	dns := ""
	options := map[string]bool{}
	for _, line := range lines(dnsData) {
		options[line] = true
		if v, ok := strings.CutPrefix(line, "listen-address="); ok {
			for _, s := range strings.Split(v, ",") {
				a, e := netip.ParseAddr(strings.TrimSpace(s))
				if e == nil && a.Is4() && !a.IsLoopback() {
					dns = a.String()
					break
				}
			}
		}
	}
	if dns == "" {
		add("dns-configuration", "missing IPv4 DNS listener", false)
		return r
	}
	resolver := &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
		d := net.Dialer{Timeout: 2 * time.Second}
		return d.DialContext(ctx, network, net.JoinHostPort(dns, "53"))
	}}
	lookup := c.Lookup
	if lookup == nil {
		lookup = func(ctx context.Context, name string) ([]netip.Addr, error) {
			return resolver.LookupNetIP(ctx, "ip4", name)
		}
	}
	lookupCache := map[string][]netip.Addr{}
	resolve := func(name string) []netip.Addr {
		if ips, ok := lookupCache[name]; ok {
			return ips
		}
		child, cancel := context.WithTimeout(ctx, 2*time.Second)
		defer cancel()
		ips, err := lookup(child, name)
		if err != nil {
			ips = nil
		}
		slices.SortFunc(ips, func(a, b netip.Addr) int { return a.Compare(b) })
		ips = slices.Compact(ips)
		lookupCache[name] = ips
		return ips
	}
	wired := route("-ifscope", cfg.Domestic.Interface, "default")
	wifi := route("-ifscope", cfg.Foreign.Interface, "default")
	defaultRoute := route("default")
	foreign := route("1.1.1.1")
	upper := route("208.67.222.222")
	blocked := foreign.Reject && upper.Reject && foreign.Interface == "lo0" && upper.Interface == "lo0"
	foreignDown := wifi.Gateway == "" || wifi.Interface != cfg.Foreign.Interface
	fallback := foreignDown && blocked && defaultRoute.Matches(wired)
	add("default-route", defaultRoute.String(), defaultRoute.Matches(wifi) || fallback)
	add("foreign-route", foreign.String(), foreign.Matches(wifi) || fallback)
	domestic := route("223.5.5.5")
	add("domestic-route", domestic.String(), wired.Interface == cfg.Domestic.Interface && domestic.Matches(wired))
	for label, program := range map[string]string{"homebrew.mxcl.dnsmasq": "dnsmasq-network-split", "com.local.network-split-dns-event-route-agent": "network-split-dns-event-route-agent"} {
		out, err := c.Run(ctx, "/bin/launchctl", "print", "system/"+label)
		values := map[string]string{}
		for _, line := range strings.Split(out, "\n") {
			key, value, ok := strings.Cut(strings.TrimSpace(line), " = ")
			if ok {
				if _, found := values[key]; !found {
					values[key] = value
				}
			}
		}
		expected := filepath.Join(c.Sbin, program)
		if label == "com.local.network-split-dns-event-route-agent" && c.ObserverProgram != "" {
			expected = c.ObserverProgram
		}
		add(label, values["state"], err == nil && values["state"] == "running" && values["program"] == expected)
	}
	for _, service := range []string{"Wi-Fi", "Ethernet"} {
		out, err := c.Run(ctx, "/usr/sbin/networksetup", "-getdnsservers", service)
		add("dns-"+service, strings.TrimSpace(out), err == nil && strings.TrimSpace(out) == dns)
	}
	out, err := c.Run(ctx, "/usr/sbin/scutil", "--dns")
	dnsOK := err == nil
	foundDNS := false
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		if len(f) == 3 && strings.HasPrefix(f[0], "nameserver[") {
			foundDNS = true
			if f[2] != dns {
				dnsOK = false
			}
		}
	}
	add("system-resolvers", dns, dnsOK && foundDNS)
	plistPath := filepath.Join(c.Launchd, "homebrew.mxcl.dnsmasq.plist")
	binaryPath := filepath.Join(c.Sbin, "dnsmasq-network-split")
	metadata := c.Metadata
	if metadata == nil {
		metadata = privateMetadata
	}
	metadataOK := metadata(binaryPath, 0o555) && metadata(configPath, 0o644) && metadata(plistPath, 0o644)
	optionsOK := true
	for _, option := range []string{"no-resolv", "filter-AAAA", "domain-needed", "bogus-priv", "stop-dns-rebind", "dns-loop-detect", "local-service"} {
		optionsOK = optionsOK && options[option]
	}
	out, err = c.Run(ctx, "/usr/bin/plutil", "-convert", "json", "-o", "-", plistPath)
	var daemon struct{ ProgramArguments []string }
	argumentsOK := err == nil && json.Unmarshal([]byte(out), &daemon) == nil && dnsArgumentsOK(daemon.ProgramArguments, binaryPath, configPath)
	add("dns-security-baseline", fmt.Sprintf("metadata=%t options=%t launch_arguments=%t", metadataOK, optionsOK, argumentsOK), metadataOK && optionsOK && argumentsOK)
	var nonce [8]byte
	_, randomErr := rand.Read(nonce[:])
	probeName := "network-split-" + hex.EncodeToString(nonce[:]) + ".invalid."
	child, cancel := context.WithTimeout(ctx, 2*time.Second)
	ips, err := lookup(child, probeName)
	cancel()
	var dnsErr *net.DNSError
	add("negative-dns", "reserved nonexistent name", randomErr == nil && len(ips) == 0 && errors.As(err, &dnsErr) && dnsErr.IsNotFound)
	addressPolicy := policy.New(filepath.Join(c.Etc, "china_ip_list.txt"), filepath.Join(c.Etc, "domestic_extra_routes.txt"))
	policyOK := addressPolicy.Allowed("223.5.5.5")
	add("address-policy", "domestic resolver control", policyOK)
	domains, err := boundedRead(filepath.Join(c.Etc, "domestic_domains.conf"))
	names := lines(domains)
	add("domestic-domain-list", fmt.Sprintf("%d entries", len(names)), err == nil && len(names) > 0 && len(names) <= 256)
	if len(names) > 256 {
		names = names[:256]
	}
	publicOK := true
	for _, name := range names {
		ips := resolve(name)
		if len(ips) == 0 {
			r.Domains = append(r.Domains, Row{Name: name, State: "unknown", Detail: "DNS lookup failed"})
			r.State = "BAD"
			continue
		}
		for _, ip := range ips {
			actual := route(ip.String())
			row := Row{Name: name, Address: ip.String(), State: "wired", Detail: actual.String()}
			switch {
			case !policyOK:
				row.State = "unknown"
				r.State = "BAD"
			case !policy.Global(ip):
				row.State = "bad"
				publicOK = false
				r.State = "BAD"
			case !addressPolicy.Allowed(ip.String()):
				row.State = "policy-excluded"
			case !actual.Matches(wired):
				row.State = "drift"
				r.State = "BAD"
			}
			r.Domains = append(r.Domains, row)
		}
	}
	extra, err := boundedRead(filepath.Join(c.Etc, "domestic_extra_routes.txt"))
	extraOK := err == nil
	for _, cidr := range lines(extra) {
		prefix, e := netip.ParsePrefix(cidr)
		if e != nil || !route(prefix.Addr().String()).Matches(wired) {
			extraOK = false
		}
	}
	add("extra-domestic-routes", "configured address exceptions", extraOK)
	for _, name := range []string{"google.com", "baidu.com", "claude.ai", "api.anthropic.com", "console.anthropic.com"} {
		ips := resolve(name)
		ok := len(ips) > 0
		for _, ip := range ips {
			if !policy.Global(ip) {
				ok = false
				publicOK = false
			}
			if name != "baidu.com" && !fallback && !route(ip.String()).Matches(wifi) {
				ok = false
			}
		}
		if fallback && name != "baidu.com" {
			r.Checks = append(r.Checks, Row{Name: name, State: "blocked", Detail: "Wi-Fi unavailable"})
		} else {
			add(name, "DNS and IP-route sample", ok)
		}
	}
	add("public-dns-answers", "no private or reserved IPv4 answers", publicOK)
	if fallback {
		r.Checks = append(r.Checks, Row{Name: "foreign-http", State: "blocked", Detail: "Wi-Fi unavailable; no wired probe"})
	} else {
		head := c.HTTP
		if head == nil {
			head = Head
		}
		for _, target := range []string{"https://www.google.com/generate_204", "https://claude.ai/", "https://api.anthropic.com/"} {
			detail, ok := head(ctx, cfg.Foreign.Interface, target)
			add(target, detail, ok)
		}
	}
	if ctx.Err() != nil {
		add("collection", ctx.Err().Error(), false)
	}
	if r.State == "OK" && fallback {
		r.State = "FALLBACK"
	}
	slices.SortFunc(r.Checks, func(a, b Row) int { return strings.Compare(a.Name, b.Name) })
	return r
}

// Head verifies TLS and binds the socket to the foreign interface. No proxy,
// redirect or interface fallback is allowed, and no response body is read.
func Head(ctx context.Context, iface, target string) (string, bool) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	dialer := net.Dialer{Timeout: 5 * time.Second, ControlContext: func(_ context.Context, _, _ string, raw syscall.RawConn) error {
		device, err := net.InterfaceByName(iface)
		if err != nil {
			return err
		}
		if device.Flags&net.FlagUp == 0 {
			return errors.New("foreign interface down")
		}
		var bound error
		if err := raw.Control(func(fd uintptr) {
			bound = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IP, syscall.IP_BOUND_IF, device.Index)
		}); err != nil {
			return err
		}
		return bound
	}}
	transport := &http.Transport{Proxy: nil, TLSHandshakeTimeout: 5 * time.Second, DialContext: func(ctx context.Context, _, addr string) (net.Conn, error) {
		return dialer.DialContext(ctx, "tcp4", addr)
	}}
	defer transport.CloseIdleConnections()
	client := http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	request, err := http.NewRequestWithContext(ctx, http.MethodHead, target, nil)
	if err != nil {
		return err.Error(), false
	}
	start := time.Now()
	response, err := client.Do(request)
	if err != nil {
		return err.Error(), false
	}
	response.Body.Close()
	ok := response.StatusCode >= 200 && response.StatusCode < 500
	if request.URL.Host == "www.google.com" {
		ok = response.StatusCode == 204
	}
	return fmt.Sprintf("HTTP %d; %d ms; interface=%s", response.StatusCode, time.Since(start).Milliseconds(), iface), ok
}
