// Package dnsservice provides DNS policy and socket support for the unified program.
package dnsservice

import (
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"

	"github.com/miekg/dns"
	"network-owned-engine/internal/policy"
)

const MaxPolicyBytes = 1 << 20

type Config struct {
	Port             int
	Listen           []netip.Addr
	Servers          []netip.Addr
	Domains          map[string][]netip.Addr
	CacheEntries     int
	MaxTTL, CacheTTL uint32
	QueryLog         string
}

// Parse accepts only the DNS options already used by this installation. An
// unsupported option blocks migration instead of silently losing behavior.
func Parse(data []byte) (Config, error) {
	c := Config{Port: 53, CacheEntries: 150, MaxTTL: 3600, CacheTTL: 3600, Domains: map[string][]netip.Addr{}}
	if len(data) > MaxPolicyBytes {
		return c, errors.New("DNS policy is too large")
	}
	flags := map[string]bool{}
	singles := map[string]bool{}
	for index, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if before, _, ok := strings.Cut(line, " #"); ok {
			line = strings.TrimSpace(before)
		}
		key, value, hasValue := strings.Cut(line, "=")
		bad := func() error { return fmt.Errorf("unsupported or invalid DNS option on line %d: %s", index+1, key) }
		if !hasValue {
			if !slices.Contains([]string{"bind-interfaces", "no-resolv", "filter-AAAA", "domain-needed", "bogus-priv", "stop-dns-rebind", "dns-loop-detect", "local-service"}, key) || flags[key] {
				return c, bad()
			}
			flags[key] = true
			continue
		}
		if key != "server" {
			if singles[key] {
				return c, bad()
			}
			singles[key] = true
		}
		switch key {
		case "port", "cache-size", "max-cache-ttl", "max-ttl":
			n, err := strconv.ParseUint(value, 10, 32)
			if err != nil {
				return c, bad()
			}
			switch key {
			case "port":
				if n == 0 || n > 65535 {
					return c, bad()
				}
				c.Port = int(n)
			case "cache-size":
				if n > 10000 {
					return c, bad()
				}
				c.CacheEntries = int(n)
			case "max-cache-ttl":
				if n > 86400 {
					return c, bad()
				}
				c.CacheTTL = uint32(n)
			case "max-ttl":
				if n > 86400 {
					return c, bad()
				}
				c.MaxTTL = uint32(n)
			}
		case "listen-address":
			for _, text := range strings.Split(value, ",") {
				ip, err := netip.ParseAddr(text)
				if err != nil || !ip.Is4() || (!ip.IsLoopback() && !ip.IsGlobalUnicast()) || slices.Contains(c.Listen, ip) {
					return c, bad()
				}
				c.Listen = append(c.Listen, ip)
			}
		case "server":
			domain, ipText := "", value
			if strings.HasPrefix(value, "/") {
				parts := strings.Split(value, "/")
				if len(parts) != 3 || !validDomain(parts[1]) {
					return c, bad()
				}
				domain, ipText = strings.ToLower(strings.TrimSuffix(parts[1], ".")), parts[2]
			}
			ip, err := netip.ParseAddr(ipText)
			if err != nil || !ip.Is4() || !ip.IsGlobalUnicast() || !policy.Global(ip) {
				return c, bad()
			}
			if domain == "" {
				if !slices.Contains(c.Servers, ip) {
					c.Servers = append(c.Servers, ip)
				}
			} else if !slices.Contains(c.Domains[domain], ip) {
				c.Domains[domain] = append(c.Domains[domain], ip)
			}
		case "log-queries":
			if value != "extra" {
				return c, bad()
			}
		case "log-facility":
			if !filepath.IsAbs(value) || filepath.Clean(value) != value {
				return c, bad()
			}
			c.QueryLog = value
		default:
			return c, bad()
		}
	}
	for _, key := range []string{"bind-interfaces", "no-resolv", "filter-AAAA", "domain-needed", "bogus-priv", "stop-dns-rebind", "dns-loop-detect", "local-service"} {
		if !flags[key] {
			return c, fmt.Errorf("required DNS option missing: %s", key)
		}
	}
	if len(c.Listen) == 0 || len(c.Listen) > 4 || len(c.Servers) == 0 || len(c.Servers) > 8 || len(c.Domains) == 0 || len(c.Domains) > 256 || c.QueryLog == "" || !singles["log-queries"] {
		return c, errors.New("incomplete or oversized DNS policy")
	}
	for _, servers := range c.Domains {
		if len(servers) > 8 {
			return c, errors.New("too many DNS servers for one domain")
		}
	}
	unique := map[netip.Addr]bool{}
	for _, ip := range c.Servers {
		unique[ip] = true
	}
	for _, servers := range c.Domains {
		for _, ip := range servers {
			unique[ip] = true
		}
	}
	if len(unique) > 32 {
		return c, errors.New("too many distinct DNS upstreams")
	}
	for _, ip := range c.Listen {
		if slices.Contains(c.Servers, ip) {
			return c, errors.New("DNS policy loops to its listener")
		}
		for _, servers := range c.Domains {
			if slices.Contains(servers, ip) {
				return c, errors.New("DNS policy loops to its listener")
			}
		}
	}
	return c, nil
}

func Load(path string) (Config, error) {
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
	if err != nil {
		return Config{}, err
	}
	f := os.NewFile(uintptr(fd), path)
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() > MaxPolicyBytes || info.Mode().Perm()&0o022 != 0 || info.Sys().(*syscall.Stat_t).Nlink != 1 {
		return Config{}, errors.New("invalid DNS policy file")
	}
	data, err := io.ReadAll(io.LimitReader(f, MaxPolicyBytes+1))
	if err != nil {
		return Config{}, err
	}
	return Parse(data)
}

func validDomain(name string) bool {
	name = strings.TrimSuffix(name, ".")
	if name == "" || len(name) > 253 {
		return false
	}
	for _, label := range strings.Split(name, ".") {
		if len(label) == 0 || len(label) > 63 {
			return false
		}
		for _, ch := range label {
			if !(ch >= 'a' && ch <= 'z' || ch >= 'A' && ch <= 'Z' || ch >= '0' && ch <= '9' || ch == '-' || ch == '_') {
				return false
			}
		}
	}
	return true
}

func (c Config) Select(name string) (servers []netip.Addr, domestic bool) {
	name = strings.ToLower(strings.TrimSuffix(name, "."))
	for _, offset := range dns.Split(dns.Fqdn(name)) {
		if values, ok := c.Domains[name[offset:]]; ok {
			return append([]netip.Addr(nil), values...), true
		}
	}
	return append([]netip.Addr(nil), c.Servers...), false
}
