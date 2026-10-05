package dnsservice

import (
	"fmt"
	"slices"
	"strings"
)

// Encode writes the supported policy subset for isolated preflight fixtures.
// The installed policy is preserved during migration.
func (c Config) Encode() []byte {
	var b strings.Builder
	fmt.Fprintf(&b, "port=%d\n", c.Port)
	var addresses []string
	for _, ip := range c.Listen {
		addresses = append(addresses, ip.String())
	}
	fmt.Fprintf(&b, "listen-address=%s\n", strings.Join(addresses, ","))
	for _, flag := range []string{"bind-interfaces", "no-resolv", "filter-AAAA", "domain-needed", "bogus-priv", "stop-dns-rebind", "dns-loop-detect", "local-service"} {
		fmt.Fprintln(&b, flag)
	}
	fmt.Fprintf(&b, "cache-size=%d\nmax-ttl=%d\nmax-cache-ttl=%d\nlog-queries=extra\nlog-facility=%s\n", c.CacheEntries, c.MaxTTL, c.CacheTTL, c.QueryLog)
	for _, ip := range c.Servers {
		fmt.Fprintf(&b, "server=%s\n", ip)
	}
	var domains []string
	for name := range c.Domains {
		domains = append(domains, name)
	}
	slices.Sort(domains)
	for _, name := range domains {
		for _, ip := range c.Domains[name] {
			fmt.Fprintf(&b, "server=/%s/%s\n", name, ip)
		}
	}
	return []byte(b.String())
}
