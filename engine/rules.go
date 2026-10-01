package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"
)

const maxRuleBytes = 16 << 20

type matcher struct {
	exact    map[string]bool
	suffix   map[string]bool
	keywords []string
	patterns []*regexp.Regexp
	networks map[int]map[netip.Prefix]bool
}

func compileRules(rules DomainRules) (*matcher, error) {
	m := &matcher{exact: map[string]bool{}, suffix: map[string]bool{}, networks: map[int]map[netip.Prefix]bool{}}
	for _, item := range []struct {
		values []string
		target map[string]bool
	}{{rules.Domain, m.exact}, {rules.Suffix, m.suffix}} {
		for _, value := range item.values {
			host, err := normalizeHost(value)
			if err != nil {
				return nil, fmt.Errorf("invalid rule domain: %w", err)
			}
			item.target[host] = true
		}
	}
	for _, word := range rules.Keyword {
		if word == "" {
			return nil, errors.New("empty domain keyword")
		}
		m.keywords = append(m.keywords, word)
	}
	for _, pattern := range rules.Regex {
		compiled, err := regexp.Compile(pattern)
		if err != nil {
			return nil, err
		}
		m.patterns = append(m.patterns, compiled)
	}
	for _, value := range rules.CIDR {
		prefix, err := netip.ParsePrefix(value)
		if err != nil {
			return nil, err
		}
		if !prefix.Addr().Is4() {
			continue
		}
		prefix = prefix.Masked()
		if m.networks[prefix.Bits()] == nil {
			m.networks[prefix.Bits()] = map[netip.Prefix]bool{}
		}
		m.networks[prefix.Bits()][prefix] = true
	}
	return m, nil
}

func (m *matcher) domain(host string) bool {
	if m.exact[host] {
		return true
	}
	for suffix := host; suffix != ""; {
		if m.suffix[suffix] {
			return true
		}
		index := strings.IndexByte(suffix, '.')
		if index < 0 {
			break
		}
		suffix = suffix[index+1:]
	}
	for _, word := range m.keywords {
		if strings.Contains(host, word) {
			return true
		}
	}
	for _, pattern := range m.patterns {
		if pattern.MatchString(host) {
			return true
		}
	}
	return false
}

func (m *matcher) ip(ip netip.Addr) bool {
	for bits, networks := range m.networks {
		if networks[netip.PrefixFrom(ip, bits).Masked()] {
			return true
		}
	}
	return false
}

func parseRuleData(data []byte, kind string) (*matcher, error) {
	if len(data) > maxRuleBytes {
		return nil, errors.New("rule data too large")
	}
	var document struct {
		Version int           `json:"version"`
		Rules   []DomainRules `json:"rules"`
	}
	if err := decodeJSON(data, &document); err != nil {
		return nil, err
	}
	if document.Version < 1 || document.Version > 3 || len(document.Rules) == 0 {
		return nil, errors.New("invalid rule document")
	}
	var merged DomainRules
	for _, rule := range document.Rules {
		if kind == "china" && len(rule.Domain)+len(rule.Suffix)+len(rule.Keyword)+len(rule.Regex) > 0 {
			return nil, errors.New("domain data in China address set")
		}
		if kind != "china" && len(rule.CIDR) > 0 {
			return nil, errors.New("address data in domain set")
		}
		merged.Domain = append(merged.Domain, rule.Domain...)
		merged.Suffix = append(merged.Suffix, rule.Suffix...)
		merged.Keyword = append(merged.Keyword, rule.Keyword...)
		merged.Regex = append(merged.Regex, rule.Regex...)
		merged.CIDR = append(merged.CIDR, rule.CIDR...)
	}
	if len(merged.Domain)+len(merged.Suffix)+len(merged.Keyword)+len(merged.Regex)+len(merged.CIDR) == 0 {
		return nil, errors.New("empty rule update rejected")
	}
	return compileRules(merged)
}

type ruleStore struct {
	mu                      sync.RWMutex
	sets                    map[string]*matcher
	protected, local, china *matcher
	cache                   string
}

func newRules(c Config) (*ruleStore, error) {
	r := &ruleStore{sets: map[string]*matcher{}, cache: c.CacheDir}
	var err error
	if r.protected, err = compileRules(c.Protected); err != nil {
		return nil, err
	}
	if r.local, err = compileRules(c.Local); err != nil {
		return nil, err
	}
	if r.china, err = compileRules(DomainRules{CIDR: c.ChinaCIDR}); err != nil {
		return nil, err
	}
	for _, source := range c.Sources {
		var last error
		for _, path := range []string{filepath.Join(c.CacheDir, source.Kind+".json"), source.Seed} {
			data, err := readRules(path)
			if err == nil {
				var set *matcher
				set, err = parseRuleData(data, source.Kind)
				if err == nil {
					r.sets[source.Kind] = set
					break
				}
			}
			last = err
		}
		if r.sets[source.Kind] == nil {
			return nil, fmt.Errorf("no usable %s rule cache or seed: %w", source.Kind, last)
		}
	}
	return r, nil
}

func readRules(path string) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Size() > maxRuleBytes {
		return nil, errors.New("unsafe or oversized rule file")
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	opened, err := f.Stat()
	if err != nil || !os.SameFile(info, opened) {
		return nil, errors.New("rule file changed while opening")
	}
	return io.ReadAll(io.LimitReader(f, maxRuleBytes+1))
}

func (r *ruleStore) domain(host string) string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if r.protected.domain(host) {
		return "foreign"
	}
	if r.local.domain(host) {
		return "domestic"
	}
	if r.sets["foreign"].domain(host) {
		return "foreign"
	}
	if r.sets["domestic"].domain(host) {
		return "domestic"
	}
	return ""
}

func (r *ruleStore) chinaGroup(ips []netip.Addr) (bool, []netip.Addr) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	isChina := func(ip netip.Addr) bool { return r.china.ip(ip) || r.sets["china"].ip(ip) }
	china := isChina(ips[0])
	filtered := make([]netip.Addr, 0, len(ips))
	for _, ip := range ips {
		if isChina(ip) == china {
			filtered = append(filtered, ip)
		}
	}
	return china, filtered
}

func (r *ruleStore) apply(kind string, data []byte) error {
	set, err := parseRuleData(data, kind)
	if err != nil {
		return err
	}
	info, err := os.Lstat(r.cache)
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0077 != 0 {
		return errors.New("unsafe rule cache directory")
	}
	file, err := os.CreateTemp(r.cache, ".update-")
	if err != nil {
		return err
	}
	path := file.Name()
	defer os.Remove(path)
	if err = file.Chmod(0600); err == nil {
		_, err = file.Write(data)
	}
	if err == nil {
		err = file.Sync()
	}
	closeErr := file.Close()
	if err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	if err = os.Rename(path, filepath.Join(r.cache, kind+".json")); err != nil {
		return err
	}
	r.mu.Lock()
	r.sets[kind] = set
	r.mu.Unlock()
	return nil
}

func (r *ruleStore) updater(ctx context.Context, source RuleSource, foreign Egress, dns lookupFunc, log *eventLog) {
	transport := &http.Transport{Proxy: nil, ForceAttemptHTTP2: true, TLSHandshakeTimeout: 8 * time.Second, IdleConnTimeout: 30 * time.Second,
		DialContext: func(ctx context.Context, _, address string) (net.Conn, error) {
			host, port, err := net.SplitHostPort(address)
			if err != nil {
				return nil, err
			}
			if ip, err := netip.ParseAddr(host); err == nil {
				if ip.IsLoopback() {
					return interfaceDial(ctx, "lo0", address)
				}
				if !publicIP(ip) {
					return nil, errors.New("private rule endpoint rejected")
				}
				return interfaceDial(ctx, foreign.Interface, address)
			}
			ips, err := dns(ctx, host)
			if err != nil {
				return nil, err
			}
			for _, ip := range ips {
				if !publicIP(ip) {
					return nil, errors.New("private rule DNS answer rejected")
				}
			}
			return dialAddresses(ctx, foreign.Interface, ips, port)
		}}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 20 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("rule redirect rejected") }}
	interval, _ := time.ParseDuration(source.Interval)
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		request, err := http.NewRequestWithContext(ctx, http.MethodGet, source.URL, nil)
		if err != nil {
			log.write("rule_update_failed", 0, map[string]any{"kind": source.Kind, "error": err.Error()})
			continue
		}
		response, err := client.Do(request)
		if err == nil {
			var data []byte
			if response.StatusCode != 200 {
				err = fmt.Errorf("rule HTTP status %d", response.StatusCode)
			} else {
				data, err = io.ReadAll(io.LimitReader(response.Body, maxRuleBytes+1))
				if err == nil {
					err = r.apply(source.Kind, data)
				}
			}
			response.Body.Close()
		}
		if err != nil {
			log.write("rule_update_failed", 0, map[string]any{"kind": source.Kind, "error": err.Error()})
		} else {
			log.write("rule_updated", 0, map[string]any{"kind": source.Kind})
		}
	}
}
