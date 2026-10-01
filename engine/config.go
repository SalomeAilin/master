package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type DNSConfig struct {
	Address    string              `json:"address"`
	ServerName string              `json:"server_name"`
	Hosts      map[string][]string `json:"hosts,omitempty"`
}

type Egress struct {
	Interface string    `json:"interface"`
	DNS       DNSConfig `json:"dns"`
}

type DomainRules struct {
	Domain  []string `json:"domain,omitempty"`
	Suffix  []string `json:"domain_suffix,omitempty"`
	Keyword []string `json:"domain_keyword,omitempty"`
	Regex   []string `json:"domain_regex,omitempty"`
	CIDR    []string `json:"ip_cidr,omitempty"`
}

type RuleSource struct {
	Kind     string `json:"kind"`
	URL      string `json:"url"`
	Seed     string `json:"seed"`
	Interval string `json:"interval"`
}

type Config struct {
	Version    int          `json:"version"`
	Listen     string       `json:"listen"`
	Domestic   Egress       `json:"domestic"`
	Foreign    Egress       `json:"foreign"`
	Protected  DomainRules  `json:"protected_foreign"`
	Local      DomainRules  `json:"local_domestic"`
	ChinaCIDR  []string     `json:"china_cidr"`
	Sources    []RuleSource `json:"rule_sources"`
	CacheDir   string       `json:"cache_directory"`
	MaxClients int          `json:"max_clients"`
}

func decodeJSON(data []byte, value any) error {
	d := json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if err := d.Decode(value); err != nil {
		return err
	}
	if err := d.Decode(new(any)); err != io.EOF {
		return errors.New("trailing JSON data")
	}
	return nil
}

func loadConfig(path string) (Config, error) {
	var c Config
	f, err := os.Open(path)
	if err != nil {
		return c, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, 4<<20+1))
	if err != nil {
		return c, err
	}
	if len(data) > 4<<20 {
		return c, errors.New("configuration too large")
	}
	if err = decodeJSON(data, &c); err != nil {
		return c, err
	}
	return c, c.validate()
}

func (c *Config) validate() error {
	if c.Version != 1 {
		return errors.New("unsupported independent configuration version")
	}
	host, port, err := net.SplitHostPort(c.Listen)
	if err != nil {
		return err
	}
	ip, err := netip.ParseAddr(host)
	if err != nil || !ip.Is4() || !ip.IsLoopback() || port == "0" {
		return errors.New("listener must be an IPv4 loopback address with a fixed port")
	}
	if _, err := parseTarget(c.Listen); err != nil {
		return err
	}
	if c.MaxClients == 0 {
		c.MaxClients = 512
	}
	if c.MaxClients < 1 || c.MaxClients > 4096 {
		return errors.New("invalid client limit")
	}
	for _, e := range []Egress{c.Domestic, c.Foreign} {
		if strings.TrimSpace(e.Interface) == "" {
			return errors.New("an egress interface is mandatory")
		}
		if len(e.DNS.Hosts) == 0 {
			ip, err := netip.ParseAddr(e.DNS.Address)
			if err != nil || !ip.Is4() || !publicIP(ip) {
				return errors.New("DoH endpoint must be a public IPv4 literal")
			}
			if _, err := normalizeHost(e.DNS.ServerName); err != nil {
				return errors.New("invalid DoH TLS server name")
			}
		} else {
			for host, values := range e.DNS.Hosts {
				if _, err := normalizeHost(host); err != nil || len(values) == 0 {
					return errors.New("invalid fixture DNS host")
				}
				for _, value := range values {
					if ip, err := netip.ParseAddr(value); err != nil || !ip.Is4() {
						return errors.New("fixture DNS must contain IPv4 literals")
					}
				}
			}
		}
	}
	if c.Domestic.Interface == c.Foreign.Interface {
		return errors.New("domestic and foreign interfaces must be distinct")
	}
	if _, err := compileRules(c.Protected); err != nil {
		return err
	}
	if _, err := compileRules(c.Local); err != nil {
		return err
	}
	if _, err := compileRules(DomainRules{CIDR: c.ChinaCIDR}); err != nil {
		return err
	}
	if !filepath.IsAbs(c.CacheDir) {
		return errors.New("cache directory must be absolute")
	}
	seen := map[string]bool{}
	for _, source := range c.Sources {
		if source.Kind != "domestic" && source.Kind != "foreign" && source.Kind != "china" {
			return errors.New("unknown rule source kind")
		}
		if seen[source.Kind] {
			return errors.New("duplicate rule source")
		}
		seen[source.Kind] = true
		if !filepath.IsAbs(source.Seed) {
			return errors.New("rule seed must be absolute")
		}
		u, err := url.Parse(source.URL)
		if err != nil || u.Host == "" || u.User != nil || u.Fragment != "" {
			return errors.New("invalid rule URL")
		}
		if u.Scheme != "https" {
			ip, err := netip.ParseAddr(u.Hostname())
			if u.Scheme != "http" || err != nil || !ip.IsLoopback() {
				return errors.New("rule downloads require HTTPS; HTTP is restricted to loopback fixtures")
			}
		}
		interval, err := time.ParseDuration(source.Interval)
		if err != nil || interval < 100*time.Millisecond || interval > 7*24*time.Hour {
			return errors.New("invalid rule update interval")
		}
	}
	for _, kind := range []string{"domestic", "foreign", "china"} {
		if !seen[kind] {
			return fmt.Errorf("missing %s rule source", kind)
		}
	}
	return nil
}

func normalizeHost(host string) (string, error) {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	if ip, err := netip.ParseAddr(host); err == nil {
		return ip.Unmap().String(), nil
	}
	if len(host) == 0 || len(host) > 253 {
		return "", errors.New("invalid hostname length")
	}
	for _, label := range strings.Split(host, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return "", errors.New("invalid hostname label")
		}
		for _, b := range []byte(label) {
			if !(b >= 'a' && b <= 'z' || b >= '0' && b <= '9' || b == '-' || b == '_') {
				return "", errors.New("hostname must use ASCII or punycode")
			}
		}
	}
	return host, nil
}

func publicIP(ip netip.Addr) bool {
	ip = ip.Unmap()
	if !ip.Is4() || !ip.IsGlobalUnicast() || ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() {
		return false
	}
	for _, block := range nonPublicIPv4 {
		if block.Contains(ip) {
			return false
		}
	}
	return true
}

var nonPublicIPv4 = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"), netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("198.18.0.0/15"), netip.MustParsePrefix("240.0.0.0/4"),
}
