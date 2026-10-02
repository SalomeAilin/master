// Package proxyconfig builds the independent engine's configuration from the
// repository's routing policy files.
package proxyconfig

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"unicode"

	"network-owned-engine/internal/policy"
)

const (
	RulesDirectory = "/usr/local/etc/network-domain-rules-independent"
	CacheDirectory = "/var/db/network-domain-proxy/independent-cache"
)

// ForeignProtected domains always use Wi-Fi, whatever their CDN address is.
var ForeignProtected = []string{
	"github.com", "githubusercontent.com", "githubassets.com", "githubcopilot.com",
	"claude.ai", "claude.com", "anthropic.com", "openai.com", "chatgpt.com",
	"oaistatic.com", "oaiusercontent.com", "google.com", "googleapis.com",
	"gstatic.com", "youtube.com", "googlevideo.com", "ytimg.com", "tiktok.com",
}

var ruleSources = [][2]string{
	{"domestic", "geo/geosite/geolocation-cn"},
	{"foreign", "geo/geosite/geolocation-!cn"},
	{"china", "geo/geoip/cn"},
}

type DNS struct {
	Address    string              `json:"address"`
	ServerName string              `json:"server_name"`
	Hosts      map[string][]string `json:"hosts,omitempty"` // isolated test fixtures only
}

type Egress struct {
	Interface string `json:"interface"`
	DNS       DNS    `json:"dns"`
}

type Protected struct {
	DomainSuffix []string `json:"domain_suffix"`
}

type Local struct {
	Domain       []string `json:"domain"`
	DomainSuffix []string `json:"domain_suffix"`
}

type RuleSource struct {
	Kind     string `json:"kind"`
	URL      string `json:"url"`
	Seed     string `json:"seed"`
	Interval string `json:"interval"`
}

// Config keeps the field order of the configuration installed in production.
type Config struct {
	Version        int          `json:"version"`
	Listen         string       `json:"listen"`
	MaxClients     int          `json:"max_clients"`
	Domestic       Egress       `json:"domestic"`
	Foreign        Egress       `json:"foreign"`
	Protected      Protected    `json:"protected_foreign"`
	Local          Local        `json:"local_domestic"`
	ChinaCIDR      []string     `json:"china_cidr"`
	CacheDirectory string       `json:"cache_directory"`
	RuleSources    []RuleSource `json:"rule_sources"`
}

// Build reads the policy files in policyDir. Empty directories select the
// production rule seed and cache locations.
func Build(policyDir, rulesDirectory, cacheDirectory string) (Config, error) {
	local, networks, err := loadPolicy(policyDir)
	if err != nil {
		return Config{}, err
	}
	if rulesDirectory == "" {
		rulesDirectory = RulesDirectory
	}
	if cacheDirectory == "" {
		cacheDirectory = CacheDirectory
	}
	c := Config{
		Version: 1, Listen: "127.0.0.1:17890", MaxClients: 512,
		Domestic:  Egress{Interface: "en0", DNS: DNS{Address: "223.5.5.5", ServerName: "dns.alidns.com"}},
		Foreign:   Egress{Interface: "en1", DNS: DNS{Address: "1.1.1.1", ServerName: "cloudflare-dns.com"}},
		Protected: Protected{DomainSuffix: slices.Clone(ForeignProtected)},
		Local:     local, ChinaCIDR: networks, CacheDirectory: cacheDirectory,
	}
	for _, source := range ruleSources {
		c.RuleSources = append(c.RuleSources, RuleSource{
			Kind:     source[0],
			URL:      "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/sing/" + source[1] + ".json",
			Seed:     filepath.Join(rulesDirectory, source[0]+".json"),
			Interval: "1h",
		})
	}
	return c, nil
}

// Encode renders the configuration as two-space indented JSON with a final
// newline, byte-for-byte the format of the configuration already installed.
func Encode(c Config) ([]byte, error) {
	var buffer bytes.Buffer
	encoder := json.NewEncoder(&buffer)
	encoder.SetEscapeHTML(false)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(c); err != nil {
		return nil, err
	}
	return buffer.Bytes(), nil
}

func loadPolicy(root string) (Local, []string, error) {
	var local Local
	hostLines, err := readLines(filepath.Join(root, "domestic_proxy_hosts.conf"))
	if err != nil {
		return local, nil, err
	}
	hosts := map[string]bool{}
	for _, line := range hostLines {
		if host := normalize(uncomment(line)); host != "" {
			hosts[host] = true
		}
	}
	suffixes := map[string]bool{}
	dnsmasqLines, err := readLines(filepath.Join(root, "dnsmasq-network-split.conf"))
	if err != nil {
		return local, nil, err
	}
	for _, line := range dnsmasqLines {
		if !strings.HasPrefix(line, "server=/") {
			continue
		}
		parts := strings.SplitN(line, "/", 3)
		if len(parts) != 3 {
			return local, nil, fmt.Errorf("malformed dnsmasq server line %q", line)
		}
		if parts[2] == "223.5.5.5" || parts[2] == "119.29.29.29" {
			suffixes[normalize(parts[1])] = true
		}
	}
	domainLines, err := readLines(filepath.Join(root, "domestic_domains.conf"))
	if err != nil {
		return local, nil, err
	}
	for _, line := range domainLines {
		if domain := normalize(uncomment(line)); domain != "" {
			suffixes[domain] = true
		}
	}
	if !suffixes["douyinvod.com"] || !suffixes["cn"] {
		return local, nil, errors.New("incomplete domestic domain policy")
	}
	var networks []string
	for _, name := range []string{"china_ip_list.txt", "domestic_extra_routes.txt"} {
		lines, err := readLines(filepath.Join(root, name))
		if err != nil {
			return local, nil, err
		}
		for _, line := range lines {
			if value := uncomment(line); value != "" {
				prefix, err := policy.ParsePrefix(value)
				if err != nil {
					return local, nil, fmt.Errorf("%s: %q: %w", name, value, err)
				}
				networks = append(networks, prefix.String())
			}
		}
	}
	local.Domain, local.DomainSuffix = sortedKeys(hosts), sortedKeys(suffixes)
	return local, networks, nil
}

// readLines rejects non-ASCII policy text: the engine accepts only ASCII or
// punycode names, so such a file could never be deployed.
func readLines(path string) ([]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	for _, b := range data {
		if b >= 0x80 {
			return nil, fmt.Errorf("%s: policy text must be ASCII", path)
		}
	}
	text := strings.ReplaceAll(strings.ReplaceAll(string(data), "\r\n", "\n"), "\r", "\n")
	return strings.Split(strings.TrimSuffix(text, "\n"), "\n"), nil
}

func uncomment(line string) string {
	value, _, _ := strings.Cut(line, "#")
	return strings.TrimFunc(value, func(r rune) bool { return unicode.IsSpace(r) || (r >= 0x1c && r <= 0x1f) })
}

func normalize(name string) string { return strings.TrimRight(strings.ToLower(name), ".") }

func sortedKeys(set map[string]bool) []string {
	keys := make([]string, 0, len(set))
	for key := range set {
		keys = append(keys, key)
	}
	slices.Sort(keys)
	return keys
}

// FindPolicyDir returns the nearest "config" directory holding the routing
// policy, searching upward from start.
func FindPolicyDir(start string) (string, error) {
	start, err := filepath.Abs(start)
	if err != nil {
		return "", err
	}
	for dir := start; ; dir = filepath.Dir(dir) {
		candidate := filepath.Join(dir, "config")
		if _, err := os.Stat(filepath.Join(candidate, "domestic_domains.conf")); err == nil {
			return candidate, nil
		}
		if filepath.Dir(dir) == dir {
			return "", errors.New("routing policy directory not found; pass -policy-dir")
		}
	}
}
