package proxyconfig

import (
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

const repositoryPolicy = "../../../config"

func build(t *testing.T) Config {
	t.Helper()
	c, err := Build(repositoryPolicy, "", "")
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func domestic(c Config, name string) bool {
	if slices.Contains(c.Local.Domain, name) {
		return true
	}
	for _, suffix := range c.Local.DomainSuffix {
		if name == suffix || strings.HasSuffix(name, "."+suffix) {
			return true
		}
	}
	return false
}

func TestMediaAndForeignCDNKeepDomainClassification(t *testing.T) {
	c := build(t)
	for _, name := range []string{"v26-web-prime.douyinvod.com", "billing.console.aliyun.com", "player-gw-s.aliyuncs.com",
		"api.smoot.apple.cn", "vc-gate-edge.ndcpp.com", "lf-cdn-tos.bytescm.com"} {
		if !domestic(c, name) {
			t.Error("not domestic:", name)
		}
	}
}

func TestForeignAndSuffixConfusion(t *testing.T) {
	c := build(t)
	for _, name := range []string{"github.com", "claude.ai", "douyin.com.attacker.test", "notdouyin.com",
		"other.ndcpp.com", "tiktok.com", "x.vc-gate-edge.ndcpp.com"} {
		if domestic(c, name) {
			t.Error("domestic:", name)
		}
	}
}

func TestInterfacesAreSeparateWithoutFallback(t *testing.T) {
	c := build(t)
	if c.Foreign.Interface != "en1" || c.Domestic.Interface != "en0" || c.Listen != "127.0.0.1:17890" {
		t.Fatalf("%+v", c)
	}
	data, _ := Encode(c)
	if strings.Contains(string(data), "fallback") || strings.Contains(string(data), "hosts") {
		t.Fatal("production configuration has a fallback or fixture DNS")
	}
}

func TestKnownForeignIsProtectedFromIPInference(t *testing.T) {
	c := build(t)
	for _, domain := range []string{"github.com", "claude.ai", "tiktok.com", "google.com"} {
		if !slices.Contains(c.Protected.DomainSuffix, domain) {
			t.Error("not protected:", domain)
		}
	}
	contains := func(ip string) bool {
		for _, value := range c.ChinaCIDR {
			if netip.MustParsePrefix(value).Contains(netip.MustParseAddr(ip)) {
				return true
			}
		}
		return false
	}
	if !contains("223.5.5.5") || contains("1.1.1.1") {
		t.Fatal("China address list misclassified a resolver")
	}
}

func TestJSONRuleDataIsCachedWithoutAnEngineDependency(t *testing.T) {
	c := build(t)
	var kinds []string
	for _, source := range c.RuleSources {
		kinds = append(kinds, source.Kind)
		if !strings.HasPrefix(source.URL, "https://") || !strings.HasSuffix(source.URL, ".json") ||
			source.Interval != "1h" || !strings.HasPrefix(source.Seed, RulesDirectory+"/") {
			t.Errorf("%+v", source)
		}
	}
	if !slices.Equal(kinds, []string{"domestic", "foreign", "china"}) || c.CacheDirectory != CacheDirectory {
		t.Fatal(kinds, c.CacheDirectory)
	}
}

func TestDoHEndpointsAreLiteralsWithCertificateNames(t *testing.T) {
	c := build(t)
	for _, want := range []struct {
		egress        Egress
		address, name string
	}{{c.Domestic, "223.5.5.5", "dns.alidns.com"}, {c.Foreign, "1.1.1.1", "cloudflare-dns.com"}} {
		if want.egress.DNS.Address != want.address || want.egress.DNS.ServerName != want.name || want.egress.DNS.Hosts != nil {
			t.Fatalf("%+v", want.egress.DNS)
		}
	}
}

func TestEncodingMatchesInstalledFormat(t *testing.T) {
	data, err := Encode(Config{Version: 1, Local: Local{Domain: []string{}, DomainSuffix: []string{"a"}}})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(string(data), "{\n  \"version\": 1,\n  \"listen\": \"\",") ||
		!strings.Contains(string(data), "\"domain\": [],\n    \"domain_suffix\": [\n      \"a\"\n    ]") ||
		!strings.HasSuffix(string(data), "}\n") {
		t.Fatalf("%s", data)
	}
}

func TestPolicyErrorsAreReported(t *testing.T) {
	for name, edit := range map[string]func(dir string){
		"missing douyinvod": func(dir string) {
			os.WriteFile(filepath.Join(dir, "domestic_domains.conf"), []byte("cn\n"), 0644)
			os.WriteFile(filepath.Join(dir, "dnsmasq-network-split.conf"), []byte("no-resolv\n"), 0644)
		},
		"host bits": func(dir string) {
			os.WriteFile(filepath.Join(dir, "domestic_extra_routes.txt"), []byte("1.2.3.4/24\n"), 0644)
		},
		"non-ASCII": func(dir string) {
			os.WriteFile(filepath.Join(dir, "domestic_proxy_hosts.conf"), []byte("\xe4\xbe\x8b.cn\n"), 0644)
		},
		"truncated server line": func(dir string) {
			os.WriteFile(filepath.Join(dir, "dnsmasq-network-split.conf"), []byte("server=/example\n"), 0644)
		},
	} {
		dir := t.TempDir()
		for _, file := range []string{"domestic_proxy_hosts.conf", "dnsmasq-network-split.conf", "domestic_domains.conf",
			"china_ip_list.txt", "domestic_extra_routes.txt"} {
			data, err := os.ReadFile(filepath.Join(repositoryPolicy, file))
			if err != nil {
				t.Fatal(err)
			}
			os.WriteFile(filepath.Join(dir, file), data, 0644)
		}
		edit(dir)
		if _, err := Build(dir, "", ""); err == nil {
			t.Error(name, "accepted")
		}
	}
}

func TestFindPolicyDirSearchesUpward(t *testing.T) {
	dir, err := FindPolicyDir(".")
	if absolute, _ := filepath.Abs(repositoryPolicy); err != nil || dir != absolute {
		t.Fatal(dir, err)
	}
	if _, err := FindPolicyDir(t.TempDir()); err == nil {
		t.Fatal("found a policy directory outside the repository")
	}
}
