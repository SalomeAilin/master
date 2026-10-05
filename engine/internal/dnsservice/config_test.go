package dnsservice

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const policyFixture = `port=53
listen-address=127.0.0.1,192.0.2.10
bind-interfaces
no-resolv
filter-AAAA
domain-needed
bogus-priv
stop-dns-rebind
dns-loop-detect
local-service
cache-size=10000
server=1.1.1.1
server=/cn/223.5.5.5
server=/example.cn/119.29.29.29
log-queries=extra
log-facility=/var/log/network-split-dns-query.log
max-ttl=60
max-cache-ttl=60
`

func TestPolicyPreservesLimitsAndLongestSuffix(t *testing.T) {
	c, err := Parse([]byte(policyFixture))
	if err != nil {
		t.Fatal(err)
	}
	if c.Port != 53 || c.CacheEntries != 10000 || c.MaxTTL != 60 || c.CacheTTL != 60 || len(c.Listen) != 2 {
		t.Fatal(c)
	}
	for name, want := range map[string]string{"www.any.cn": "223.5.5.5", "WWW.EXAMPLE.CN.": "119.29.29.29", "example.cn.evil.test": "1.1.1.1", "notexample.cn": "223.5.5.5"} {
		servers, domestic := c.Select(name)
		if len(servers) != 1 || servers[0].String() != want || domestic != (want != "1.1.1.1") {
			t.Fatal(name, servers, domestic)
		}
	}
}

func TestPolicyRejectsUnsupportedOrWeakenedSettings(t *testing.T) {
	for _, data := range []string{policyFixture + "dhcp-range=192.0.2.1,192.0.2.10\n", strings.ReplaceAll(policyFixture, "stop-dns-rebind\n", ""), strings.ReplaceAll(policyFixture, "cache-size=10000", "cache-size=999999"), strings.ReplaceAll(policyFixture, "server=1.1.1.1", "server=127.0.0.1"), strings.ReplaceAll(policyFixture, "/cn/", "/*cn/"), policyFixture + "port=5353\n", strings.ReplaceAll(policyFixture, "listen-address=127.0.0.1,192.0.2.10", "listen-address=0.0.0.0")} {
		if _, err := Parse([]byte(data)); err == nil {
			t.Fatal("unsafe policy accepted", data)
		}
	}
}

func TestRepositoryDNSPolicyCanBeMigrated(t *testing.T) {
	data, err := os.ReadFile("../../../config/dnsmasq-network-split.conf")
	if err != nil {
		t.Fatal(err)
	}
	c, err := Parse(data)
	if err != nil {
		t.Fatal(err)
	}
	if c.Port != 53 || len(c.Servers) != 3 || c.MaxTTL != 60 || c.CacheTTL != 60 {
		t.Fatal("repository policy changed", c)
	}
}

func TestPolicyLoaderRejectsLinksAndWritableInputs(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policy")
	if err := os.WriteFile(path, []byte(policyFixture), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(link); err == nil {
		t.Fatal("symlink accepted")
	}
	os.Remove(link)
	if err := os.Link(path, link); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil {
		t.Fatal("hardlinked policy accepted")
	}
	os.Remove(link)
	os.Chmod(path, 0o666)
	if _, err := Load(path); err == nil {
		t.Fatal("writable policy accepted")
	}
}
