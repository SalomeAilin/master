package wiredguard

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"
)

func TestDarwinGroupSlotZeroIsTheOnlyPrimaryReplacement(t *testing.T) {
	var raw []string
	for i := 0; i < 15; i++ {
		raw = append(raw, fmt.Sprint(100+i))
	}
	raw = append(raw, "20") // Account APIs need not put the primary group first.
	groups, err := accountGroups(20, raw)
	if err != nil {
		t.Fatal(err)
	}
	if len(groups) != 16 || groups[0] != 20 {
		t.Fatal(groups)
	}
	groups[0] = 62000 // Darwin setgid replaces slot zero after setgroups.
	for i := 0; i < 15; i++ {
		if !slices.Contains(groups, uint32(100+i)) {
			t.Fatal("supplementary group lost", groups)
		}
	}
	if slices.Contains(groups, uint32(20)) {
		t.Fatal("old primary was silently added as a seventeenth group")
	}
	if _, err = accountGroups(20, append(raw, "999")); err == nil {
		t.Fatal("group overflow accepted")
	}
}

func TestProxyReadinessRequiresProtocolResponse(t *testing.T) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	// A bound, listening parent socket alone completes TCP handshakes.
	if err = proxyReady(listener.Addr().String()); err == nil {
		listener.Close()
		t.Fatal("TCP handshake was mistaken for a live proxy")
	}
	listener.Close()
	for _, answer := range [][2]byte{{5, 0}, {5, 255}} {
		listener, err = net.Listen("tcp4", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		done := make(chan struct{})
		go func() {
			defer close(done)
			connection, e := listener.Accept()
			if e != nil {
				return
			}
			defer connection.Close()
			connection.SetDeadline(time.Now().Add(time.Second))
			var greeting [3]byte
			connection.Read(greeting[:])
			connection.Write(answer[:])
		}()
		err = proxyReady(listener.Addr().String())
		listener.Close()
		<-done
		if (err == nil) != (answer == [2]byte{5, 0}) {
			t.Fatalf("greeting response %v: %v", answer, err)
		}
	}
}

func TestProxyConfigurationBindsTheSelectedWiredInterfaceAndHasNoExternalUpdates(t *testing.T) {
	var c struct {
		Domestic, Foreign struct {
			Interface string
			DNS       struct {
				Address    string
				ServerName string `json:"server_name"`
			}
		}
		Sources []struct{ URL, Interval string } `json:"rule_sources"`
	}
	if err := json.Unmarshal(proxyConfiguration("/private/tmp/worker", "en7"), &c); err != nil {
		t.Fatal(err)
	}
	if c.Domestic.Interface != "en7" || c.Foreign.Interface != "en999" {
		t.Fatal(c)
	}
	if c.Domestic.DNS.Address != "223.5.5.5" || c.Domestic.DNS.ServerName != "dns.alidns.com" {
		t.Fatal("unexpected DoH endpoint", c.Domestic)
	}
	if len(c.Sources) != 3 {
		t.Fatal(c)
	}
	for _, source := range c.Sources {
		if source.URL != "http://127.0.0.1:1/disabled" || source.Interval != "168h" {
			t.Fatal(source)
		}
	}
}

func TestCacheCleanupDoesNotFollowASymlinkOrDeleteUnexpectedUserData(t *testing.T) {
	outside := t.TempDir()
	file := filepath.Join(outside, "proxy.log")
	if err := os.WriteFile(file, []byte("keep"), 0600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(t.TempDir(), "cache")
	if err := os.Symlink(outside, link); err != nil {
		t.Fatal(err)
	}
	if err := removeCache(link); err == nil {
		t.Fatal("symlink accepted as cache")
	}
	if data, err := os.ReadFile(file); err != nil || string(data) != "keep" {
		t.Fatal("outside data changed", err)
	}
	if err := removeCache(outside); err == nil {
		t.Fatal("ordinary user's directory accepted as root-owned cache")
	}
}
