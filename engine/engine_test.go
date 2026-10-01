package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func fixtureConfig(t *testing.T) Config {
	t.Helper()
	dir := t.TempDir()
	c := Config{Version: 1, Listen: "127.0.0.1:17890", MaxClients: 16, CacheDir: filepath.Join(dir, "cache"),
		Domestic:  Egress{Interface: "lo0", DNS: DNSConfig{Hosts: map[string][]string{"unused.test": {"1.1.1.1"}}}},
		Foreign:   Egress{Interface: "en999", DNS: DNSConfig{Hosts: map[string][]string{"unused.test": {"1.1.1.1"}}}},
		Protected: DomainRules{Suffix: []string{"github.com"}}, Local: DomainRules{Suffix: []string{"douyin.com"}}}
	if err := os.Mkdir(c.CacheDir, 0700); err != nil {
		t.Fatal(err)
	}
	for kind, rule := range map[string]DomainRules{"domestic": {Suffix: []string{"listed-cn.test"}}, "foreign": {Suffix: []string{"listed-foreign.test"}}, "china": {CIDR: []string{"223.5.5.0/24"}}} {
		data, _ := json.Marshal(map[string]any{"version": 2, "rules": []DomainRules{rule}})
		path := filepath.Join(dir, kind+".json")
		if err := os.WriteFile(path, data, 0600); err != nil {
			t.Fatal(err)
		}
		c.Sources = append(c.Sources, RuleSource{Kind: kind, Seed: path, URL: "https://example.com/" + kind, Interval: "1h"})
	}
	return c
}

func fixtureEngine(t *testing.T) *engine {
	t.Helper()
	e, err := newEngine(fixtureConfig(t), &eventLog{writer: io.Discard})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(e.close)
	return e
}

func TestPolicyPrecedenceAndMixedAnswers(t *testing.T) {
	e := fixtureEngine(t)
	queries := []string{}
	e.domestic = func(_ context.Context, host string) ([]netip.Addr, error) {
		queries = append(queries, "domestic:"+host)
		return []netip.Addr{netip.MustParseAddr("223.5.5.5"), netip.MustParseAddr("1.1.1.1")}, nil
	}
	e.foreign = func(_ context.Context, host string) ([]netip.Addr, error) {
		queries = append(queries, "foreign:"+host)
		return []netip.Addr{netip.MustParseAddr("223.5.5.5")}, nil
	}
	for _, test := range []struct {
		host, kind, resolver string
		addresses            int
	}{
		{"cdn.github.com", "foreign", "foreign", 1},
		{"video.douyin.com", "domestic", "domestic", 2},
		{"listed-cn.test", "domestic", "domestic", 2},
		{"listed-foreign.test", "foreign", "foreign", 1},
		{"unknown.test", "domestic", "domestic", 1},
	} {
		t.Run(test.host, func(t *testing.T) {
			p, err := e.resolve(context.Background(), test.host+":443")
			if err != nil || p.kind != test.kind || len(p.ips) != test.addresses {
				t.Fatalf("plan=%+v error=%v", p, err)
			}
			if !strings.HasPrefix(queries[len(queries)-1], test.resolver+":") {
				t.Fatal(queries)
			}
		})
	}
	e.domestic = func(context.Context, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("1.1.1.1"), netip.MustParseAddr("223.5.5.5")}, nil
	}
	p, err := e.resolve(context.Background(), "unknown.test:443")
	if err != nil || p.kind != "foreign" || len(p.ips) != 1 || p.ips[0].String() != "1.1.1.1" {
		t.Fatalf("%+v %v", p, err)
	}
}

func TestIPGroupingUsesOneHotUpdateSnapshot(t *testing.T) {
	e := fixtureEngine(t)
	all, err := compileRules(DomainRules{CIDR: []string{"8.8.8.0/24", "1.1.1.0/24"}})
	if err != nil {
		t.Fatal(err)
	}
	none, err := compileRules(DomainRules{})
	if err != nil {
		t.Fatal(err)
	}
	e.domestic = func(context.Context, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("8.8.8.8"), netip.MustParseAddr("1.1.1.1")}, nil
	}
	var updates sync.WaitGroup
	updates.Add(1)
	defer updates.Wait()
	go func() {
		defer updates.Done()
		for i := 0; i < 20000; i++ {
			e.rules.mu.Lock()
			e.rules.sets["china"] = all
			if i%2 == 0 {
				e.rules.sets["china"] = none
			}
			e.rules.mu.Unlock()
		}
	}()
	for i := 0; i < 20000; i++ {
		p, err := e.resolve(context.Background(), "unknown.test:443")
		if err != nil || len(p.ips) != 2 {
			t.Fatalf("answers grouped using inconsistent snapshots: %+v %v", p, err)
		}
	}
}

func TestPrivateRebindingAndAddressValidation(t *testing.T) {
	e := fixtureEngine(t)
	for _, address := range []string{"127.0.0.1", "192.168.1.1", "169.254.169.254", "0.0.0.0", "224.0.0.1", "::1"} {
		e.domestic = func(context.Context, string) ([]netip.Addr, error) {
			return []netip.Addr{netip.MustParseAddr("1.1.1.1"), netip.MustParseAddr(address)}, nil
		}
		if _, err := e.resolve(context.Background(), "video.douyin.com:443"); err == nil {
			t.Fatal("private DNS answer accepted", address)
		}
		if _, err := e.resolve(context.Background(), net.JoinHostPort(address, "443")); err == nil {
			t.Fatal("private literal accepted", address)
		}
	}
	for _, address := range []string{"host:0", "host:65536", "host:bad", "host:443/path", "user@host:443", "a..com:80"} {
		if _, err := parseTarget(address); err == nil {
			t.Fatal("invalid target accepted", address)
		}
	}
}

func TestCorruptUpdateRetainsRulesAndCachedRestart(t *testing.T) {
	c := fixtureConfig(t)
	rules, err := newRules(c)
	if err != nil {
		t.Fatal(err)
	}
	data := []byte(`{"version":2,"rules":[{"domain_suffix":["new-cn.test"]}]}`)
	if err := rules.apply("domestic", data); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{`garbage`, `{"version":2,"rules":[]}`, `{"version":2,"rules":[{"unexpected":true}]}`} {
		if err := rules.apply("domestic", []byte(bad)); err == nil {
			t.Fatal("corrupt update accepted")
		}
		if rules.domain("new-cn.test") != "domestic" {
			t.Fatal("last good rules lost")
		}
	}
	for _, source := range c.Sources {
		if source.Kind == "domestic" {
			os.Remove(source.Seed)
		}
	}
	restarted, err := newRules(c)
	if err != nil || restarted.domain("new-cn.test") != "domestic" {
		t.Fatalf("cached restart: %v", err)
	}
	info, err := os.Stat(filepath.Join(c.CacheDir, "domestic.json"))
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatal("cache must be private", err)
	}
}

func TestRuleFormatsAndBoundary(t *testing.T) {
	m, err := compileRules(DomainRules{Domain: []string{"exact.test"}, Suffix: []string{"suffix.test"}, Keyword: []string{"needle"}, Regex: []string{`^video\d+\.test$`}, CIDR: []string{"223.5.5.0/24"}})
	if err != nil {
		t.Fatal(err)
	}
	for _, host := range []string{"exact.test", "suffix.test", "a.suffix.test", "needle.test", "video12.test"} {
		if !m.domain(host) {
			t.Fatal("missing rule", host)
		}
	}
	if m.domain("badsuffix.test") || m.domain("a.exact.test") || !m.ip(netip.MustParseAddr("223.5.5.5")) || m.ip(netip.MustParseAddr("1.1.1.1")) {
		t.Fatal("rule boundary failure")
	}
}

func TestStrictConfig(t *testing.T) {
	c := fixtureConfig(t)
	if err := c.validate(); err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*Config){func(c *Config) { c.Listen = "0.0.0.0:17890" }, func(c *Config) { c.Foreign.Interface = "" }, func(c *Config) { c.Version = 99 }, func(c *Config) { c.Sources[0].URL = "http://example.com/rules" }, func(c *Config) { c.CacheDir = "relative" }} {
		copy := c
		copy.Sources = append([]RuleSource{}, c.Sources...)
		mutate(&copy)
		if copy.validate() == nil {
			t.Fatal("invalid configuration accepted")
		}
	}
	var decoded Config
	if decodeJSON([]byte(`{"version":1,"ignored":true}`), &decoded) == nil || decodeJSON([]byte(`{} {}`), &decoded) == nil {
		t.Fatal("unrecognized JSON accepted")
	}
}

func echoServer(t *testing.T) net.Listener {
	t.Helper()
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { listener.Close() })
	go func() {
		for {
			c, err := listener.Accept()
			if err != nil {
				return
			}
			go func() { defer c.Close(); io.Copy(c, c) }()
		}
	}()
	return listener
}

func proxyFixture(t *testing.T, e *engine) string {
	t.Helper()
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- e.serve(ctx, listener) }()
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Error(err)
			}
		case <-time.After(3 * time.Second):
			t.Error("proxy failed bounded shutdown")
			listener.Close()
		}
	})
	return listener.Addr().String()
}

func mapTestDial(e *engine, address string) {
	e.domestic = func(context.Context, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("223.5.5.5")}, nil
	}
	e.foreign = func(context.Context, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("1.1.1.1")}, nil
	}
	e.dial = func(ctx context.Context, _ string, _ []netip.Addr, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "tcp4", address)
	}
}

func TestCONNECTPreservesBufferedTunnelBytes(t *testing.T) {
	e := fixtureEngine(t)
	echo := echoServer(t)
	mapTestDial(e, echo.Addr().String())
	address := proxyFixture(t, e)
	client, err := net.Dial("tcp4", address)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	client.SetDeadline(time.Now().Add(3 * time.Second))
	client.Write([]byte("CONNECT video.douyin.com:443 HTTP/1.1\r\nHost: video.douyin.com:443\r\n\r\npipelined-tls-bytes"))
	reader := bufio.NewReader(client)
	response, err := http.ReadResponse(reader, &http.Request{Method: "CONNECT"})
	if err != nil || response.StatusCode != 200 {
		t.Fatalf("CONNECT response: %v %v", response, err)
	}
	data := make([]byte, len("pipelined-tls-bytes"))
	if _, err := io.ReadFull(reader, data); err != nil || string(data) != "pipelined-tls-bytes" {
		t.Fatalf("lost buffered data %q %v", data, err)
	}
}

func TestSOCKSAndUnsupportedCommands(t *testing.T) {
	e := fixtureEngine(t)
	echo := echoServer(t)
	mapTestDial(e, echo.Addr().String())
	address := proxyFixture(t, e)
	for _, command := range []byte{1, 3} {
		client, err := net.Dial("tcp4", address)
		if err != nil {
			t.Fatal(err)
		}
		client.SetDeadline(time.Now().Add(3 * time.Second))
		client.Write([]byte{5, 1, 0})
		greeting := make([]byte, 2)
		io.ReadFull(client, greeting)
		if !bytes.Equal(greeting, []byte{5, 0}) {
			t.Fatal(greeting)
		}
		host := "video.douyin.com"
		request := append([]byte{5, command, 0, 3, byte(len(host))}, []byte(host)...)
		request = append(request, 1, 187)
		client.Write(request)
		reply := make([]byte, 10)
		if _, err := io.ReadFull(client, reply); err != nil {
			t.Fatal(err)
		}
		if command == 3 {
			if reply[1] != 7 {
				t.Fatal("UDP command silently accepted")
			}
			client.Close()
			continue
		}
		if reply[1] != 0 {
			t.Fatal(reply)
		}
		client.Write([]byte("socks-data"))
		data := make([]byte, 10)
		if _, err := io.ReadFull(client, data); err != nil || string(data) != "socks-data" {
			t.Fatal(string(data), err)
		}
		client.Close()
	}
}

func TestHTTPForwardingPayloadAndHopHeaders(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Proxy-Authorization") != "" || r.Header.Get("X-Private-Hop") != "" {
			t.Error("proxy credentials or hop header leaked")
		}
		body, _ := io.ReadAll(r.Body)
		if r.Method != "POST" || string(body) != "request-body" {
			t.Error("request altered")
		}
		w.Header().Set("Content-Type", "text/plain")
		w.Header().Set("Content-Range", "bytes 0-11/12")
		w.WriteHeader(206)
		w.Write([]byte("response-body"))
	}))
	defer target.Close()
	e := fixtureEngine(t)
	mapTestDial(e, strings.TrimPrefix(target.URL, "http://"))
	address := proxyFixture(t, e)
	client, err := net.Dial("tcp4", address)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	client.SetDeadline(time.Now().Add(3 * time.Second))
	fmt.Fprint(client, "POST http://VIDEO.DOUYIN.COM/range HTTP/1.1\r\nHost: VIDEO.DOUYIN.COM\r\nContent-Length: 12\r\nProxy-Authorization: sensitive\r\nConnection: X-Private-Hop, close\r\nX-Private-Hop: secret\r\n\r\nrequest-body")
	response, err := http.ReadResponse(bufio.NewReader(client), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	data, err := io.ReadAll(response.Body)
	if err != nil || response.StatusCode != 206 || string(data) != "response-body" || response.Header.Get("Content-Range") == "" {
		t.Fatalf("forwarded response: %q %v", data, err)
	}
}

func TestDoHUsesStandardDNSValidation(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		query, _ := io.ReadAll(r.Body)
		if len(query) < 17 {
			t.Error("invalid DNS query")
			http.Error(w, "bad", 400)
			return
		}
		end := 12
		for query[end] != 0 {
			end += 1 + int(query[end])
			if end >= len(query) {
				t.Error("bad DNS name")
				return
			}
		}
		end += 5
		answer := append([]byte{}, query[:end]...)
		binary.BigEndian.PutUint16(answer[2:4], 0x8180)
		binary.BigEndian.PutUint16(answer[6:8], 1)
		binary.BigEndian.PutUint16(answer[10:12], 0)
		answer = append(answer, 0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 0, 0, 4, 223, 5, 5, 5)
		w.Header().Set("Content-Type", "application/dns-message")
		w.Write(answer)
	}))
	defer server.Close()
	resolver := &net.Resolver{PreferGo: true, StrictErrors: true, Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return &dohStream{ctx: ctx, client: server.Client(), url: server.URL}, nil
	}}
	ips, err := resolver.LookupNetIP(context.Background(), "ip4", "fixture.invalid.")
	if err != nil || len(ips) != 1 || ips[0].String() != "223.5.5.5" {
		t.Fatalf("DoH lookup: %v %v", ips, err)
	}
	stream := &dohStream{ctx: context.Background(), client: server.Client(), url: server.URL}
	if _, err := stream.Write([]byte{0, 3, 1}); err == nil {
		t.Fatal("invalid framed DNS accepted")
	}
	stream.Close()
	if _, err := stream.Read(make([]byte, 1)); err == nil {
		t.Fatal("closed DNS stream readable")
	}
}

func TestCleartextUpgradePreservesBufferedBytes(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Upgrade") != "websocket" {
			t.Error("upgrade header lost")
		}
		conn, buffer, err := w.(http.Hijacker).Hijack()
		if err != nil {
			t.Error(err)
			return
		}
		defer conn.Close()
		buffer.WriteString("HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n")
		buffer.Flush()
		data := make([]byte, 7)
		if _, err := io.ReadFull(buffer.Reader, data); err != nil {
			t.Error(err)
			return
		}
		conn.Write(data)
	}))
	defer target.Close()
	e := fixtureEngine(t)
	mapTestDial(e, strings.TrimPrefix(target.URL, "http://"))
	address := proxyFixture(t, e)
	client, err := net.Dial("tcp4", address)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	client.SetDeadline(time.Now().Add(3 * time.Second))
	fmt.Fprint(client, "GET http://video.douyin.com/ws HTTP/1.1\r\nHost: video.douyin.com\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\nws-data")
	reader := bufio.NewReader(client)
	response, err := http.ReadResponse(reader, nil)
	if err != nil || response.StatusCode != 101 {
		t.Fatalf("upgrade response: %v %v", response, err)
	}
	data := make([]byte, 7)
	if _, err := io.ReadFull(reader, data); err != nil || string(data) != "ws-data" {
		t.Fatalf("upgrade payload: %q %v", data, err)
	}
}

func TestNativeLogBoundsAndSymlinks(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "service.log")
	log, err := openPrivateLog(path, 1024, 3)
	if err != nil {
		t.Fatal(err)
	}
	var writers sync.WaitGroup
	for i := 0; i < 8; i++ {
		writers.Add(1)
		go func() {
			defer writers.Done()
			for j := 0; j < 100; j++ {
				if _, err := log.Write([]byte(strings.Repeat("x", 140) + "\n")); err != nil {
					t.Error(err)
				}
			}
		}()
	}
	writers.Wait()
	if _, err := log.Write([]byte(strings.Repeat("z", 4096))); err != nil {
		t.Fatal(err)
	}
	log.Close()
	files, _ := filepath.Glob(path + "*")
	if len(files) != 4 {
		t.Fatal(files)
	}
	for _, file := range files {
		info, err := os.Stat(file)
		if err != nil || info.Size() > 1024 || info.Mode().Perm() != 0600 {
			t.Fatal("log bound/privacy", file, info, err)
		}
	}
	if _, err := log.Write([]byte("closed")); err == nil {
		t.Fatal("closed logger writable")
	}
	os.Remove(path)
	os.Symlink(filepath.Join(dir, "service.log.1"), path)
	if _, err := openPrivateLog(path, 1024, 3); err == nil {
		t.Fatal("symlink accepted")
	}
}

func TestKernelInterfaceConstraint(t *testing.T) {
	if testing.Short() {
		t.Skip("kernel socket test")
	}
	echo := echoServer(t)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if c, err := interfaceDial(ctx, "en999", echo.Addr().String()); err == nil {
		c.Close()
		t.Fatal("invalid interface fell back")
	}
	c, err := interfaceDial(ctx, "lo0", echo.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	c.Close()
}
