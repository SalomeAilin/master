//go:build integration

// Integration tests run the compiled engine end to end with isolated fixtures:
// CLI flags, private log rotation, signal handling, rule hot updates and cached
// restart. TestLiveFailClosed also uses the real network and runs only with
// NETWORK_SPLIT_LIVE=1. Run with: go test -tags integration -run Integration .
package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"network-owned-engine/internal/proxyconfig"
)

var engineBinary string

func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "network-engine-integration.")
	if err == nil {
		engineBinary = filepath.Join(dir, "network-domain-engine")
		build := exec.Command("go", "build", "-o", engineBinary, ".")
		build.Stdout, build.Stderr = os.Stdout, os.Stderr
		err = build.Run()
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	code := m.Run()
	os.RemoveAll(dir)
	os.Exit(code)
}

func freePort(t *testing.T) int {
	t.Helper()
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	return listener.Addr().(*net.TCPAddr).Port
}

func candidateConfig(t *testing.T, rules, cache string) proxyconfig.Config {
	t.Helper()
	c, err := proxyconfig.Build("../config", rules, cache)
	if err != nil {
		t.Fatal(err)
	}
	c.Listen = fmt.Sprintf("127.0.0.1:%d", freePort(t))
	return c
}

func writeJSON(t *testing.T, path string, value any) {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
}

func waitFor(t *testing.T, what string, condition func() bool) {
	t.Helper()
	for deadline := time.Now().Add(6 * time.Second); time.Now().Before(deadline); time.Sleep(50 * time.Millisecond) {
		if condition() {
			return
		}
	}
	t.Fatal("timed out waiting for", what)
}

func stopEngine(t *testing.T, command *exec.Cmd, exited <-chan error) error {
	t.Helper()
	command.Process.Signal(syscall.SIGTERM)
	select {
	case err := <-exited:
		return err
	case <-time.After(5 * time.Second):
		command.Process.Kill()
		<-exited
		t.Fatal("engine did not exit on SIGTERM")
		return nil
	}
}

func launchEngine(t *testing.T, args []string, output *os.File) (*exec.Cmd, <-chan error) {
	t.Helper()
	command := exec.Command(engineBinary, args...)
	command.Stdout, command.Stderr = output, output
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	exited := make(chan error, 1)
	go func() { exited <- command.Wait() }()
	return command, exited
}

func TestIntegrationNativeLogsRotateAndSIGTERMExitsCleanly(t *testing.T) {
	root := t.TempDir()
	c := candidateConfig(t, root, filepath.Join(root, "cache"))
	for _, source := range c.RuleSources {
		rule := map[string][]string{"domain": {"fixture.test"}}
		if source.Kind == "china" {
			rule = map[string][]string{"ip_cidr": {"223.5.5.0/24"}}
		}
		writeJSON(t, source.Seed, map[string]any{"version": 2, "rules": []any{rule}})
	}
	config, logPath := filepath.Join(root, "config.json"), filepath.Join(root, "service.log")
	writeJSON(t, config, c)
	args := []string{"run", "--disable-color", "--log-file", logPath, "--log-max-size", "1024", "--log-max-backups", "3", "-c", config}
	output, _ := os.Create(filepath.Join(root, "stderr.log"))
	defer output.Close()
	command, exited := launchEngine(t, args, output)
	waitFor(t, "engine start", func() bool {
		data, _ := os.ReadFile(logPath)
		return strings.Contains(string(data), `"event":"started"`)
	})
	for i := 0; i < 40; i++ {
		connection, err := net.DialTimeout("tcp", c.Listen, 2*time.Second)
		if err != nil {
			t.Fatal(err)
		}
		fmt.Fprint(connection, "CONNECT 127.0.0.1:1 HTTP/1.1\r\nHost: 127.0.0.1:1\r\n\r\n")
		connection.SetReadDeadline(time.Now().Add(2 * time.Second))
		connection.Read(make([]byte, 4096))
		connection.Close()
	}
	time.Sleep(100 * time.Millisecond)
	if err := stopEngine(t, command, exited); err != nil {
		t.Fatal("non-zero exit after SIGTERM:", err)
	}
	logs, _ := filepath.Glob(logPath + "*")
	if len(logs) != 4 {
		t.Fatal(logs)
	}
	rejected := false
	for _, path := range logs {
		info, _ := os.Stat(path)
		if info.Size() > 1024 || info.Mode().Perm() != 0o600 {
			t.Fatal(path, info.Size(), info.Mode())
		}
		data, _ := os.ReadFile(path)
		rejected = rejected || strings.Contains(string(data), `"event":"rejected"`)
	}
	if !rejected {
		t.Fatal("private CONNECT targets were not rejected in the log")
	}
	os.WriteFile(config, []byte("{broken"), 0o600)
	if err := exec.Command(engineBinary, args...).Run(); err == nil {
		t.Fatal("invalid configuration started")
	}
	data, _ := os.ReadFile(logPath)
	if info, _ := os.Stat(logPath); !strings.Contains(string(data), `"event":"startup_failed"`) || info.Size() > 1024 {
		t.Fatalf("startup failure not in bounded log: %q", data)
	}
}

// ruleServer serves the three rule datasets and lets a test replace them.
type ruleServer struct {
	mu   sync.Mutex
	body map[string][]byte
}

func (s *ruleServer) set(kind string, body []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.body[kind] = body
}

func (s *ruleServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	body := s.body[strings.TrimPrefix(r.URL.Path, "/")]
	s.mu.Unlock()
	w.Write(body)
}

type engineEvents struct {
	path string
}

// request returns the events of the engine request made from local port.
func (e engineEvents) request(start int, port int) []map[string]any {
	data, _ := os.ReadFile(e.path)
	var events []map[string]any
	scanner := bufio.NewScanner(bytes.NewReader(data[min(start, len(data)):]))
	for scanner.Scan() {
		var event map[string]any
		if json.Unmarshal(scanner.Bytes(), &event) == nil {
			events = append(events, event)
		}
	}
	var id any
	for _, event := range events {
		if event["event"] == "incoming" && event["from"] == fmt.Sprintf("127.0.0.1:%d", port) {
			id = event["id"]
			break
		}
	}
	var matched []map[string]any
	for _, event := range events {
		if id != nil && event["id"] == id {
			matched = append(matched, event)
		}
	}
	return matched
}

func (e engineEvents) size() int {
	info, err := os.Stat(e.path)
	if err != nil {
		return 0
	}
	return int(info.Size())
}

func connectThrough(t *testing.T, listen, name string) int {
	t.Helper()
	connection, err := net.DialTimeout("tcp", listen, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	fmt.Fprintf(connection, "CONNECT %s:443 HTTP/1.1\r\nHost: %s:443\r\n\r\n", name, name)
	connection.SetReadDeadline(time.Now().Add(5 * time.Second))
	response, _ := bufio.NewReader(connection).ReadString('\n')
	if name != "private-rebind.test" && !strings.HasPrefix(response, "HTTP/1.1 502") {
		t.Fatalf("%s: %q", name, response)
	}
	return connection.LocalAddr().(*net.TCPAddr).Port
}

func TestIntegrationAutomaticClassificationHotUpdatesAndCachedRestart(t *testing.T) {
	rules := &ruleServer{body: map[string][]byte{
		"domestic": []byte(`{"version":2,"rules":[{"domain":["listed-cn.test"]}]}`),
		"foreign":  []byte(`{"version":2,"rules":[{"domain":["listed-foreign.test"]}]}`),
		"china":    []byte(`{"version":2,"rules":[{"ip_cidr":["223.5.5.0/24"]}]}`),
	}}
	server := httptest.NewServer(rules)
	defer server.Close()
	root := t.TempDir()
	c := candidateConfig(t, root, filepath.Join(root, "cache"))
	c.ChinaCIDR = []string{}
	names := map[string][]string{
		"github.com": {"223.5.5.5"}, "www.douyin.com": {"1.1.1.1"},
		"listed-cn.test": {"1.1.1.1"}, "listed-foreign.test": {"223.5.5.5"},
		"unknown-cn.test": {"223.5.5.5"}, "unknown-foreign.test": {"1.1.1.1"},
		"updated-cn.test": {"1.1.1.1"}, "private-rebind.test": {"127.0.0.1"},
	}
	// Missing interfaces expose the chosen outbound without sending traffic.
	c.Domestic = proxyconfig.Egress{Interface: "en998", DNS: proxyconfig.DNS{Hosts: names}}
	c.Foreign = proxyconfig.Egress{Interface: "en999", DNS: proxyconfig.DNS{Hosts: names}}
	for i, source := range c.RuleSources {
		os.WriteFile(source.Seed, rules.body[source.Kind], 0o600)
		c.RuleSources[i].URL, c.RuleSources[i].Interval = server.URL+"/"+source.Kind, "500ms"
	}
	config := filepath.Join(root, "config.json")
	writeJSON(t, config, c)
	if output, err := exec.Command(engineBinary, "check", "-c", config).CombinedOutput(); err != nil {
		t.Fatalf("check: %v %s", err, output)
	}
	events := engineEvents{path: filepath.Join(root, "output.log")}

	run := func(cached bool) {
		output, _ := os.Create(events.path)
		defer output.Close()
		command, exited := launchEngine(t, []string{"run", "-c", config}, output)
		defer stopEngine(t, command, exited)
		waitFor(t, "engine start", func() bool {
			data, _ := os.ReadFile(events.path)
			return strings.Contains(string(data), `"event":"started"`)
		})
		check := func(name, kind string) {
			start := events.size()
			port := connectThrough(t, c.Listen, name)
			waitFor(t, name+" -> "+kind, func() bool {
				for _, event := range events.request(start, port) {
					if event["event"] == "route" && event["outbound"] == kind && event["target"] == name+":443" {
						return true
					}
				}
				return false
			})
		}
		for _, test := range [][2]string{{"github.com", "foreign"}, {"www.douyin.com", "domestic"},
			{"listed-cn.test", "domestic"}, {"listed-foreign.test", "foreign"},
			{"unknown-cn.test", "domestic"}, {"unknown-foreign.test", "foreign"}} {
			check(test[0], test[1])
		}
		start := events.size()
		port := connectThrough(t, c.Listen, "private-rebind.test")
		waitFor(t, "private answer rejection", func() bool {
			for _, event := range events.request(start, port) {
				if event["event"] == "rejected" {
					return true
				}
			}
			return false
		})
		for _, event := range events.request(start, port) {
			if event["event"] == "route" {
				t.Fatal("private DNS answer reached an outbound dial")
			}
		}
		if cached {
			check("updated-cn.test", "domestic")
			return
		}
		check("updated-cn.test", "foreign")
		rules.set("domestic", []byte(`{"version":2,"rules":[{"domain":["listed-cn.test","updated-cn.test"]}]}`))
		time.Sleep(1500 * time.Millisecond)
		check("updated-cn.test", "domestic")
		rules.set("domestic", []byte("corrupt-not-json"))
		waitFor(t, "rejected corrupt update", func() bool {
			data, _ := os.ReadFile(events.path)
			return strings.Contains(string(data), "rule_update_failed")
		})
		check("updated-cn.test", "domestic")
	}
	run(false)
	server.Close()
	for _, source := range c.RuleSources {
		os.Remove(source.Seed)
	}
	run(true) // update server and seeds unavailable: the private cache must serve
}

// TestLiveFailClosed breaks only the candidate's foreign interface: foreign
// access must fail while domestic DoH and access keep working.
func TestIntegrationLiveFailClosed(t *testing.T) {
	if os.Getenv("NETWORK_SPLIT_LIVE") != "1" {
		t.Skip("set NETWORK_SPLIT_LIVE=1 to use the real network")
	}
	seeds := os.Getenv("NETWORK_SPLIT_RULES")
	if seeds == "" {
		seeds = proxyconfig.RulesDirectory
	}
	root := t.TempDir()
	c := candidateConfig(t, seeds, filepath.Join(root, "cache"))
	c.Foreign.Interface = "en999"
	config := filepath.Join(root, "config.json")
	writeJSON(t, config, c)
	output, _ := os.Create(filepath.Join(root, "output.log"))
	defer output.Close()
	command, exited := launchEngine(t, []string{"run", "-c", config}, output)
	defer stopEngine(t, command, exited)
	waitFor(t, "listener", func() bool {
		connection, err := net.DialTimeout("tcp", c.Listen, 100*time.Millisecond)
		if err == nil {
			connection.Close()
		}
		return err == nil
	})
	proxy, _ := url.Parse("http://" + c.Listen)
	client := &http.Client{Timeout: 12 * time.Second, Transport: &http.Transport{Proxy: http.ProxyURL(proxy)}}
	if response, err := client.Get("https://github.com/"); err == nil {
		response.Body.Close()
		t.Fatal("foreign connection escaped the invalid pinned interface")
	}
	// Any certificate-verified HTTP response proves the domestic path; the
	// site's status for a non-browser client is not under test.
	response, err := client.Get("https://www.douyin.com/")
	if err != nil {
		t.Fatal("domestic access failed:", err)
	}
	t.Log("domestic status", response.Status)
	response.Body.Close()
	data, _ := os.ReadFile(filepath.Join(root, "output.log"))
	if !strings.Contains(string(data), "no such network interface") {
		t.Fatalf("%s", data)
	}
}
