// Command network-domain-proxy-evidence collects read-only live evidence of
// the production proxy's egress: for each probe it holds a certificate-verified
// TLS connection through the proxy while it lists the engine's new kernel
// sockets. Socket ownership comes from netstat, so no administrator rights are
// needed; with them, the engine's private log also confirms the decision.
package main

import (
	"bufio"
	"crypto/tls"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"os/exec"
	"slices"
	"strings"
	"time"
)

const (
	engineLog = "/var/log/network-domain-proxy/service.log"
	proxy     = "127.0.0.1:17890"
)

type probeResult struct {
	Host                string           `json:"host"`
	CertificateVerified bool             `json:"certificate_verified"`
	Status              string           `json:"status"`
	Seconds             float64          `json:"seconds_to_response_headers_including_socket_inspection"`
	OutboundLog         []map[string]any `json:"outbound_log"`
	NewSockets          []string         `json:"new_external_tcp_sockets"`
	Attribution         string           `json:"socket_attribution"`
}

func main() {
	output := flag.String("output", "", "also write the report to this new file")
	flag.Parse()
	report, err := collect()
	if err == nil {
		var data []byte
		if data, err = json.MarshalIndent(report, "", "  "); err == nil {
			data = append(data, '\n')
			if *output != "" {
				err = writeNew(*output, data)
			}
			os.Stdout.Write(data)
		}
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func writeNew(path string, data []byte) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	_, err = file.Write(data)
	if closeErr := file.Close(); err == nil {
		err = closeErr
	}
	return err
}

func collect() (map[string]any, error) {
	pids, err := exec.Command("/usr/bin/pgrep", "-f", "^/usr/local/libexec/network-domain-engine run( |$)").Output()
	fields := strings.Fields(string(pids))
	if err != nil || len(fields) != 1 {
		return nil, errors.New("expected exactly one production proxy engine")
	}
	pid := fields[0]
	report := map[string]any{"time": time.Now().Format(time.RFC3339), "engine_pid": pid}
	var probes []map[string]any
	for _, host := range []string{"www.douyin.com", "www.csdn.net", "github.com"} {
		var attempts []probeResult
		for i := 0; i < 3; i++ {
			result, err := probe(pid, host)
			if err != nil {
				return nil, fmt.Errorf("%s: %w", host, err)
			}
			attempts = append(attempts, result)
			if result.Attribution == "unique" {
				break
			}
		}
		probes = append(probes, map[string]any{"host": host, "attempts": attempts})
	}
	report["probes"] = probes
	report["engine_log_correlated"] = readable(engineLog)
	report["limitations"] = []string{"Short live sample, not a video playback test",
		"Concurrent browser connections can make socket attribution ambiguous"}
	return report, nil
}

func readable(path string) bool {
	file, err := os.Open(path)
	if err == nil {
		file.Close()
	}
	return err == nil
}

// sockets lists the engine's established external TCP connections as
// "local->remote" with port separators normalized to colons. netstat needs no
// privileges, but macOS can hide the socket table from processes it has not
// granted local network access; lsof, as administrator, is the fallback.
func sockets(pid string) (map[string]bool, error) {
	out, err := exec.Command("/usr/sbin/netstat", "-anv", "-p", "tcp").Output()
	if err != nil {
		return nil, err
	}
	if strings.Contains(string(out), "Proto") {
		found := map[string]bool{}
		for _, line := range strings.Split(string(out), "\n") {
			cols := strings.Fields(line)
			if len(cols) < 11 || cols[0] != "tcp4" || cols[5] != "ESTABLISHED" || !strings.Contains(line, ":"+pid+" ") {
				continue
			}
			if socket := colon(cols[3]) + "->" + colon(cols[4]); external(socket) {
				found[socket] = true
			}
		}
		return found, nil
	}
	out, _ = exec.Command("/usr/sbin/lsof", "-nP", "-a", "-p", pid, "-iTCP", "-sTCP:ESTABLISHED", "-F", "n").Output()
	found := map[string]bool{}
	for _, line := range strings.Split(string(out), "\n") {
		if socket, ok := strings.CutPrefix(line, "n"); ok && strings.Contains(socket, "->") && external(socket) {
			found[socket] = true
		}
	}
	if len(found) == 0 {
		return nil, errors.New("kernel socket table unavailable: netstat was filtered and lsof needs administrator rights")
	}
	return found, nil
}

func external(socket string) bool {
	return !strings.HasPrefix(socket, "127.0.0.1:") && strings.HasSuffix(socket, ":443")
}

func colon(address string) string {
	index := strings.LastIndexByte(address, '.')
	return address[:index] + ":" + address[index+1:]
}

func probe(pid, host string) (probeResult, error) {
	before, err := sockets(pid)
	if err != nil {
		return probeResult{}, err
	}
	started := time.Now()
	connection, err := net.DialTimeout("tcp", proxy, 10*time.Second)
	if err != nil {
		return probeResult{}, err
	}
	defer connection.Close()
	connection.SetDeadline(time.Now().Add(30 * time.Second))
	localPort := connection.LocalAddr().(*net.TCPAddr).Port
	fmt.Fprintf(connection, "CONNECT %s:443 HTTP/1.1\r\nHost: %s:443\r\n\r\n", host, host)
	reader := bufio.NewReader(connection)
	status, err := reader.ReadString('\n')
	if err != nil || !strings.HasPrefix(status, "HTTP/1.1 200") {
		return probeResult{}, fmt.Errorf("proxy refused CONNECT: %q %v", status, err)
	}
	for line := status; line != "\r\n"; {
		if line, err = reader.ReadString('\n'); err != nil {
			return probeResult{}, err
		}
	}
	tlsConnection := tls.Client(&bufferedConn{Conn: connection, reader: reader}, &tls.Config{ServerName: host})
	if err := tlsConnection.Handshake(); err != nil {
		return probeResult{}, err
	}
	// Hold this TLS connection while inspecting the engine's kernel sockets.
	after, err := sockets(pid)
	if err != nil {
		return probeResult{}, err
	}
	var candidates []string
	for socket := range after {
		if !before[socket] {
			candidates = append(candidates, socket)
		}
	}
	slices.Sort(candidates)
	fmt.Fprintf(tlsConnection, "GET / HTTP/1.1\r\nHost: %s\r\nConnection: close\r\nUser-Agent: network-split-verification/1\r\n\r\n", host)
	response, err := bufio.NewReader(tlsConnection).ReadString('\n')
	if err != nil {
		return probeResult{}, err
	}
	result := probeResult{Host: host, CertificateVerified: true, Status: strings.TrimSpace(response),
		Seconds: float64(time.Since(started).Milliseconds()) / 1000, NewSockets: candidates}
	if decisions, exact, ok := logDecisions(localPort); ok {
		result.OutboundLog = decisions
		candidates = slices.DeleteFunc(candidates, func(s string) bool { return !exact[s] })
		result.NewSockets = candidates
	}
	result.Attribution = "ambiguous; do not treat candidates as exact attribution"
	if len(candidates) == 1 {
		result.Attribution = "unique"
	}
	return result, nil
}

// logDecisions returns the route and connection events of the engine request
// that came from localPort, when the private log is readable.
func logDecisions(localPort int) ([]map[string]any, map[string]bool, bool) {
	data, err := os.ReadFile(engineLog)
	if err != nil {
		return nil, nil, false
	}
	var events []map[string]any
	for _, line := range strings.Split(string(data), "\n") {
		var event map[string]any
		if json.Unmarshal([]byte(line), &event) == nil {
			events = append(events, event)
		}
	}
	from := fmt.Sprintf("127.0.0.1:%d", localPort)
	start := -1
	for i := len(events) - 1; i >= 0; i-- {
		if events[i]["event"] == "incoming" && events[i]["from"] == from {
			start = i
			break
		}
	}
	if start < 0 {
		return nil, map[string]bool{}, true
	}
	id := events[start]["id"]
	var decisions []map[string]any
	exact := map[string]bool{}
	for _, event := range events[start+1:] {
		if event["id"] != id || (event["event"] != "route" && event["event"] != "connected") {
			continue
		}
		decisions = append(decisions, event)
		if event["event"] == "connected" {
			exact[fmt.Sprint(event["source"])+"->"+fmt.Sprint(event["destination"])] = true
		}
	}
	return decisions, exact, true
}

type bufferedConn struct {
	net.Conn
	reader *bufio.Reader
}

func (c *bufferedConn) Read(p []byte) (int, error) { return c.reader.Read(p) }
