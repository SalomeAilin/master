package dnsservice_test

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"network-owned-engine/internal/dnsservice"
	"network-owned-engine/internal/service"
)

func TestDNSActivatedSocketChild(t *testing.T) {
	if os.Getenv("NETWORK_SPLIT_SOCKET_CHILD") != "1" {
		t.Skip("isolated launchd child only")
	}
	if os.Geteuid() != -2 && uint64(os.Geteuid()) != 4294967294 {
		t.Fatal("DNS fixture is not nobody", os.Geteuid())
	}
	port, err := strconv.Atoi(os.Getenv("NETWORK_SPLIT_SOCKET_PORT"))
	if err != nil {
		t.Fatal(err)
	}
	c := dnsservice.Config{Port: port, Listen: []netip.Addr{netip.MustParseAddr("127.0.0.1")}}
	listeners, err := c.ActivatedListeners()
	if err != nil {
		t.Fatal(err)
	}
	defer listeners.Close()
	done := make(chan error, 2)
	go func() {
		conn, err := listeners.TCP[0].Accept()
		if err == nil {
			conn.SetDeadline(time.Now().Add(5 * time.Second))
			_, err = conn.Write([]byte("nobody"))
			conn.Close()
		}
		done <- err
	}()
	go func() {
		listeners.UDP[0].SetDeadline(time.Now().Add(10 * time.Second))
		data := make([]byte, 32)
		_, addr, err := listeners.UDP[0].ReadFrom(data)
		if err == nil {
			_, err = listeners.UDP[0].WriteTo([]byte("nobody"), addr)
		}
		done <- err
	}()
	for i := 0; i < 2; i++ {
		if err := <-done; err != nil {
			t.Fatal(err)
		}
	}
}

func TestLaunchdPassesLowPortSocketsToNobody(t *testing.T) {
	if os.Getenv("NETWORK_SPLIT_LAUNCHD_TEST") != "1" {
		t.Skip("native launchd integration is opt-in")
	}
	if os.Geteuid() != 0 {
		t.Fatal("administrator required for the isolated socket test")
	}
	if !dnsservice.SocketActivationAvailable() {
		t.Fatal("build this test with CGO_ENABLED=1")
	}
	port := 0
	for candidate := 54; candidate < 60; candidate++ {
		address := fmt.Sprintf("127.0.0.1:%d", candidate)
		tcp, err := net.Listen("tcp4", address)
		if err != nil {
			continue
		}
		udp, err := net.ListenPacket("udp4", address)
		tcp.Close()
		if err != nil {
			continue
		}
		udp.Close()
		port = candidate
		break
	}
	if port == 0 {
		t.Fatal("no unused low loopback port available")
	}
	c := dnsservice.Config{Port: port, Listen: []netip.Addr{netip.MustParseAddr("127.0.0.1")}}
	label := fmt.Sprintf("com.local.network-split-dns-test.%d.%d", os.Getpid(), time.Now().UnixNano())
	def := map[string]any{"Label": label, "ProgramArguments": []string{os.Args[0], "-test.run=^TestDNSActivatedSocketChild$", "-test.v"}, "UserName": "nobody", "RunAtLoad": true, "KeepAlive": false,
		"EnvironmentVariables": map[string]any{"NETWORK_SPLIT_SOCKET_CHILD": "1", "NETWORK_SPLIT_SOCKET_PORT": strconv.Itoa(port)}, "Sockets": c.SocketDefinition()}
	data, err := service.Plist(def)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), label+".plist")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if out, err := exec.CommandContext(ctx, "/bin/launchctl", "bootout", "system/"+label).CombinedOutput(); err != nil {
			if exit, ok := err.(*exec.ExitError); !ok || exit.ExitCode() != 113 {
				t.Errorf("test job cleanup failed: %v %s", err, out)
			}
		}
	}()
	if out, err := exec.CommandContext(ctx, "/bin/launchctl", "bootstrap", "system", path).CombinedOutput(); err != nil {
		t.Fatal(string(out), err)
	}
	address := fmt.Sprintf("127.0.0.1:%d", port)
	for _, network := range []string{"udp4", "tcp4"} {
		conn, err := net.DialTimeout(network, address, 5*time.Second)
		if err != nil {
			t.Fatal(err)
		}
		conn.SetDeadline(time.Now().Add(8 * time.Second))
		if strings.HasPrefix(network, "udp") {
			_, err = conn.Write([]byte("probe"))
		}
		if err != nil {
			conn.Close()
			t.Fatal(err)
		}
		response := make([]byte, 6)
		_, err = io.ReadFull(conn, response)
		conn.Close()
		if err != nil || string(response) != "nobody" {
			t.Fatal(network, string(response), err)
		}
	}
	t.Logf("nobody served TCP and UDP on loopback port %d via %s", port, label)
}
