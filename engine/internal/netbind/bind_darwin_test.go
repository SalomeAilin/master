package netbind

import (
	"context"
	"net"
	"testing"
	"time"
)

func TestUDPPinningAndUnavailableInterface(t *testing.T) {
	listener, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	for _, iface := range []string{"lo0", "network-interface-that-does-not-exist"} {
		dialer := net.Dialer{Timeout: time.Second, ControlContext: Control(iface)}
		conn, err := dialer.DialContext(context.Background(), "udp4", listener.LocalAddr().String())
		if iface != "lo0" {
			if err == nil {
				conn.Close()
				t.Fatal("missing interface fell back")
			}
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		if _, err := conn.Write([]byte("pin")); err != nil {
			t.Fatal(err)
		}
		conn.Close()
		listener.SetReadDeadline(time.Now().Add(time.Second))
		buf := make([]byte, 16)
		n, _, err := listener.ReadFrom(buf)
		if err != nil || string(buf[:n]) != "pin" {
			t.Fatal(n, err)
		}
	}
}
