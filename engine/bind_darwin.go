package main

import (
	"context"
	"net"
	"time"

	"network-owned-engine/internal/netbind"
)

// A kernel interface constraint, not a preference or a source-address hint.
func interfaceDial(ctx context.Context, iface, address string) (net.Conn, error) {
	d := net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}
	d.SetMultipathTCP(false)
	d.ControlContext = netbind.Control(iface)
	return d.DialContext(ctx, "tcp4", address)
}
