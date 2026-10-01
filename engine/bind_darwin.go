package main

import (
	"context"
	"errors"
	"net"
	"syscall"
	"time"
)

// A kernel interface constraint, not a preference or a source-address hint.
func interfaceDial(ctx context.Context, iface, address string) (net.Conn, error) {
	d := net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}
	d.SetMultipathTCP(false)
	d.ControlContext = func(_ context.Context, _, _ string, raw syscall.RawConn) error {
		device, err := net.InterfaceByName(iface)
		if err != nil {
			return err
		}
		if device.Flags&net.FlagUp == 0 {
			return errors.New("egress interface is down")
		}
		var bound error
		if err = raw.Control(func(fd uintptr) {
			bound = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IP, syscall.IP_BOUND_IF, device.Index)
		}); err != nil {
			return err
		}
		return bound
	}
	return d.DialContext(ctx, "tcp4", address)
}
