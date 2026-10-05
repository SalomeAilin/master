// Package netbind pins outgoing IPv4 sockets to one kernel interface.
package netbind

import (
	"context"
	"errors"
	"net"
	"syscall"
)

func Control(iface string) func(context.Context, string, string, syscall.RawConn) error {
	return func(_ context.Context, network, _ string, raw syscall.RawConn) error {
		if network != "tcp4" && network != "udp4" {
			return errors.New("IPv4 socket required")
		}
		device, err := net.InterfaceByName(iface)
		if err != nil {
			return err
		}
		if device.Flags&net.FlagUp == 0 {
			return errors.New("egress interface is down")
		}
		var bound error
		if err := raw.Control(func(fd uintptr) {
			bound = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IP, syscall.IP_BOUND_IF, device.Index)
		}); err != nil {
			return err
		}
		return bound
	}
}
