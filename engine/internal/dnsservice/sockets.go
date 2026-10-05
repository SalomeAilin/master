package dnsservice

import (
	"errors"
	"net"
	"net/netip"
	"slices"
	"strconv"
)

const UDPActivation = "DNSUDP"
const TCPActivation = "DNSTCP"

// SocketDefinition leaves privileged binding to launchd. The worker remains
// unprivileged and receives only the sockets defined for this service.
func (c Config) SocketDefinition() map[string]any {
	result := map[string]any{}
	for name, kind := range map[string]string{UDPActivation: "dgram", TCPActivation: "stream"} {
		var sockets []any
		for _, ip := range c.Listen {
			sockets = append(sockets, map[string]any{"SockType": kind, "SockFamily": "IPv4", "SockNodeName": ip.String(), "SockServiceName": strconv.Itoa(c.Port), "SockPassive": true})
		}
		result[name] = sockets
	}
	return result
}

type Listeners struct {
	TCP []net.Listener
	UDP []net.PacketConn
}

func (l *Listeners) Close() {
	for _, c := range l.TCP {
		c.Close()
	}
	for _, c := range l.UDP {
		c.Close()
	}
}

func (c Config) activatedAddress(address net.Addr) bool {
	ip, port, err := net.SplitHostPort(address.String())
	if err != nil || port != strconv.Itoa(c.Port) {
		return false
	}
	a, err := netip.ParseAddr(ip)
	return err == nil && slices.Contains(c.Listen, a.Unmap())
}

func (c Config) ActivatedListeners() (_ *Listeners, err error) {
	l := &Listeners{}
	defer func() {
		if err != nil {
			l.Close()
		}
	}()
	for _, name := range []string{UDPActivation, TCPActivation} {
		files, e := activate(name)
		if e != nil {
			return nil, e
		}
		for _, f := range files {
			defer f.Close()
		}
		if len(files) != len(c.Listen) {
			return nil, errors.New("launchd listener count differs from DNS policy")
		}
		seen := map[string]bool{}
		for _, f := range files {
			var address net.Addr
			if name == UDPActivation {
				conn, e := net.FilePacketConn(f)
				if e != nil {
					return nil, e
				}
				l.UDP = append(l.UDP, conn)
				address = conn.LocalAddr()
			} else {
				conn, e := net.FileListener(f)
				if e != nil {
					return nil, e
				}
				l.TCP = append(l.TCP, conn)
				address = conn.Addr()
			}
			if !c.activatedAddress(address) || seen[address.String()] {
				return nil, errors.New("unexpected activated DNS listener")
			}
			seen[address.String()] = true
		}
	}
	return l, nil
}
