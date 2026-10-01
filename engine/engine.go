package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"os"
	"strconv"
	"sync"
	"sync/atomic"
	"time"
)

type plan struct {
	host, port, kind, iface string
	ips                     []netip.Addr
}
type dialFunc func(context.Context, string, []netip.Addr, string) (net.Conn, error)

type engine struct {
	config                  Config
	rules                   *ruleStore
	log                     *eventLog
	domestic, foreign       lookupFunc
	dial                    dialFunc
	dnsDomestic, dnsForeign *dohResolver
	transports              map[string]*http.Transport
	ids                     atomic.Uint64
	mu                      sync.Mutex
	connections             map[*trackedConn]bool
	closed                  bool
}

func newEngine(c Config, logger *eventLog) (*engine, error) {
	rules, err := newRules(c)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(c.CacheDir, 0700); err != nil {
		return nil, err
	}
	info, err := os.Lstat(c.CacheDir)
	if err != nil || !info.IsDir() || info.Mode().Perm()&0077 != 0 {
		return nil, errors.New("rule cache must be a private directory")
	}
	e := &engine{config: c, rules: rules, log: logger, dial: dialAddresses, connections: map[*trackedConn]bool{}, transports: map[string]*http.Transport{}}
	e.dnsDomestic = newResolver(c.Domestic)
	e.dnsForeign = newResolver(c.Foreign)
	e.domestic = e.dnsDomestic.lookup
	e.foreign = e.dnsForeign.lookup
	for _, kind := range []string{"domestic", "foreign"} {
		e.transports[kind] = &http.Transport{Proxy: nil, MaxIdleConns: 128, MaxIdleConnsPerHost: 8, IdleConnTimeout: 30 * time.Second, ResponseHeaderTimeout: 20 * time.Second,
			DialContext: func(ctx context.Context, _, address string) (net.Conn, error) {
				p, ok := ctx.Value(planKey{}).(plan)
				if !ok || net.JoinHostPort(p.host, p.port) != address || p.kind != kind {
					return nil, errors.New("forwarding plan mismatch")
				}
				return e.connect(ctx, p, 0)
			}}
	}
	return e, nil
}

func parseTarget(address string) (plan, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return plan{}, err
	}
	host, err = normalizeHost(host)
	if err != nil {
		return plan{}, err
	}
	number, err := strconv.Atoi(port)
	if err != nil || number < 1 || number > 65535 {
		return plan{}, errors.New("invalid destination port")
	}
	return plan{host: host, port: strconv.Itoa(number)}, nil
}

func (e *engine) resolve(ctx context.Context, address string) (plan, error) {
	p, err := parseTarget(address)
	if err != nil {
		return p, err
	}
	if ip, err := netip.ParseAddr(p.host); err == nil {
		p.ips = []netip.Addr{ip}
	} else {
		p.kind = e.rules.domain(p.host)
		lookup := e.domestic
		if p.kind == "foreign" {
			lookup = e.foreign
		}
		p.ips, err = lookup(ctx, p.host)
		if err != nil {
			return p, err
		}
	}
	if len(p.ips) == 0 {
		return p, errors.New("no IPv4 DNS answers")
	}
	for _, ip := range p.ips {
		if !publicIP(ip) {
			return p, errors.New("private or unsupported DNS destination rejected")
		}
	}
	if p.kind == "" {
		// Group all answers against one rule snapshot, including during hot updates.
		china, eligible := e.rules.chinaGroup(p.ips)
		p.kind = "foreign"
		if china {
			p.kind = "domestic"
		}
		p.ips = eligible
	}
	p.iface = e.config.Foreign.Interface
	if p.kind == "domestic" {
		p.iface = e.config.Domestic.Interface
	}
	return p, nil
}

func dialAddresses(ctx context.Context, iface string, ips []netip.Addr, port string) (net.Conn, error) {
	if len(ips) == 0 {
		return nil, errors.New("empty destination address list")
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	var last error
	for _, ip := range ips {
		attempt, stop := context.WithTimeout(ctx, 3*time.Second)
		connection, err := interfaceDial(attempt, iface, net.JoinHostPort(ip.String(), port))
		stop()
		if err == nil {
			return connection, nil
		}
		last = err
		if ctx.Err() != nil {
			break
		}
	}
	return nil, last
}

func (e *engine) connect(ctx context.Context, p plan, id uint64) (net.Conn, error) {
	e.log.write("route", id, map[string]any{"target": net.JoinHostPort(p.host, p.port), "outbound": p.kind, "interface": p.iface})
	conn, err := e.dial(ctx, p.iface, p.ips, p.port)
	if err != nil {
		return nil, err
	}
	tracked, err := e.track(conn, nil)
	if err != nil {
		conn.Close()
		return nil, err
	}
	e.log.write("connected", id, map[string]any{"source": conn.LocalAddr().String(), "destination": conn.RemoteAddr().String(), "outbound": p.kind})
	return tracked, nil
}

type trackedConn struct {
	net.Conn
	owner   *engine
	once    sync.Once
	release func()
}

func (c *trackedConn) Close() error {
	var err error
	c.once.Do(func() {
		err = c.Conn.Close()
		c.owner.mu.Lock()
		delete(c.owner.connections, c)
		c.owner.mu.Unlock()
		if c.release != nil {
			c.release()
		}
	})
	return err
}
func (c *trackedConn) CloseWrite() error {
	if half, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return half.CloseWrite()
	}
	return nil
}
func (e *engine) track(conn net.Conn, release func()) (*trackedConn, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.closed {
		return nil, net.ErrClosed
	}
	c := &trackedConn{Conn: conn, owner: e, release: release}
	e.connections[c] = true
	return c, nil
}
func (e *engine) close() {
	e.mu.Lock()
	e.closed = true
	connections := make([]*trackedConn, 0, len(e.connections))
	for conn := range e.connections {
		connections = append(connections, conn)
	}
	e.mu.Unlock()
	for _, conn := range connections {
		conn.Close()
	}
	for _, transport := range e.transports {
		transport.CloseIdleConnections()
	}
	e.dnsDomestic.transport.CloseIdleConnections()
	e.dnsForeign.transport.CloseIdleConnections()
}

func (e *engine) failure(id uint64, err error) {
	e.log.write("rejected", id, map[string]any{"error": fmt.Sprint(err)})
}
