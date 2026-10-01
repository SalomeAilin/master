package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"sync"
	"time"
)

type lookupFunc func(context.Context, string) ([]netip.Addr, error)

type dohResolver struct {
	config    DNSConfig
	resolver  *net.Resolver
	client    *http.Client
	transport *http.Transport
}

func newResolver(egress Egress) *dohResolver {
	d := &dohResolver{config: egress.DNS}
	d.transport = &http.Transport{
		Proxy: nil, ForceAttemptHTTP2: true, MaxIdleConns: 8, MaxIdleConnsPerHost: 8,
		IdleConnTimeout: 90 * time.Second, TLSHandshakeTimeout: 5 * time.Second,
		TLSClientConfig: &tls.Config{ServerName: egress.DNS.ServerName, MinVersion: tls.VersionTLS12},
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return interfaceDial(ctx, egress.Interface, net.JoinHostPort(egress.DNS.Address, "443"))
		},
	}
	d.client = &http.Client{Transport: d.transport, Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("DoH redirect rejected") }}
	d.resolver = &net.Resolver{PreferGo: true, StrictErrors: true, Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return &dohStream{ctx: ctx, client: d.client, url: "https://" + egress.DNS.ServerName + "/dns-query"}, nil
	}}
	return d
}

func (d *dohResolver) lookup(ctx context.Context, host string) ([]netip.Addr, error) {
	if values, ok := d.config.Hosts[host]; ok {
		ips := make([]netip.Addr, 0, len(values))
		for _, value := range values {
			ips = append(ips, netip.MustParseAddr(value))
		}
		return ips, nil
	}
	if len(d.config.Hosts) != 0 {
		return nil, errors.New("host missing from isolated fixture DNS")
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	return d.resolver.LookupNetIP(ctx, "ip4", host+".")
}

// net.Resolver owns DNS encoding, response validation and parsing. This adapter
// carries its framed DNS messages over certificate-verified HTTPS instead of UDP.
type dohStream struct {
	ctx      context.Context
	client   *http.Client
	url      string
	mu       sync.Mutex
	response *bytes.Reader
	closed   bool
	deadline time.Time
}

func (d *dohStream) Write(data []byte) (int, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed {
		return 0, net.ErrClosed
	}
	if len(data) < 2 || int(binary.BigEndian.Uint16(data[:2])) != len(data)-2 {
		return 0, errors.New("invalid framed DNS query")
	}
	ctx := d.ctx
	if !d.deadline.IsZero() {
		var cancel context.CancelFunc
		ctx, cancel = context.WithDeadline(ctx, d.deadline)
		defer cancel()
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, d.url, bytes.NewReader(data[2:]))
	if err != nil {
		return 0, err
	}
	request.Header.Set("Content-Type", "application/dns-message")
	request.Header.Set("Accept", "application/dns-message")
	response, err := d.client.Do(request)
	if err != nil {
		return 0, err
	}
	defer response.Body.Close()
	if response.StatusCode != 200 || response.Header.Get("Content-Type") != "application/dns-message" {
		return 0, errors.New("invalid DoH HTTP response")
	}
	message, err := io.ReadAll(io.LimitReader(response.Body, 65536))
	if err != nil {
		return 0, err
	}
	if len(message) < 12 || len(message) > 65535 {
		return 0, errors.New("invalid DoH message size")
	}
	framed := make([]byte, len(message)+2)
	binary.BigEndian.PutUint16(framed, uint16(len(message)))
	copy(framed[2:], message)
	d.response = bytes.NewReader(framed)
	return len(data), nil
}

func (d *dohStream) Read(data []byte) (int, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed {
		return 0, net.ErrClosed
	}
	if d.response == nil {
		return 0, errors.New("DNS read before query")
	}
	return d.response.Read(data)
}
func (d *dohStream) Close() error         { d.mu.Lock(); defer d.mu.Unlock(); d.closed = true; return nil }
func (d *dohStream) LocalAddr() net.Addr  { return &net.TCPAddr{} }
func (d *dohStream) RemoteAddr() net.Addr { return &net.TCPAddr{} }
func (d *dohStream) SetDeadline(t time.Time) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.deadline = t
	return nil
}
func (d *dohStream) SetReadDeadline(t time.Time) error  { return d.SetDeadline(t) }
func (d *dohStream) SetWriteDeadline(t time.Time) error { return d.SetDeadline(t) }
