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

// Answers are reused for their DNS TTL, capped so a long TTL cannot pin a
// stale CDN address. Failures are not cached and nothing is written to disk.
const (
	dnsCacheMaxTTL     = 5 * time.Minute
	dnsCacheMaxEntries = 4096
)

type dohResolver struct {
	config    DNSConfig
	resolver  *net.Resolver
	client    *http.Client
	transport *http.Transport
	mu        sync.Mutex
	cache     map[string]cachedAnswer
}

type cachedAnswer struct {
	ips     []netip.Addr
	expires time.Time
}

type answerTTLKey struct{}

// answerTTL collects the shortest answer TTL seen during one lookup.
type answerTTL struct {
	mu    sync.Mutex
	value time.Duration
	seen  bool
}

func (a *answerTTL) observe(ttl time.Duration) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if !a.seen || ttl < a.value {
		a.value, a.seen = ttl, true
	}
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
	if ips, ok := d.cached(host); ok {
		return ips, nil
	}
	ttl := &answerTTL{}
	ctx, cancel := context.WithTimeout(context.WithValue(ctx, answerTTLKey{}, ttl), 5*time.Second)
	defer cancel()
	ips, err := d.resolver.LookupNetIP(ctx, "ip4", host+".")
	if err == nil {
		d.remember(host, ips, ttl)
	}
	return ips, err
}

func (d *dohResolver) cached(host string) ([]netip.Addr, bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	entry, ok := d.cache[host]
	if !ok {
		return nil, false
	}
	if !time.Now().Before(entry.expires) {
		delete(d.cache, host)
		return nil, false
	}
	return append([]netip.Addr(nil), entry.ips...), true
}

func (d *dohResolver) remember(host string, ips []netip.Addr, ttl *answerTTL) {
	ttl.mu.Lock()
	lifetime, seen := min(ttl.value, dnsCacheMaxTTL), ttl.seen
	ttl.mu.Unlock()
	if !seen || lifetime <= 0 || len(ips) == 0 {
		return
	}
	now := time.Now()
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.cache == nil {
		d.cache = map[string]cachedAnswer{}
	}
	if len(d.cache) >= dnsCacheMaxEntries {
		for key, entry := range d.cache {
			if !now.Before(entry.expires) {
				delete(d.cache, key)
			}
		}
		for key := range d.cache {
			if len(d.cache) < dnsCacheMaxEntries {
				break
			}
			delete(d.cache, key)
		}
	}
	d.cache[host] = cachedAnswer{ips: append([]netip.Addr(nil), ips...), expires: now.Add(lifetime)}
}

// minimumAnswerTTL returns the shortest TTL in a response's answer section. It
// only sizes the cache lifetime; net.Resolver still validates the answer.
func minimumAnswerTTL(message []byte) (time.Duration, bool) {
	if len(message) < 12 {
		return 0, false
	}
	offset := 12
	for i := 0; i < int(binary.BigEndian.Uint16(message[4:6])); i++ {
		var ok bool
		if offset, ok = skipDNSName(message, offset); !ok || offset+4 > len(message) {
			return 0, false
		}
		offset += 4
	}
	var minimum uint32
	found := false
	for i := 0; i < int(binary.BigEndian.Uint16(message[6:8])); i++ {
		var ok bool
		if offset, ok = skipDNSName(message, offset); !ok || offset+10 > len(message) {
			return 0, false
		}
		ttl := binary.BigEndian.Uint32(message[offset+4 : offset+8])
		if ttl > 1<<31-1 {
			ttl = 0 // RFC 2181: a TTL with the top bit set is treated as zero.
		}
		offset += 10 + int(binary.BigEndian.Uint16(message[offset+8:offset+10]))
		if offset > len(message) {
			return 0, false
		}
		if !found || ttl < minimum {
			minimum, found = ttl, true
		}
	}
	return time.Duration(minimum) * time.Second, found
}

func skipDNSName(message []byte, offset int) (int, bool) {
	for offset < len(message) {
		length := int(message[offset])
		switch {
		case length == 0:
			return offset + 1, true
		case length&0xc0 == 0xc0:
			return offset + 2, offset+2 <= len(message)
		case length&0xc0 != 0:
			return 0, false
		}
		offset += 1 + length
	}
	return 0, false
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
	if collector, ok := d.ctx.Value(answerTTLKey{}).(*answerTTL); ok {
		if ttl, found := minimumAnswerTTL(message); found {
			collector.observe(ttl)
		}
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
