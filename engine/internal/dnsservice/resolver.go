package dnsservice

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"net/netip"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
	"network-owned-engine/internal/netbind"
	"network-owned-engine/internal/policy"
)

// ForwardBudget bounds one forwarded query across its whole upstream group.
// Lookups that judge DNS health must wait longer, or a slow answer that still
// succeeds is reported as a failure.
const ForwardBudget = 5 * time.Second

type ExchangeFunc func(context.Context, *dns.Msg, netip.Addr, string, string) (*dns.Msg, error)
type flight struct {
	done     chan struct{}
	response *dns.Msg
	err      error
}
type upstream struct {
	address netip.Addr
	iface   string
}

type Resolver struct {
	Config      Config
	Wired, WiFi string
	Exchange    ExchangeFunc
	Now         func() time.Time
	hosts       map[string][]netip.Addr
	cache       *answerCache
	mu          sync.Mutex
	flights     map[string]*flight
	loops       map[string]upstream
	blocked     map[upstream]bool
	preferred   map[string]netip.Addr
}

func NewResolver(c Config, wired, wifi string, hosts []byte) (*Resolver, error) {
	if len(c.Servers) == 0 || c.CacheEntries < 0 || c.CacheEntries > 10000 {
		return nil, errors.New("invalid DNS resolver limits or default upstreams")
	}
	for _, servers := range c.Domains {
		if len(servers) == 0 {
			return nil, errors.New("empty DNS domain upstream group")
		}
	}
	if wired == "" || wifi == "" || wired == wifi {
		return nil, errors.New("DNS egress interfaces must differ")
	}
	r := &Resolver{Config: c, Wired: wired, WiFi: wifi, Exchange: exchange, Now: time.Now, cache: newCache(c.CacheEntries), hosts: map[string][]netip.Addr{}, flights: map[string]*flight{}, loops: map[string]upstream{}, blocked: map[upstream]bool{}, preferred: map[string]netip.Addr{}}
	if len(hosts) > 1<<20 {
		return nil, errors.New("hosts file exceeds limit")
	}
	for _, line := range strings.Split(string(hosts), "\n") {
		line, _, _ = strings.Cut(line, "#")
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		ip, err := netip.ParseAddr(fields[0])
		if err != nil {
			continue
		}
		for _, name := range fields[1:] {
			if validDomain(name) {
				key := dns.CanonicalName(name)
				if !slices.Contains(r.hosts[key], ip) {
					r.hosts[key] = append(r.hosts[key], ip)
				}
			}
		}
	}
	return r, nil
}

func exchange(ctx context.Context, q *dns.Msg, address netip.Addr, iface, network string) (*dns.Msg, error) {
	client := &dns.Client{Net: network, UDPSize: 1232, Timeout: 1500 * time.Millisecond, Dialer: &net.Dialer{Timeout: 1500 * time.Millisecond, ControlContext: netbind.Control(iface)}}
	response, _, err := client.ExchangeContext(ctx, q, net.JoinHostPort(address.String(), "53"))
	return response, err
}

func responseFor(q *dns.Msg, code int) *dns.Msg {
	m := new(dns.Msg)
	m.SetRcode(q, code)
	m.RecursionAvailable = true
	return m
}

func (r *Resolver) local(q *dns.Msg) *dns.Msg {
	question := q.Question[0]
	name := dns.CanonicalName(question.Name)
	if ips, exists := r.hosts[name]; exists {
		m := responseFor(q, dns.RcodeSuccess)
		m.Authoritative = true
		if question.Qtype == dns.TypeA || question.Qtype == dns.TypeANY {
			for _, ip := range ips {
				if ip.Is4() {
					m.Answer = append(m.Answer, &dns.A{Hdr: dns.RR_Header{Name: question.Name, Rrtype: dns.TypeA, Class: dns.ClassINET}, A: net.IP(ip.AsSlice())})
				}
			}
		}
		return m
	}
	if strings.HasSuffix(name, ".in-addr.arpa.") || strings.HasSuffix(name, ".ip6.arpa.") {
		for host, ips := range r.hosts {
			for _, ip := range ips {
				reverse, _ := dns.ReverseAddr(ip.String())
				if question.Qtype == dns.TypePTR && dns.CanonicalName(reverse) == name {
					m := responseFor(q, dns.RcodeSuccess)
					m.Authoritative = true
					m.Answer = []dns.RR{&dns.PTR{Hdr: dns.RR_Header{Name: question.Name, Rrtype: dns.TypePTR, Class: dns.ClassINET}, Ptr: host}}
					return m
				}
			}
		}
		if privateReverse(name) {
			return responseFor(q, dns.RcodeNameError)
		}
	}
	if (question.Qtype == dns.TypeA || question.Qtype == dns.TypeAAAA) && dns.CountLabel(name) < 2 {
		return responseFor(q, dns.RcodeNameError)
	}
	return nil
}

func privateReverse(name string) bool {
	for _, zone := range []string{"10.in-addr.arpa.", "127.in-addr.arpa.", "168.192.in-addr.arpa.", "254.169.in-addr.arpa.", "0.in-addr.arpa.", "d.f.ip6.arpa.", "c.f.ip6.arpa.", "8.e.f.ip6.arpa.", "9.e.f.ip6.arpa.", "a.e.f.ip6.arpa.", "b.e.f.ip6.arpa."} {
		if dns.IsSubDomain(zone, name) {
			return true
		}
	}
	for octet := 16; octet < 32; octet++ {
		if dns.IsSubDomain(strconv.Itoa(octet)+".172.in-addr.arpa.", name) {
			return true
		}
	}
	if value, ok := strings.CutSuffix(name, ".in-addr.arpa."); ok {
		labels := strings.Split(value, ".")
		if len(labels) == 4 {
			slices.Reverse(labels)
			ip, err := netip.ParseAddr(strings.Join(labels, "."))
			return err == nil && !publicAddress(ip)
		}
	}
	if value, ok := strings.CutSuffix(name, ".ip6.arpa."); ok {
		labels := strings.Split(value, ".")
		if len(labels) != 32 {
			return false
		}
		slices.Reverse(labels)
		for i := range labels {
			if len(labels[i]) != 1 {
				return false
			}
		}
		b, err := hex.DecodeString(strings.Join(labels, ""))
		if err == nil {
			ip, ok := netip.AddrFromSlice(b)
			return ok && !publicAddress(ip)
		}
	}
	return false
}

func publicAddress(ip netip.Addr) bool {
	ip = ip.Unmap()
	if !ip.IsGlobalUnicast() || ip.IsPrivate() || ip.IsLoopback() {
		return false
	}
	if ip.Is4() {
		return policy.Global(ip)
	}
	return true
}

func cleanResponse(q, m *dns.Msg, maxTTL uint32) (*dns.Msg, error) {
	if m == nil || !m.Response || m.Id != q.Id || m.Opcode != dns.OpcodeQuery || len(m.Question) != 1 || !strings.EqualFold(m.Question[0].Name, q.Question[0].Name) || m.Question[0].Qtype != q.Question[0].Qtype || m.Question[0].Qclass != q.Question[0].Qclass {
		return nil, errors.New("DNS response does not match its query")
	}
	m = m.Copy()
	filtered := false
	for _, section := range []*[]dns.RR{&m.Answer, &m.Ns, &m.Extra} {
		out := (*section)[:0]
		for _, rr := range *section {
			if rr.Header().Rrtype == dns.TypeAAAA {
				filtered = true
				continue
			}
			if sig, ok := rr.(*dns.RRSIG); ok && sig.TypeCovered == dns.TypeAAAA {
				filtered = true
				continue
			}
			switch value := rr.(type) {
			case *dns.A:
				ip, ok := netip.AddrFromSlice(value.A)
				if !ok || !publicAddress(ip) {
					return nil, errors.New("DNS rebinding answer rejected")
				}
			case *dns.HTTPS:
				if err := checkHints(&value.SVCB); err != nil {
					return nil, err
				}
			case *dns.SVCB:
				if err := checkHints(value); err != nil {
					return nil, err
				}
			}
			if rr.Header().Rrtype != dns.TypeOPT {
				if rr.Header().Ttl > 1<<31-1 {
					rr.Header().Ttl = 0
				}
				rr.Header().Ttl = min(rr.Header().Ttl, maxTTL)
			}
			out = append(out, rr)
		}
		*section = out
	}
	if filtered {
		m.AuthenticatedData = false
	}
	if m.Rcode == dns.RcodeNameError || len(m.Answer) == 0 {
		for _, rr := range m.Ns {
			if soa, ok := rr.(*dns.SOA); ok {
				soa.Hdr.Ttl = min(soa.Hdr.Ttl, soa.Minttl)
			}
		}
	}
	return m, nil
}

func checkHints(record *dns.SVCB) error {
	for _, kv := range record.Value {
		switch hint := kv.(type) {
		case *dns.SVCBIPv4Hint:
			for _, value := range hint.Hint {
				ip, ok := netip.AddrFromSlice(value)
				if !ok || !publicAddress(ip) {
					return errors.New("private DNS service hint rejected")
				}
			}
		case *dns.SVCBIPv6Hint:
			for _, value := range hint.Hint {
				ip, ok := netip.AddrFromSlice(value)
				if !ok || !publicAddress(ip) {
					return errors.New("private DNS service hint rejected")
				}
			}
		}
	}
	return nil
}

func (r *Resolver) Resolve(ctx context.Context, q *dns.Msg) (*dns.Msg, bool, error) {
	if len(q.Question) != 1 || q.Question[0].Qclass != dns.ClassINET || q.Opcode != dns.OpcodeQuery {
		return responseFor(q, dns.RcodeRefused), false, nil
	}
	name := dns.CanonicalName(q.Question[0].Name)
	r.mu.Lock()
	loop, found := r.loops[name]
	if found {
		r.blocked[loop] = true
	}
	r.mu.Unlock()
	if found {
		return responseFor(q, dns.RcodeServerFailure), false, errors.New("DNS forwarding loop detected")
	}
	if local := r.local(q); local != nil {
		return local, false, nil
	}
	key := queryKey(q)
	if cached := r.cache.get(key, q, r.Now()); cached != nil {
		return cached, true, nil
	}
	if !q.RecursionDesired {
		return responseFor(q, dns.RcodeRefused), false, nil
	}
	if q.Question[0].Qtype == dns.TypeAXFR || q.Question[0].Qtype == dns.TypeIXFR || q.IsTsig() != nil {
		return responseFor(q, dns.RcodeRefused), false, nil
	}
	if key != "" {
		r.mu.Lock()
		if cached := r.cache.get(key, q, r.Now()); cached != nil {
			r.mu.Unlock()
			return cached, true, nil
		}
		if pending := r.flights[key]; pending != nil {
			r.mu.Unlock()
			select {
			case <-ctx.Done():
				return nil, false, ctx.Err()
			case <-pending.done:
			}
			if pending.response == nil {
				return nil, false, pending.err
			}
			m := pending.response.Copy()
			m.Id = q.Id
			m.Question = append([]dns.Question(nil), q.Question...)
			return m, false, pending.err
		}
		if len(r.flights) >= maxConcurrent {
			r.mu.Unlock()
			return nil, false, errors.New("DNS request limit reached")
		}
		pending := &flight{done: make(chan struct{})}
		r.flights[key] = pending
		r.mu.Unlock()
		defer func() { r.mu.Lock(); delete(r.flights, key); close(pending.done); r.mu.Unlock() }()
		m, err := r.forward(ctx, q)
		pending.response, pending.err = m, err
		if err == nil {
			r.cache.put(key, m, r.Config.CacheTTL, r.Now())
		}
		return m, false, err
	}
	m, err := r.forward(ctx, q)
	return m, false, err
}

func (r *Resolver) forward(ctx context.Context, q *dns.Msg) (*dns.Msg, error) {
	servers, domestic := r.Config.Select(q.Question[0].Name)
	if len(servers) == 0 {
		return nil, errors.New("DNS upstream group is empty")
	}
	iface := r.WiFi
	if domestic {
		iface = r.Wired
	}
	ctx, cancel := context.WithTimeout(ctx, ForwardBudget)
	defer cancel()
	r.mu.Lock()
	start := max(0, slices.Index(servers, r.preferred[iface]))
	r.mu.Unlock()
	var last error
	for index := range servers {
		address := servers[(start+index)%len(servers)]
		r.mu.Lock()
		blocked := r.blocked[upstream{address, iface}]
		r.mu.Unlock()
		if blocked {
			continue
		}
		request := q.Copy()
		request.Id = dns.Id()
		if opt := request.IsEdns0(); opt != nil {
			opt.SetUDPSize(1232)
		}
		m, err := r.Exchange(ctx, request, address, iface, "udp4")
		if err == nil && m != nil && m.Truncated {
			m, err = r.Exchange(ctx, request, address, iface, "tcp4")
		}
		if err == nil {
			m, err = cleanResponse(request, m, r.Config.MaxTTL)
		}
		if err == nil && !m.Truncated && m.Rcode != dns.RcodeServerFailure && m.Rcode != dns.RcodeRefused {
			r.mu.Lock()
			r.preferred[iface] = address
			r.mu.Unlock()
			m.Id = q.Id
			m.Question = append([]dns.Question(nil), q.Question...)
			return m, nil
		}
		if err != nil {
			last = err
		} else {
			last = errors.New("upstream refused DNS query")
		}
		if ctx.Err() != nil {
			break
		}
	}
	if last == nil {
		last = errors.New("no usable DNS upstream")
	}
	return nil, last
}

func (r *Resolver) ProbeLoops(ctx context.Context) {
	all := map[upstream]bool{}
	for _, ip := range r.Config.Servers {
		all[upstream{ip, r.WiFi}] = true
	}
	for _, ips := range r.Config.Domains {
		for _, ip := range ips {
			all[upstream{ip, r.Wired}] = true
		}
	}
	var wg sync.WaitGroup
	for server := range all {
		var nonce [16]byte
		if _, err := rand.Read(nonce[:]); err != nil {
			continue
		}
		name := hex.EncodeToString(nonce[:]) + ".test."
		r.mu.Lock()
		r.loops[name] = server
		r.mu.Unlock()
		wg.Add(1)
		go func() {
			defer wg.Done()
			ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
			defer cancel()
			q := new(dns.Msg)
			q.SetQuestion(name, dns.TypeTXT)
			r.Exchange(ctx, q, server.address, server.iface, "udp4")
		}()
	}
	wg.Wait()
}

func LoadHosts() ([]byte, error) {
	f, err := os.Open("/etc/hosts")
	if err != nil {
		return nil, err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, (1<<20)+1))
	if err != nil {
		return nil, err
	}
	if len(b) > 1<<20 {
		return nil, errors.New("hosts file exceeds limit")
	}
	return b, nil
}
