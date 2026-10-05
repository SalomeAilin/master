package dnsservice

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/miekg/dns"
)

const maxConcurrent = 64

type Server struct {
	Resolver *Resolver
	Logger   *QueryLogger
	Allowed  []netip.Prefix
	ctx      context.Context
	busy     chan struct{}
}

func LocalNetworks() ([]netip.Prefix, error) {
	addresses, err := net.InterfaceAddrs()
	if err != nil {
		return nil, err
	}
	prefixes := []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")}
	for _, address := range addresses {
		if p, err := netip.ParsePrefix(address.String()); err == nil && p.Addr().Is4() && p.Bits() > 0 {
			prefixes = append(prefixes, p.Masked())
		}
	}
	return prefixes, nil
}

func acceptMessage(h dns.Header) dns.MsgAcceptAction {
	if h.Bits&0x8000 != 0 {
		return dns.MsgIgnore
	}
	if h.Bits>>11&15 != dns.OpcodeQuery {
		return dns.MsgRejectNotImplemented
	}
	if h.Qdcount != 1 || h.Ancount != 0 || h.Nscount != 0 || h.Arcount > 1 {
		return dns.MsgReject
	}
	return dns.MsgAccept
}

func (s *Server) allowed(address net.Addr) bool {
	host, _, err := net.SplitHostPort(address.String())
	if err != nil {
		return false
	}
	ip, err := netip.ParseAddr(host)
	if err != nil {
		return false
	}
	ip = ip.Unmap()
	for _, p := range s.Allowed {
		if p.Contains(ip) {
			return true
		}
	}
	return false
}

func (s *Server) ServeDNS(w dns.ResponseWriter, q *dns.Msg) {
	if !s.allowed(w.RemoteAddr()) {
		return
	}
	if len(q.Question) != 1 {
		w.WriteMsg(responseFor(q, dns.RcodeFormatError))
		return
	}
	if len(q.Extra) > 0 && (len(q.Extra) != 1 || q.IsEdns0() == nil) {
		w.WriteMsg(responseFor(q, dns.RcodeRefused))
		return
	}
	if opt := q.IsEdns0(); opt != nil && opt.Hdr.Name != "." {
		w.WriteMsg(responseFor(q, dns.RcodeFormatError))
		return
	}
	if _, valid := dns.IsDomainName(q.Question[0].Name); !valid {
		w.WriteMsg(responseFor(q, dns.RcodeFormatError))
		return
	}
	if q.IsEdns0() != nil && q.IsEdns0().Version() != 0 {
		m := responseFor(q, dns.RcodeBadVers)
		m.SetEdns0(1232, false)
		w.WriteMsg(m)
		return
	}
	select {
	case s.busy <- struct{}{}:
		defer func() { <-s.busy }()
	default:
		w.WriteMsg(responseFor(q, dns.RcodeServerFailure))
		return
	}
	ctx, cancel := context.WithTimeout(s.ctx, 6*time.Second)
	defer cancel()
	m, cached, err := s.Resolver.Resolve(ctx, q)
	if err != nil || m == nil {
		m = responseFor(q, dns.RcodeServerFailure)
	}
	if s.Logger != nil {
		s.Logger.Write(q, m, w.RemoteAddr().String(), cached, err)
	}
	if _, udp := w.RemoteAddr().(*net.UDPAddr); udp {
		size := 512
		if opt := q.IsEdns0(); opt != nil {
			size = max(512, min(1232, int(opt.UDPSize())))
		}
		m.Truncate(size)
	}
	w.WriteMsg(m)
}

// Serve uses pre-bound listeners, whether supplied by launchd or an isolated
// test. It closes every listener and joins server goroutines on cancellation.
func (s *Server) Serve(ctx context.Context, l *Listeners) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	defer l.Close()
	s.ctx = ctx
	s.busy = make(chan struct{}, maxConcurrent)
	if len(s.Allowed) == 0 || len(l.TCP) == 0 || len(l.UDP) == 0 {
		return errors.New("DNS listeners and local client networks are required")
	}
	servers := make([]*dns.Server, 0, len(l.TCP)+len(l.UDP))
	ready := make(chan struct{}, len(l.TCP)+len(l.UDP))
	create := func() *dns.Server {
		return &dns.Server{Handler: s, UDPSize: 4096, ReadTimeout: 5 * time.Second, WriteTimeout: 2 * time.Second, IdleTimeout: func() time.Duration { return 5 * time.Second }, MaxTCPQueries: 32, MsgAcceptFunc: acceptMessage, NotifyStartedFunc: func() { ready <- struct{}{} }}
	}
	for _, conn := range l.UDP {
		server := create()
		server.PacketConn = conn
		servers = append(servers, server)
	}
	for _, conn := range l.TCP {
		server := create()
		server.Listener = &limitedListener{Listener: conn, slots: make(chan struct{}, maxConcurrent)}
		servers = append(servers, server)
	}
	results := make(chan error, len(servers))
	for _, server := range servers {
		go func() { results <- server.ActivateAndServe() }()
	}
	consumed := 0
	var result error
	var probesDone chan struct{}
	for count := 0; count < len(servers); count++ {
		select {
		case <-ready:
		case result = <-results:
			consumed++
			goto shutdown
		case <-ctx.Done():
			goto shutdown
		}
	}
	probesDone = make(chan struct{})
	go func() { defer close(probesDone); s.Resolver.ProbeLoops(ctx) }()
	select {
	case result = <-results:
		consumed++
	case <-ctx.Done():
	}
shutdown:
	cancel()
	stop, stopCancel := context.WithTimeout(context.Background(), 7*time.Second)
	defer stopCancel()
	for _, server := range servers {
		server.ShutdownContext(stop)
	}
	l.Close()
	for consumed < len(servers) {
		select {
		case <-results:
			consumed++
		case <-stop.Done():
			return errors.New("DNS server shutdown did not finish")
		}
	}
	if probesDone != nil {
		select {
		case <-probesDone:
		case <-stop.Done():
			return errors.New("DNS loop probe shutdown did not finish")
		}
	}
	return result
}

type limitedListener struct {
	net.Listener
	slots chan struct{}
}
type limitedConn struct {
	net.Conn
	once    sync.Once
	release func()
}

func (c *limitedConn) Close() error { err := c.Conn.Close(); c.once.Do(c.release); return err }
func (l *limitedListener) Accept() (net.Conn, error) {
	for {
		c, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		select {
		case l.slots <- struct{}{}:
			return &limitedConn{Conn: c, release: func() { <-l.slots }}, nil
		default:
			c.Close()
		}
	}
}
