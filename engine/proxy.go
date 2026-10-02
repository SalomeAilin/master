package main

import (
	"bufio"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type planKey struct{}
type bufferedConn struct {
	net.Conn
	reader *bufio.Reader
}

func (c *bufferedConn) Read(p []byte) (int, error) { return c.reader.Read(p) }
func (c *bufferedConn) CloseWrite() error {
	if half, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return half.CloseWrite()
	}
	return nil
}

type httpQueue struct {
	connections chan net.Conn
	done        chan struct{}
	once        sync.Once
	address     net.Addr
}

func (q *httpQueue) Accept() (net.Conn, error) {
	select {
	case <-q.done:
		return nil, net.ErrClosed
	case c := <-q.connections:
		return c, nil
	}
}
func (q *httpQueue) Close() error   { q.once.Do(func() { close(q.done) }); return nil }
func (q *httpQueue) Addr() net.Addr { return q.address }

func (e *engine) serve(ctx context.Context, listener net.Listener) error {
	queue := &httpQueue{connections: make(chan net.Conn, e.config.MaxClients), done: make(chan struct{}), address: listener.Addr()}
	server := &http.Server{Handler: http.HandlerFunc(e.http), ReadHeaderTimeout: 10 * time.Second, IdleTimeout: 90 * time.Second, MaxHeaderBytes: 64 << 10,
		BaseContext: func(net.Listener) context.Context { return ctx }}
	serverDone := make(chan error, 1)
	go func() { serverDone <- server.Serve(queue) }()
	stop := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			listener.Close()
		case <-stop:
		}
	}()
	defer close(stop)
	defer func() { queue.Close(); e.close(); server.Close(); <-serverDone }()
	capacity := make(chan struct{}, e.config.MaxClients)
	var workers sync.WaitGroup
	defer workers.Wait()
	// Close tracked sockets before waiting for protocol workers on shutdown.
	defer e.close()
	e.log.write("started", 0, map[string]any{"version": version, "listener": listener.Addr().String()})
	for {
		conn, err := listener.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		select {
		case capacity <- struct{}{}:
		default:
			conn.Close()
			continue
		}
		tracked, err := e.track(conn, func() { <-capacity })
		if err != nil {
			conn.Close()
			<-capacity
			continue
		}
		workers.Add(1)
		go func() {
			defer workers.Done()
			tracked.SetReadDeadline(time.Now().Add(10 * time.Second))
			reader := bufio.NewReaderSize(tracked, 8192)
			first, err := reader.Peek(1)
			if err != nil {
				tracked.Close()
				return
			}
			wrapped := &bufferedConn{Conn: tracked, reader: reader}
			if first[0] == 5 {
				defer wrapped.Close()
				e.socks(ctx, wrapped)
				return
			}
			select {
			case queue.connections <- wrapped:
			case <-ctx.Done():
				wrapped.Close()
			}
		}()
	}
}

func (e *engine) http(w http.ResponseWriter, request *http.Request) {
	id := e.ids.Add(1)
	e.log.write("incoming", id, map[string]any{"from": request.RemoteAddr, "protocol": "http"})
	if request.Method == http.MethodConnect {
		e.connectHTTP(w, request, id)
		return
	}
	if request.URL.Scheme != "http" || request.URL.Host == "" || request.URL.User != nil || request.URL.Fragment != "" {
		http.Error(w, "absolute HTTP URL required", http.StatusBadRequest)
		return
	}
	address := request.URL.Host
	if request.URL.Port() == "" {
		address = net.JoinHostPort(request.URL.Hostname(), "80")
	}
	p, err := e.resolve(request.Context(), address)
	if err != nil {
		e.failure(id, err)
		http.Error(w, "destination unavailable", http.StatusBadGateway)
		return
	}
	request = request.Clone(context.WithValue(request.Context(), planKey{}, p))
	request.RequestURI = ""
	request.Host = request.URL.Host
	request.URL.Host = net.JoinHostPort(p.host, p.port)
	upgrade := request.Header.Get("Upgrade")
	wantsUpgrade := strings.EqualFold(upgrade, "websocket") && headerToken(request.Header, "Connection", "upgrade")
	stripHopHeaders(request.Header)
	if wantsUpgrade {
		request.Header.Set("Connection", "Upgrade")
		request.Header.Set("Upgrade", "websocket")
	}
	response, err := e.transports[p.kind].RoundTrip(request)
	if err != nil {
		e.failure(id, err)
		http.Error(w, "upstream unavailable", http.StatusBadGateway)
		return
	}
	defer response.Body.Close()
	if response.StatusCode == http.StatusSwitchingProtocols {
		body, ok := response.Body.(io.ReadWriteCloser)
		if !wantsUpgrade || !ok || !strings.EqualFold(response.Header.Get("Upgrade"), "websocket") || !headerToken(response.Header, "Connection", "upgrade") {
			http.Error(w, "invalid upstream protocol upgrade", http.StatusBadGateway)
			return
		}
		client, buffer, err := w.(http.Hijacker).Hijack()
		if err != nil {
			return
		}
		defer client.Close()
		client.SetDeadline(time.Time{})
		stripHopHeaders(response.Header)
		response.Header.Set("Connection", "Upgrade")
		response.Header.Set("Upgrade", "websocket")
		if _, err = buffer.WriteString("HTTP/1.1 101 Switching Protocols\r\n"); err != nil {
			return
		}
		if err = response.Header.Write(buffer); err != nil {
			return
		}
		if _, err = buffer.WriteString("\r\n"); err != nil {
			return
		}
		if err = buffer.Flush(); err != nil {
			return
		}
		relay(client, buffer.Reader, body)
		return
	}
	stripHopHeaders(response.Header)
	for key, values := range response.Header {
		w.Header()[key] = values
	}
	w.WriteHeader(response.StatusCode)
	io.Copy(w, response.Body)
}

func headerToken(headers http.Header, name, token string) bool {
	for _, value := range headers.Values(name) {
		for _, part := range strings.Split(value, ",") {
			if strings.EqualFold(strings.TrimSpace(part), token) {
				return true
			}
		}
	}
	return false
}

func stripHopHeaders(headers http.Header) {
	for _, value := range headers.Values("Connection") {
		for _, field := range strings.Split(value, ",") {
			headers.Del(strings.TrimSpace(field))
		}
	}
	for _, name := range []string{"Connection", "Proxy-Connection", "Proxy-Authorization", "Proxy-Authenticate", "Keep-Alive", "TE", "Trailer", "Transfer-Encoding", "Upgrade"} {
		headers.Del(name)
	}
}

func (e *engine) connectHTTP(w http.ResponseWriter, request *http.Request, id uint64) {
	p, err := e.resolve(request.Context(), request.Host)
	if err != nil {
		e.failure(id, err)
		http.Error(w, "destination unavailable", http.StatusBadGateway)
		return
	}
	upstream, err := e.connect(request.Context(), p, id)
	if err != nil {
		e.failure(id, err)
		http.Error(w, "upstream unavailable", http.StatusBadGateway)
		return
	}
	defer upstream.Close()
	client, buffer, err := w.(http.Hijacker).Hijack()
	if err != nil {
		return
	}
	defer client.Close()
	client.SetDeadline(time.Time{})
	if _, err = buffer.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
		return
	}
	if err = buffer.Flush(); err != nil {
		return
	}
	relay(client, buffer.Reader, upstream)
}

// A tunnel closes after relayIdle without bytes in either direction. After one
// side finishes sending, the other side has relayLinger to send again.
const (
	relayIdle   = 5 * time.Minute
	relayLinger = 30 * time.Second
)

func relay(client net.Conn, reader io.Reader, upstream io.ReadWriteCloser) {
	relayWithLimits(client, reader, upstream, relayIdle, relayLinger)
}

// Idleness is measured across both directions, so a quiet request side never
// ends a response that is still streaming, or the reverse. Only a real end of
// stream is forwarded as a half-close; errors and idle expiry close both sides.
func relayWithLimits(client net.Conn, reader io.Reader, upstream io.ReadWriteCloser, idle, linger time.Duration) {
	moved := &activity{start: time.Now()}
	var closing sync.Once
	closeBoth := func() { closing.Do(func() { client.Close(); upstream.Close() }) }
	defer closeBoth()
	ended := make(chan bool, 2)
	pump := func(destination io.Writer, source io.Reader) {
		_, err := io.Copy(destination, &activityReader{Reader: source, moved: moved})
		if half, ok := destination.(interface{ CloseWrite() error }); ok && err == nil && half.CloseWrite() == nil {
			ended <- true
			return
		}
		closeBoth()
		ended <- false
	}
	go pump(upstream, reader)
	go pump(client, upstream)
	timer := time.NewTimer(idle)
	defer timer.Stop()
	expired := timer.C
	halfClosed := time.Duration(-1)
	for running := 2; running > 0; {
		select {
		case clean := <-ended:
			running--
			if running == 0 || !clean {
				continue
			}
			halfClosed = moved.elapsed()
		case <-expired:
		}
		if expired == nil {
			continue
		}
		since, limit := time.Duration(moved.last.Load()), idle
		if halfClosed >= since {
			since, limit = halfClosed, linger
		}
		if wait := limit - (moved.elapsed() - since); wait > 0 {
			timer.Reset(wait)
			continue
		}
		closeBoth()
		expired = nil
	}
}

// activity records when bytes last moved, on the monotonic clock.
type activity struct {
	start time.Time
	last  atomic.Int64
}

func (a *activity) elapsed() time.Duration { return time.Since(a.start) }

type activityReader struct {
	io.Reader
	moved *activity
}

func (r *activityReader) Read(p []byte) (int, error) {
	n, err := r.Reader.Read(p)
	if n > 0 {
		r.moved.last.Store(int64(r.moved.elapsed()))
	}
	return n, err
}

func (e *engine) socks(ctx context.Context, client net.Conn) {
	id := e.ids.Add(1)
	e.log.write("incoming", id, map[string]any{"from": client.RemoteAddr().String(), "protocol": "socks5"})
	header := make([]byte, 2)
	if _, err := io.ReadFull(client, header); err != nil || header[0] != 5 || header[1] == 0 {
		return
	}
	methods := make([]byte, int(header[1]))
	if _, err := io.ReadFull(client, methods); err != nil {
		return
	}
	noAuth := false
	for _, method := range methods {
		if method == 0 {
			noAuth = true
		}
	}
	if !noAuth {
		client.Write([]byte{5, 255})
		return
	}
	if _, err := client.Write([]byte{5, 0}); err != nil {
		return
	}
	request := make([]byte, 4)
	if _, err := io.ReadFull(client, request); err != nil || request[0] != 5 || request[2] != 0 {
		return
	}
	if request[1] != 1 {
		socksReply(client, 7)
		return
	}
	var host string
	switch request[3] {
	case 1:
		address := make([]byte, 4)
		if _, err := io.ReadFull(client, address); err != nil {
			return
		}
		host = net.IP(address).String()
	case 3:
		length := make([]byte, 1)
		if _, err := io.ReadFull(client, length); err != nil || length[0] == 0 {
			return
		}
		address := make([]byte, int(length[0]))
		if _, err := io.ReadFull(client, address); err != nil {
			return
		}
		host = string(address)
	default:
		socksReply(client, 8)
		return
	}
	port := make([]byte, 2)
	if _, err := io.ReadFull(client, port); err != nil {
		return
	}
	p, err := e.resolve(ctx, net.JoinHostPort(host, strconv.Itoa(int(binary.BigEndian.Uint16(port)))))
	if err != nil {
		e.failure(id, err)
		socksReply(client, 4)
		return
	}
	upstream, err := e.connect(ctx, p, id)
	if err != nil {
		e.failure(id, err)
		socksReply(client, 5)
		return
	}
	defer upstream.Close()
	bound, err := net.ResolveTCPAddr("tcp4", upstream.LocalAddr().String())
	if err != nil {
		socksReply(client, 1)
		return
	}
	ip := bound.IP.To4()
	if ip == nil {
		socksReply(client, 1)
		return
	}
	reply := []byte{5, 0, 0, 1}
	reply = append(reply, ip...)
	reply = append(reply, byte(bound.Port>>8), byte(bound.Port))
	if _, err = client.Write(reply); err != nil {
		return
	}
	client.SetDeadline(time.Time{})
	relay(client, client, upstream)
}

func socksReply(client net.Conn, code byte) { client.Write([]byte{5, code, 0, 1, 0, 0, 0, 0, 0, 0}) }

func startEngine(ctx context.Context, c Config, log *eventLog) error {
	e, err := newEngine(c, log)
	if err != nil {
		return err
	}
	defer e.close()
	listener, err := net.Listen("tcp4", c.Listen)
	if err != nil {
		return err
	}
	defer listener.Close()
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	var updates sync.WaitGroup
	defer updates.Wait()
	defer cancel()
	for _, source := range c.Sources {
		updates.Add(1)
		go func() { defer updates.Done(); e.rules.updater(ctx, source, c.Foreign, e.foreign, log) }()
	}
	err = e.serve(ctx, listener)
	if err != nil && !errors.Is(err, net.ErrClosed) {
		return fmt.Errorf("proxy listener: %w", err)
	}
	return nil
}
