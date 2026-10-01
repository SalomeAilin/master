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
		done := make(chan struct{})
		go func() {
			io.Copy(body, &idleReader{Reader: buffer.Reader, connection: client})
			body.Close()
			close(done)
		}()
		io.Copy(&idleWriter{Writer: client, connection: client}, body)
		client.Close()
		<-done
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

func relay(client net.Conn, reader io.Reader, upstream net.Conn) {
	readClient := &idleReader{Reader: reader, connection: client}
	writeClient := &idleWriter{Writer: client, connection: client}
	readUpstream := &idleReader{Reader: upstream, connection: upstream}
	writeUpstream := &idleWriter{Writer: upstream, connection: upstream}
	done := make(chan struct{})
	go func() {
		io.Copy(writeUpstream, readClient)
		if half, ok := upstream.(interface{ CloseWrite() error }); ok {
			half.CloseWrite()
		}
		upstream.SetReadDeadline(time.Now().Add(30 * time.Second))
		close(done)
	}()
	io.Copy(writeClient, readUpstream)
	if half, ok := client.(interface{ CloseWrite() error }); ok {
		half.CloseWrite()
	}
	client.SetReadDeadline(time.Now().Add(30 * time.Second))
	<-done
}

type idleReader struct {
	io.Reader
	connection net.Conn
}

func (r *idleReader) Read(p []byte) (int, error) {
	r.connection.SetReadDeadline(time.Now().Add(5 * time.Minute))
	return r.Reader.Read(p)
}

type idleWriter struct {
	io.Writer
	connection net.Conn
}

func (w *idleWriter) Write(p []byte) (int, error) {
	w.connection.SetWriteDeadline(time.Now().Add(5 * time.Minute))
	return w.Writer.Write(p)
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
