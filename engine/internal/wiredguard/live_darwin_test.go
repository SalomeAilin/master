//go:build darwin && cgo

package wiredguard

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// This test deliberately uses the production lock and durable state. A killed
// test leaves the barrier and its ownership record for wired-app release.
// It never launches, stops, or changes the user's Baidu application.
func TestWiredPFLive(t *testing.T) {
	if os.Getenv("MASTER_WIRED_PF_LIVE") != "1" {
		t.Skip("set MASTER_WIRED_PF_LIVE=1 explicitly to run the administrator PF test")
	}
	if os.Geteuid() != 0 || os.Getegid() != 0 {
		t.Fatal("live PF test requires effective UID and GID 0")
	}
	uid, err := strconv.ParseUint(os.Getenv("MASTER_WIRED_PF_UID"), 10, 32)
	if err != nil || uid == 0 || uid > 2147483647 {
		t.Fatal("MASTER_WIRED_PF_UID must identify the existing unprivileged account")
	}
	account, err := LookupAccount(uint32(uid))
	if err != nil {
		t.Fatal(err)
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	// The nobody helper must be able to traverse the build directory. Fail
	// before touching PF if a private build directory prevents execution.
	for path := executable; ; path = filepath.Dir(path) {
		info, err := os.Stat(path)
		if err != nil || info.Mode().Perm()&0001 == 0 {
			t.Fatalf("test executable path must be searchable/executable by nobody: %s (%v)", path, err)
		}
		if path == "/" {
			break
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 35*time.Second)
	defer cancel()
	store := Store{Path: Directory, Owner: 0}
	unlock, err := store.Lock()
	if err != nil {
		t.Fatal(err)
	}
	defer unlock()
	if _, err = store.Read(); !os.IsNotExist(err) {
		t.Fatalf("an existing or unreadable session must be resolved before this test: %v", err)
	}
	n := &Native{Store: store, Account: account}
	snap, err := n.Inspect(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range snap.Processes {
		if IsBaidu(p) {
			t.Fatal("close Baidu yourself before the live test; the test does not stop user applications")
		}
	}
	gid, err := SelectGID(account, snap)
	if err != nil {
		t.Fatal(err)
	}
	wired, err := installedWiredInterface(ctx, false)
	if err != nil {
		t.Fatal(err)
	}
	if err = n.Preflight(ctx, nil); err != nil {
		t.Fatal(err)
	}
	h := &livePFHarness{native: n, executable: executable, state: State{Version: 1, UID: account.UID, GID: gid, Wired: wired, Phase: "reserved"}}
	// An ordinary failure unwinds through this function before unlocking.
	// The external -test.timeout must exceed 35s plus the 15s cleanup budget.
	defer func() {
		cleanupCtx, stop := context.WithTimeout(context.Background(), 15*time.Second)
		defer stop()
		if err := h.cleanup(cleanupCtx); err != nil {
			t.Errorf("live cleanup refused: %v; production state retained at %s/session.json; inspect it and use wired-app release after all recorded helpers have exited", err, Directory)
		}
	}()
	h.state.LastError = "explicit local PF self-test; no Baidu launch; helpers have independent 8s deadlines"
	if err = store.Save(h.state); err != nil {
		t.Fatal(err)
	}
	h.saved = true
	h.enableAttempted = true
	h.state.Token, err = n.Enable(ctx)
	if err != nil {
		_ = h.receipt("PF enable ownership is uncertain: " + err.Error())
		t.Fatal(err)
	}
	h.state.Phase = "enabled"
	if err = store.Save(h.state); err != nil {
		t.Fatal(err)
	}
	h.state.RuleHash, err = n.Load(ctx, h.state)
	if err != nil {
		_ = h.receipt("PF load/verification failed: " + err.Error())
		t.Fatal(err)
	}
	h.state.Phase = "barrier"
	if err = store.Save(h.state); err != nil {
		t.Fatal(err)
	}
	if err = n.Verify(ctx, h.state); err != nil {
		t.Fatal(err)
	}
	t.Logf("live test owns GID %d, anchor %s; token/hash are durably recorded in %s/session.json", gid, Anchor, Directory)

	for _, network := range []string{"tcp4", "tcp6", "udp4", "udp6"} {
		t.Run(network, func(t *testing.T) {
			if err := h.blockedNonce(ctx, network); err != nil {
				t.Error(err)
				return
			}
			t.Log("root control echoed before and after; controlled nonce absent; deny packet/byte counters increased")
		})
	}
	if err = h.listenerIdentity(ctx); err != nil {
		t.Error(err)
	}
	if err = n.Verify(ctx, h.state); err != nil {
		t.Error(err)
	}
	if !t.Failed() {
		t.Log("local PF capability gate passed; physical Ethernet removal and real Baidu transfer remain separate acceptance checks")
	}
}

type livePFHarness struct {
	native          *Native
	executable      string
	state           State
	saved           bool
	enableAttempted bool
	children        []*livePFChild
	closers         []io.Closer
}

type livePFRequest struct {
	Op, Network, Address, Nonce string
}

type livePFResponse struct {
	Ready, Connected, Echo bool
	Accepted               int
	Seen                   []string
	Error                  string
}

type livePFChild struct {
	cmd      *exec.Cmd
	identity Identity
	input    io.WriteCloser
	output   io.ReadCloser
	decoder  *json.Decoder
	stderr   bytes.Buffer
	reaped   bool
	waitErr  error
}

func (h *livePFHarness) receipt(reason string) error {
	var ids []string
	for _, child := range h.children {
		ids = append(ids, fmt.Sprintf("pid=%d start=%d uid=%d gid=%d", child.cmd.Process.Pid, child.identity.Started, child.identity.UID, child.identity.GID))
	}
	h.state.LastError = reason + "; test helpers: " + strings.Join(ids, "; ")
	return h.native.Save(h.state)
}

func (h *livePFHarness) start(ctx context.Context, uid, gid uint32, file *os.File) (*livePFChild, error) {
	child := &livePFChild{}
	child.cmd = exec.Command(h.executable, "-test.run=^TestWiredPFHelper$", "-test.timeout=12s")
	child.cmd.WaitDelay = 500 * time.Millisecond
	child.cmd.Env = []string{"PATH=/usr/bin:/bin:/usr/sbin:/sbin", "LC_ALL=C", "MASTER_WIRED_PF_HELPER=1"}
	child.cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: uid, Gid: gid, Groups: []uint32{}}, Setpgid: true}
	if file != nil {
		child.cmd.ExtraFiles = []*os.File{file}
	}
	var err error
	if child.input, err = child.cmd.StdinPipe(); err != nil {
		return nil, err
	}
	if child.output, err = child.cmd.StdoutPipe(); err != nil {
		child.input.Close()
		return nil, err
	}
	child.cmd.Stderr = &child.stderr
	child.decoder = json.NewDecoder(io.LimitReader(child.output, 16384))
	if err = child.cmd.Start(); err != nil {
		child.input.Close()
		child.output.Close()
		return nil, err
	}
	h.children = append(h.children, child)
	// Do not call Wait until all responses have been consumed and the child
	// is known to have exited. This keeps StdoutPipe open while decoding and
	// keeps the child PID reserved until the last possible signal is done.
	child.identity, err = nativeIdentity(child.cmd.Process.Pid)
	if err != nil {
		_ = h.receipt("helper identity unavailable; do not signal an unverified PID")
		return nil, err
	}
	if child.identity.UID != uid || child.identity.GID != gid || child.identity.RealGID != gid || child.identity.SavedGID != gid || child.identity.Path != h.executable {
		_ = h.receipt("helper credentials differ from the requested identity")
		return nil, errors.New("helper did not retain the exact requested credentials")
	}
	if err = h.receipt("local PF self-test in progress"); err != nil {
		return nil, err
	}
	if err = ctx.Err(); err != nil {
		return nil, err
	}
	return child, nil
}

func (child *livePFChild) request(ctx context.Context, request livePFRequest) (livePFResponse, error) {
	var response livePFResponse
	if err := json.NewEncoder(child.input).Encode(request); err != nil {
		return response, err
	}
	type result struct {
		response livePFResponse
		err      error
	}
	done := make(chan result, 1)
	go func() {
		var value livePFResponse
		err := child.decoder.Decode(&value)
		done <- result{value, err}
	}()
	select {
	case value := <-done:
		if value.err != nil {
			return value.response, value.err
		}
		if value.response.Error != "" {
			return value.response, errors.New(value.response.Error)
		}
		return value.response, nil
	case <-ctx.Done():
		return response, ctx.Err()
	case <-time.After(3 * time.Second):
		return response, errors.New("helper response exceeded 3s")
	}
}

func (child *livePFChild) stop(ctx context.Context) error {
	if child.reaped {
		return nil
	}
	child.input.Close()
	for _, signal := range []syscall.Signal{0, syscall.SIGTERM, syscall.SIGKILL} {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(350 * time.Millisecond):
		}
		exited, err := child.hasExited()
		if err != nil {
			return err
		}
		if exited {
			return child.reap()
		}
		if signal != 0 {
			// No Wait has run, so even an exit after hasExited cannot let
			// an unrelated process reuse this direct child's PID here.
			if err = syscall.Kill(child.identity.PID, signal); err != nil && !errors.Is(err, syscall.ESRCH) {
				return err
			}
		}
	}
	for deadline := time.Now().Add(time.Second); time.Now().Before(deadline); {
		exited, err := child.hasExited()
		if err != nil {
			return err
		}
		if exited {
			return child.reap()
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(20 * time.Millisecond):
		}
	}
	return fmt.Errorf("helper PID %d did not exit; state and PF barrier retained", child.cmd.Process.Pid)
}

func (child *livePFChild) hasExited() (bool, error) {
	p, err := unix.SysctlKinfoProc("kern.proc.pid", child.cmd.Process.Pid)
	if err != nil {
		if gone(child.cmd.Process.Pid) {
			return true, nil
		}
		return false, err
	}
	started := int64(p.Proc.P_starttime.Sec)*1000000 + int64(p.Proc.P_starttime.Usec)
	if child.identity.Started == 0 || started != child.identity.Started || int(p.Eproc.Ppid) != os.Getpid() {
		return false, fmt.Errorf("helper PID identity/parent changed; no signal sent: %d", child.cmd.Process.Pid)
	}
	if p.Proc.P_stat == 5 {
		return true, nil
	}
	current, err := nativeIdentity(child.cmd.Process.Pid)
	if err != nil || !SameProcess(current, child.identity) {
		return false, fmt.Errorf("helper identity is unavailable or changed; no signal sent: %d (%v)", child.cmd.Process.Pid, err)
	}
	return false, nil
}

func (child *livePFChild) reap() error {
	// The process has exited and no further signals will be sent. Wait cannot
	// race the decoder because every request has completed or been abandoned.
	child.waitErr = child.cmd.Wait()
	child.reaped = true
	child.output.Close()
	return nil
}

func (h *livePFHarness) cleanup(ctx context.Context) error {
	for i := len(h.closers) - 1; i >= 0; i-- {
		_ = h.closers[i].Close()
	}
	var failures []error
	for _, child := range h.children {
		if err := child.stop(ctx); err != nil {
			failures = append(failures, err)
		}
	}
	if len(failures) != 0 {
		_ = h.receipt("helper cleanup incomplete; barrier retained")
		return errors.Join(failures...)
	}
	if !h.saved {
		return nil
	}
	for range 2 {
		snap, err := h.native.Inspect(ctx, &h.state)
		if err != nil {
			_ = h.receipt("ownership scan failed during cleanup; barrier retained")
			return err
		}
		processes, sockets, err := Ownership(h.state, snap)
		if err != nil || processes != 0 || sockets != 0 {
			_ = h.receipt("unknown process/socket ownership or Baidu restart during cleanup; barrier retained")
			return errors.Join(fmt.Errorf("ownership is not empty: processes=%d sockets=%d", processes, sockets), err)
		}
	}
	if !h.enableAttempted {
		return h.native.Remove()
	}
	if h.state.Token == "" || h.state.RuleHash == "" {
		_ = h.receipt("incomplete PF token/hash; automatic cleanup refused")
		return errors.New("incomplete PF ownership record requires administrator inspection")
	}
	return (Controller{System: h.native}).Release(ctx, &h.state)
}

func liveNonce() string {
	var data [16]byte
	if _, err := rand.Read(data[:]); err != nil {
		panic(err)
	}
	return hex.EncodeToString(data[:])
}

func liveExchange(conn net.Conn, nonce string) error {
	if err := conn.SetDeadline(time.Now().Add(time.Second)); err != nil {
		return err
	}
	if _, err := io.WriteString(conn, nonce+"\n"); err != nil {
		return err
	}
	line, err := bufio.NewReader(io.LimitReader(conn, 1024)).ReadString('\n')
	if err != nil {
		return err
	}
	if line != nonce+"\n" {
		return errors.New("nonce echo mismatch")
	}
	return nil
}

type liveEcho struct {
	listener net.Listener
	packet   net.PacketConn
	mu       sync.Mutex
	seen     map[string]bool
	accepted int
	conns    []net.Conn
	wg       sync.WaitGroup
}

func liveNewEcho(network, address string, inherited net.Listener) (*liveEcho, error) {
	echo := &liveEcho{seen: map[string]bool{}, listener: inherited}
	var err error
	if strings.HasPrefix(network, "udp") {
		echo.packet, err = net.ListenPacket(network, address)
	} else if inherited == nil {
		echo.listener, err = net.Listen(network, address)
	}
	if err != nil {
		return nil, err
	}
	echo.wg.Add(1)
	go func() {
		defer echo.wg.Done()
		if echo.packet != nil {
			var data [1024]byte
			for {
				n, peer, err := echo.packet.ReadFrom(data[:])
				if err != nil {
					return
				}
				echo.mu.Lock()
				echo.seen[strings.TrimSpace(string(data[:n]))] = true
				echo.mu.Unlock()
				_, _ = echo.packet.WriteTo(data[:n], peer)
			}
		}
		for {
			conn, err := echo.listener.Accept()
			if err != nil {
				return
			}
			echo.mu.Lock()
			echo.accepted++
			echo.conns = append(echo.conns, conn)
			echo.mu.Unlock()
			echo.wg.Add(1)
			go func() {
				defer echo.wg.Done()
				defer conn.Close()
				_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
				scanner := bufio.NewScanner(conn)
				scanner.Buffer(make([]byte, 1024), 1024)
				for scanner.Scan() {
					line := scanner.Text()
					echo.mu.Lock()
					echo.seen[line] = true
					echo.mu.Unlock()
					if _, err := io.WriteString(conn, line+"\n"); err != nil {
						return
					}
				}
			}()
		}
	}()
	return echo, nil
}

func (echo *liveEcho) address() string {
	if echo.packet != nil {
		return echo.packet.LocalAddr().String()
	}
	return echo.listener.Addr().String()
}

func (echo *liveEcho) status() livePFResponse {
	echo.mu.Lock()
	defer echo.mu.Unlock()
	response := livePFResponse{Ready: true, Accepted: echo.accepted}
	for nonce := range echo.seen {
		response.Seen = append(response.Seen, nonce)
	}
	return response
}

func (echo *liveEcho) Close() error {
	if echo.listener != nil {
		_ = echo.listener.Close()
	}
	if echo.packet != nil {
		_ = echo.packet.Close()
	}
	echo.mu.Lock()
	for _, conn := range echo.conns {
		_ = conn.Close()
	}
	echo.mu.Unlock()
	echo.wg.Wait()
	return nil
}

type liveLabel struct{ packets, bytes uint64 }

func liveCounters(ctx context.Context, name string) (liveLabel, error) {
	output, err := pf(ctx, "", "-a", Anchor, "-s", "labels")
	if err != nil {
		return liveLabel{}, err
	}
	for _, line := range nonemptyLines(output) {
		fields := strings.Fields(line)
		if len(fields) == 8 && fields[0] == name {
			packets, e1 := strconv.ParseUint(fields[2], 10, 64)
			bytes, e2 := strconv.ParseUint(fields[3], 10, 64)
			return liveLabel{packets, bytes}, errors.Join(e1, e2)
		}
	}
	return liveLabel{}, fmt.Errorf("counter label %s is absent or has an unexpected format", name)
}

func (h *livePFHarness) blockedNonce(ctx context.Context, network string) error {
	address := "127.0.0.1:0"
	if strings.HasSuffix(network, "6") {
		address = "[::1]:0"
	}
	echo, err := liveNewEcho(network, address, nil)
	if err != nil {
		return err
	}
	h.closers = append(h.closers, echo)
	defer echo.Close()
	control, err := net.DialTimeout(network, echo.address(), time.Second)
	if err != nil {
		return err
	}
	h.closers = append(h.closers, control)
	defer control.Close()
	if err = liveExchange(control, liveNonce()); err != nil {
		return fmt.Errorf("root control echo failed: %w", err)
	}
	label := "wired-app-deny-" + network[:3]
	before, err := liveCounters(ctx, label)
	if err != nil {
		return err
	}
	child, err := h.start(ctx, h.state.UID, h.state.GID, nil)
	if err != nil {
		return err
	}
	nonce := liveNonce()
	response, err := child.request(ctx, livePFRequest{Op: "dial", Network: network, Address: echo.address(), Nonce: nonce})
	if err != nil {
		return err
	}
	if err = child.stop(ctx); err != nil {
		return err
	}
	if err = liveExchange(control, liveNonce()); err != nil {
		return fmt.Errorf("control echo failed after the blocked attempt: %w", err)
	}
	status := echo.status()
	nonceSeen := liveContains(status.Seen, nonce)
	after, err := liveCounters(ctx, label)
	if err != nil {
		return err
	}
	if (response.Connected && strings.HasPrefix(network, "tcp")) || response.Echo || nonceSeen {
		return fmt.Errorf("controlled connection was delivered: connected=%t echo=%t accepted=%d nonce_seen=%t deny_packets=%d->%d deny_bytes=%d->%d", response.Connected, response.Echo, status.Accepted, nonceSeen, before.packets, after.packets, before.bytes, after.bytes)
	}
	if after.packets <= before.packets || after.bytes <= before.bytes {
		return errors.New("deny packet and byte counters did not increase")
	}
	return nil
}

func (h *livePFHarness) listenerIdentity(ctx context.Context) error {
	listener, err := net.Listen("tcp4", fmt.Sprintf("127.0.0.1:%d", Port))
	if err != nil {
		return err
	}
	h.closers = append(h.closers, listener)
	file, err := listener.(*net.TCPListener).File()
	if err != nil {
		return err
	}
	h.closers = append(h.closers, file)
	nobody, err := user.Lookup("nobody")
	if err != nil {
		return err
	}
	uid, e1 := strconv.ParseUint(nobody.Uid, 10, 32)
	gid, e2 := strconv.ParseUint(nobody.Gid, 10, 32)
	if err = errors.Join(e1, e2); err != nil {
		return err
	}
	server, err := h.start(ctx, uint32(uid), uint32(gid), file)
	if err != nil {
		return err
	}
	if _, err = server.request(ctx, livePFRequest{Op: "inherited"}); err != nil {
		return err
	}
	before, err := liveCounters(ctx, "wired-app-root-listener")
	if err != nil {
		return err
	}
	client, err := h.start(ctx, h.state.UID, h.state.GID, nil)
	if err != nil {
		return err
	}
	nonce := liveNonce()
	response, err := client.request(ctx, livePFRequest{Op: "dial", Network: "tcp4", Address: listener.Addr().String(), Nonce: nonce})
	if err != nil || !response.Connected || !response.Echo {
		return errors.Join(errors.New("nobody server could not echo through the inherited root listener"), err)
	}
	if err = client.stop(ctx); err != nil {
		return err
	}
	status, err := server.request(ctx, livePFRequest{Op: "status"})
	if err != nil || status.Accepted != 1 || !liveContains(status.Seen, nonce) {
		return errors.Join(errors.New("nobody server did not prove accept and nonce delivery"), err)
	}
	after, err := liveCounters(ctx, "wired-app-root-listener")
	if err != nil || after.packets <= before.packets || after.bytes <= before.bytes {
		return errors.Join(errors.New("root-listener allow counter did not increase"), err)
	}
	if err = server.stop(ctx); err != nil {
		return err
	}
	// Close all three inherited/duplicate references before the impostor bind.
	// The nobody helper has exited, so its FileListener and accepted FD are gone.
	if err = file.Close(); err != nil {
		return err
	}
	if err = listener.Close(); err != nil {
		return err
	}
	server, err = h.start(ctx, h.native.Account.UID, h.native.Account.GID, nil)
	if err != nil {
		return err
	}
	if response, err = server.request(ctx, livePFRequest{Op: "ordinary", Address: fmt.Sprintf("127.0.0.1:%d", Port)}); err != nil || !response.Ready {
		return errors.Join(errors.New("ordinary UID did not acquire the abandoned port"), err)
	}
	before, err = liveCounters(ctx, "wired-app-deny-server")
	if err != nil {
		return err
	}
	client, err = h.start(ctx, h.state.UID, h.state.GID, nil)
	if err != nil {
		return err
	}
	nonce = liveNonce()
	response, err = client.request(ctx, livePFRequest{Op: "dial", Network: "tcp4", Address: fmt.Sprintf("127.0.0.1:%d", Port), Nonce: nonce})
	if err != nil || response.Connected || response.Echo {
		return errors.Join(errors.New("ordinary listener was reachable from the controlled GID"), err)
	}
	if err = client.stop(ctx); err != nil {
		return err
	}
	status, err = server.request(ctx, livePFRequest{Op: "status"})
	if err != nil || status.Accepted != 0 || liveContains(status.Seen, nonce) {
		return errors.Join(errors.New("impostor server accepted a controlled connection"), err)
	}
	after, err = liveCounters(ctx, "wired-app-deny-server")
	if err != nil || after.packets <= before.packets || after.bytes <= before.bytes {
		return errors.Join(errors.New("server-identity deny counter did not increase"), err)
	}
	return server.stop(ctx)
}

func liveContains(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

// The helper only exchanges nonces on explicitly validated loopback addresses.
// Its own deadline also applies when the parent is killed before cleanup.
func TestWiredPFHelper(t *testing.T) {
	if os.Getenv("MASTER_WIRED_PF_HELPER") != "1" {
		t.Skip("private subprocess helper")
	}
	go func() { time.Sleep(8 * time.Second); os.Exit(124) }()
	if err := livePFHelper(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	os.Exit(0)
}

func livePFHelper() error {
	input := json.NewDecoder(io.LimitReader(os.Stdin, 16384))
	output := json.NewEncoder(os.Stdout)
	var echo *liveEcho
	defer func() {
		if echo != nil {
			_ = echo.Close()
		}
	}()
	for {
		var request livePFRequest
		if err := input.Decode(&request); err == io.EOF {
			return nil
		} else if err != nil {
			return err
		}
		response := livePFResponse{}
		switch request.Op {
		case "dial":
			if request.Network != "tcp4" && request.Network != "tcp6" && request.Network != "udp4" && request.Network != "udp6" {
				return errors.New("unrecognized helper network")
			}
			if err := liveLoopback(request.Address); err != nil {
				return err
			}
			conn, err := net.DialTimeout(request.Network, request.Address, 800*time.Millisecond)
			if err == nil {
				response.Connected = true
				response.Echo = liveExchange(conn, request.Nonce) == nil
				_ = conn.Close()
			}
			// A dial/read failure is an observation; only the parent listener
			// and PF counter checks decide whether blocking was proved.
			if err = output.Encode(response); err != nil {
				return err
			}
			return nil
		case "inherited":
			if echo != nil {
				return errors.New("listener already initialized")
			}
			file := os.NewFile(3, "inherited-root-listener")
			listener, err := net.FileListener(file)
			_ = file.Close()
			if err != nil {
				return err
			}
			if listener.Addr().String() != fmt.Sprintf("127.0.0.1:%d", Port) {
				listener.Close()
				return errors.New("inherited listener address mismatch")
			}
			echo, err = liveNewEcho("tcp4", "", listener)
			if err != nil {
				listener.Close()
				return err
			}
			response.Ready = true
		case "ordinary":
			if echo != nil || request.Address != fmt.Sprintf("127.0.0.1:%d", Port) {
				return errors.New("invalid impostor listener request")
			}
			var err error
			echo, err = liveNewEcho("tcp4", request.Address, nil)
			if err != nil {
				return err
			}
			response.Ready = true
		case "status":
			if echo == nil {
				return errors.New("listener is not initialized")
			}
			response = echo.status()
		default:
			return errors.New("unrecognized helper operation")
		}
		if err := output.Encode(response); err != nil {
			return err
		}
	}
}

func liveLoopback(address string) error {
	host, port, err := net.SplitHostPort(address)
	if err != nil || (host != "127.0.0.1" && host != "::1") {
		return errors.New("test helper refuses non-loopback destinations")
	}
	n, err := strconv.Atoi(port)
	if err != nil || n <= 0 || n > 65535 {
		return errors.New("test helper refuses an invalid destination port")
	}
	return nil
}
