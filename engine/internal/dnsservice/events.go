package dnsservice

import (
	"fmt"
	"net/netip"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/miekg/dns"
)

const QueryLogLimit = 64 << 20

type QueryLogger struct {
	Path     string
	mu       sync.Mutex
	sequence atomic.Uint64
}

// AnswerAddresses follows only this query's answer CNAME chain. Authority and
// unrelated additional records never become domestic host routes.
func AnswerAddresses(q *dns.Msg, m *dns.Msg) []string {
	if len(q.Question) != 1 || m == nil || m.Rcode != dns.RcodeSuccess {
		return nil
	}
	name := dns.CanonicalName(q.Question[0].Name)
	if strings.Contains(name, "\\") {
		return nil
	}
	reachable := map[string]bool{name: true}
	for step := 0; step < 32; step++ {
		changed := false
		for _, rr := range m.Answer {
			if c, ok := rr.(*dns.CNAME); ok && reachable[dns.CanonicalName(c.Hdr.Name)] && !reachable[dns.CanonicalName(c.Target)] {
				reachable[dns.CanonicalName(c.Target)] = true
				changed = true
			}
		}
		if !changed {
			break
		}
	}
	var addresses []string
	seen := map[string]bool{}
	for _, rr := range m.Answer {
		if a, ok := rr.(*dns.A); ok && reachable[dns.CanonicalName(a.Hdr.Name)] {
			ip, valid := netip.AddrFromSlice(a.A)
			if valid && publicAddress(ip) && !seen[ip.String()] {
				seen[ip.String()] = true
				addresses = append(addresses, ip.Unmap().String())
				if len(addresses) == 64 {
					break
				}
			}
		}
	}
	return addresses
}

// Answers slower than this record their duration, so a client that gave up
// can be told apart from an upstream that never answered.
const slowAnswer = time.Second

func (l *QueryLogger) Write(q, m *dns.Msg, client string, cached bool, elapsed time.Duration, cause error) error {
	if len(q.Question) != 1 {
		return nil
	}
	id := l.sequence.Add(1)
	prefix := fmt.Sprintf("network-dns[%d]: %d %s ", os.Getpid(), id, client)
	name := strings.TrimSuffix(q.Question[0].Name, ".")
	var batch strings.Builder
	fmt.Fprintf(&batch, "%squery[TYPE%d] %s from %s\n", prefix, q.Question[0].Qtype, name, client)
	kind := "reply"
	if cached {
		kind = "cached"
	}
	for _, ip := range AnswerAddresses(q, m) {
		fmt.Fprintf(&batch, "%s%s %s is %s\n", prefix, kind, name, ip)
	}
	if cause != nil {
		text := cause.Error()
		if len(text) > 512 {
			text = text[:512]
		}
		fmt.Fprintf(&batch, "%sfailure %q\n", prefix, text)
	}
	if elapsed >= slowAnswer {
		fmt.Fprintf(&batch, "%selapsed %dms\n", prefix, elapsed.Milliseconds())
	}
	if batch.Len() > 8192 {
		return nil
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	f, info, err := l.open()
	if err != nil {
		return err
	}
	defer f.Close()
	// Stop growth even if the observer is unavailable. Once its reader catches
	// up it compacts the existing log; at most one bounded batch crosses 64 MiB.
	if info.Size() >= QueryLogLimit {
		return nil
	}
	_, err = f.WriteString(batch.String())
	return err
}

func (l *QueryLogger) Check() error {
	f, _, err := l.open()
	if err != nil {
		return err
	}
	return f.Close()
}

func (l *QueryLogger) open() (*os.File, os.FileInfo, error) {
	fd, err := syscall.Open(l.Path, syscall.O_WRONLY|syscall.O_APPEND|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, nil, err
	}
	f := os.NewFile(uintptr(fd), l.Path)
	info, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, nil, err
	}
	s := info.Sys().(*syscall.Stat_t)
	if !info.Mode().IsRegular() || s.Nlink != 1 || s.Uid != uint32(os.Geteuid()) || info.Mode().Perm()&0o007 != 0 {
		f.Close()
		return nil, nil, fmt.Errorf("unsafe DNS query log")
	}
	return f, info, nil
}
