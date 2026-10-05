package dnsservice

import (
	"container/list"
	"fmt"
	"sync"
	"time"

	"github.com/miekg/dns"
)

const cacheByteLimit = 32 << 20

type cached struct {
	key             string
	message         *dns.Msg
	stored, expires time.Time
	size            int
}

type answerCache struct {
	mu           sync.Mutex
	entries      map[string]*list.Element
	order        *list.List
	bytes, limit int
}

func newCache(limit int) *answerCache {
	return &answerCache{entries: map[string]*list.Element{}, order: list.New(), limit: limit}
}

func queryKey(q *dns.Msg) string {
	if len(q.Question) != 1 || !q.RecursionDesired || q.IsTsig() != nil {
		return ""
	}
	do, edns := false, false
	if len(q.Extra) > 0 {
		opt := q.IsEdns0()
		if len(q.Extra) != 1 || opt == nil || opt.Version() != 0 || len(opt.Option) > 0 {
			return ""
		}
		do = opt.Do()
		edns = true
	}
	question := q.Question[0]
	return fmt.Sprintf("%s/%d/%d/%t/%t/%t/%t", dns.CanonicalName(question.Name), question.Qtype, question.Qclass, do, edns, q.CheckingDisabled, q.AuthenticatedData)
}

func allRecords(m *dns.Msg) []dns.RR {
	r := make([]dns.RR, 0, len(m.Answer)+len(m.Ns)+len(m.Extra))
	r = append(r, m.Answer...)
	r = append(r, m.Ns...)
	return append(r, m.Extra...)
}

func lifetime(m *dns.Msg, cap uint32) uint32 {
	if opt := m.IsEdns0(); opt != nil && len(opt.Option) > 0 {
		return 0
	}
	if m.Truncated || (m.Rcode != dns.RcodeSuccess && m.Rcode != dns.RcodeNameError) {
		return 0
	}
	ttl, seen := cap, false
	if m.Rcode == dns.RcodeNameError || len(m.Answer) == 0 {
		for _, rr := range m.Ns {
			if soa, ok := rr.(*dns.SOA); ok {
				ttl = min(ttl, soa.Hdr.Ttl, soa.Minttl)
				seen = true
			}
		}
	}
	if seen || len(m.Answer) > 0 {
		for _, rr := range allRecords(m) {
			if rr.Header().Rrtype != dns.TypeOPT {
				ttl = min(ttl, rr.Header().Ttl)
				seen = true
			}
		}
	}
	if !seen || ttl > 1<<31-1 {
		return 0
	}
	return ttl
}

func (c *answerCache) remove(e *list.Element) {
	v := e.Value.(*cached)
	c.bytes -= v.size
	delete(c.entries, v.key)
	c.order.Remove(e)
}

func (c *answerCache) get(key string, q *dns.Msg, now time.Time) *dns.Msg {
	if key == "" {
		return nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	e := c.entries[key]
	if e == nil {
		return nil
	}
	v := e.Value.(*cached)
	if !now.Before(v.expires) {
		c.remove(e)
		return nil
	}
	c.order.MoveToBack(e)
	m := v.message.Copy()
	seconds := uint32(max(0, now.Sub(v.stored)/time.Second))
	for _, rr := range allRecords(m) {
		if rr.Header().Rrtype != dns.TypeOPT {
			ttl := rr.Header().Ttl
			rr.Header().Ttl = ttl - min(ttl, seconds)
		}
	}
	m.Id = q.Id
	m.Question = append([]dns.Question(nil), q.Question...)
	return m
}

func (c *answerCache) put(key string, m *dns.Msg, cap uint32, now time.Time) {
	ttl := lifetime(m, cap)
	if key == "" || c.limit == 0 || ttl == 0 {
		return
	}
	size := m.Len() + len(key) + 256*(len(allRecords(m))+1)
	if size > cacheByteLimit {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if e := c.entries[key]; e != nil {
		c.remove(e)
	}
	for c.order.Len() >= c.limit || c.bytes+size > cacheByteLimit {
		c.remove(c.order.Front())
	}
	v := &cached{key: key, message: m.Copy(), stored: now, expires: now.Add(time.Duration(ttl) * time.Second), size: size}
	c.entries[key] = c.order.PushBack(v)
	c.bytes += size
}
