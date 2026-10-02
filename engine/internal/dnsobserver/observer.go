// Package dnsobserver watches dnsmasq's query log and promptly binds domestic
// CDN addresses to Ethernet. It never proxies DNS: if it stops, dnsmasq keeps
// resolving and the route guard remains the fallback.
package dnsobserver

import (
	"container/list"
	"os"
	"regexp"
	"strings"
	"time"
	"unicode"
)

const (
	QueryTTL          = 30 * time.Second
	MaxPendingQueries = 4096
)

var (
	queryPattern  = regexp.MustCompile(`dnsmasq\[(\d+)\]:\s+(\d+)\s+(\S+)\s+query\[[^\]]+\]\s+(\S+)\s+from`)
	answerPattern = regexp.MustCompile(`dnsmasq\[(\d+)\]:\s+(\d+)\s+(\S+)\s+(?:reply|cached)\s+(\S+)\s+is\s+(\S+)`)
	ipv4Pattern   = regexp.MustCompile(`^(?:\d{1,3}\.){3}\d{1,3}$`)
)

// Normalize lowercases a DNS name and drops its trailing dots.
func Normalize(name string) string { return strings.ToLower(strings.TrimRight(name, ".")) }

// LoadSuffixes reads the domains dnsmasq forwards to specific servers; every
// such domain, and "cn", counts as domestic.
func LoadSuffixes(path string) (map[string]bool, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	suffixes := map[string]bool{"cn": true}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimFunc(line, func(r rune) bool { return unicode.IsSpace(r) || (r >= 0x1c && r <= 0x1f) })
		if !strings.HasPrefix(line, "server=/") {
			continue
		}
		if parts := strings.Split(line, "/"); len(parts) >= 3 && parts[1] != "" {
			suffixes[Normalize(parts[1])] = true
		}
	}
	return suffixes, nil
}

type queryKey struct{ pid, id, client string }

type pendingQuery struct {
	key    queryKey
	domain string
	at     time.Time
}

// Correlator remembers domestic queries for a bounded time, so a CNAME answer
// is classified by the query it belongs to and never by a shared CDN alias.
// It is not safe for concurrent use.
type Correlator struct {
	Suffixes map[string]bool
	Bind     func(domain, ip string)
	Now      func() time.Time
	TTL      time.Duration
	Max      int
	order    *list.List // insertion order is also expiry order
	pending  map[queryKey]*list.Element
}

func NewCorrelator(suffixes map[string]bool, bind func(domain, ip string)) *Correlator {
	return &Correlator{Suffixes: suffixes, Bind: bind, Now: time.Now, TTL: QueryTTL, Max: MaxPendingQueries,
		order: list.New(), pending: map[queryKey]*list.Element{}}
}

// Domestic reports whether name equals a domestic suffix or is beneath one.
func (c *Correlator) Domestic(name string) bool {
	name = Normalize(name)
	for {
		if c.Suffixes[name] {
			return true
		}
		index := strings.IndexByte(name, '.')
		if index < 0 {
			return false
		}
		name = name[index+1:]
	}
}

// Pending returns the remembered queries, oldest first, as "pid/id/client".
func (c *Correlator) Pending() []string {
	var keys []string
	for e := c.order.Front(); e != nil; e = e.Next() {
		k := e.Value.(*pendingQuery).key
		keys = append(keys, k.pid+"/"+k.id+"/"+k.client)
	}
	return keys
}

// Clear forgets every remembered query.
func (c *Correlator) Clear() {
	c.order.Init()
	clear(c.pending)
}

func (c *Correlator) remove(e *list.Element) {
	delete(c.pending, c.order.Remove(e).(*pendingQuery).key)
}

// ProcessLine handles one dnsmasq log line.
func (c *Correlator) ProcessLine(line string) {
	now := c.Now()
	for front := c.order.Front(); front != nil; front = c.order.Front() {
		if now.Sub(front.Value.(*pendingQuery).at) < c.TTL {
			break
		}
		c.remove(front)
	}
	if match := queryPattern.FindStringSubmatch(line); match != nil {
		key := queryKey{match[1], match[2], match[3]}
		if e, ok := c.pending[key]; ok {
			c.remove(e)
		}
		if domain := Normalize(match[4]); c.Domestic(domain) {
			if len(c.pending) >= c.Max {
				c.remove(c.order.Front())
			}
			c.pending[key] = c.order.PushBack(&pendingQuery{key: key, domain: domain, at: now})
		}
		return
	}
	match := answerPattern.FindStringSubmatch(line)
	if match == nil {
		return
	}
	key := queryKey{match[1], match[2], match[3]}
	name, value := Normalize(match[4]), Normalize(match[5])
	origin := name
	if e, ok := c.pending[key]; ok {
		origin = e.Value.(*pendingQuery).domain
	}
	if ipv4Pattern.MatchString(value) && (c.Domestic(name) || c.Domestic(origin)) {
		c.Bind(origin, value)
	}
	// CNAME answers share the query identity. Never retain global CDN aliases.
}
