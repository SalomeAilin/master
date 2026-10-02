// Package policy authorizes DNS-derived Ethernet routes from the root-owned
// China address list and explicit extra routes, independently of domain names.
package policy

import (
	"cmp"
	"encoding/binary"
	"errors"
	"net/netip"
	"os"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
)

// Files are the production address lists.
var Files = []string{"/usr/local/etc/china_ip_list.txt", "/usr/local/etc/domestic_extra_routes.txt"}

// Address classes follow Python 3.13's ipaddress module, which defined the
// policy before this port: is_global excludes shared address space and the
// IANA special registry except two globally reachable 192.0.0.0/24 hosts.
var (
	sharedAddressSpace = netip.MustParsePrefix("100.64.0.0/10")
	multicast          = netip.MustParsePrefix("224.0.0.0/4")
	privateNetworks    = prefixes("0.0.0.0/8", "10.0.0.0/8", "127.0.0.0/8", "169.254.0.0/16",
		"172.16.0.0/12", "192.0.0.0/24", "192.0.0.170/31", "192.0.2.0/24", "192.168.0.0/16",
		"198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "240.0.0.0/4", "255.255.255.255/32")
	privateExceptions = prefixes("192.0.0.9/32", "192.0.0.10/32")
)

func prefixes(values ...string) []netip.Prefix {
	result := make([]netip.Prefix, len(values))
	for i, value := range values {
		result[i] = netip.MustParsePrefix(value)
	}
	return result
}

type fileSignature struct {
	path         string
	dev          int64
	ino          uint64
	mtime, ctime int64
	size         int64
}

// Policy caches the merged ranges of its files and reloads them whenever a
// file's identity, timestamps or size change. It is safe for concurrent use.
type Policy struct {
	files        []string
	mu           sync.Mutex
	signature    []fileSignature
	starts, ends []uint32
}

func New(files ...string) *Policy {
	return &Policy{files: append([]string(nil), files...)}
}

// Allowed reports whether ip is a globally routable, non-multicast IPv4
// address inside the policy. A missing, unreadable or malformed file
// authorizes nothing, and nothing from the previous load is kept.
func (p *Policy) Allowed(ip string) bool {
	address, ok := ParseIPv4(ip)
	if !ok || !Global(address) || multicast.Contains(address) {
		return false
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if err := p.refresh(); err != nil {
		p.signature, p.starts, p.ends = nil, nil, nil
		return false
	}
	value := toUint32(address)
	index := sort.Search(len(p.starts), func(i int) bool { return p.starts[i] > value }) - 1
	return index >= 0 && value <= p.ends[index]
}

// Ranges returns the number of merged ranges currently loaded, for tests.
func (p *Policy) Ranges() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.starts)
}

func (p *Policy) refresh() error {
	signature := make([]fileSignature, 0, len(p.files))
	for _, path := range p.files {
		var status syscall.Stat_t
		if err := syscall.Stat(path, &status); err != nil {
			return err
		}
		signature = append(signature, fileSignature{path, int64(status.Dev), status.Ino,
			status.Mtimespec.Nano(), status.Ctimespec.Nano(), status.Size})
	}
	if p.signature != nil && slices.Equal(signature, p.signature) {
		return nil
	}
	var ranges [][2]uint32
	for _, path := range p.files {
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		lines, err := asciiLines(data)
		if err != nil {
			return err
		}
		for _, line := range lines {
			value, _, _ := strings.Cut(line, "#")
			if value = trimSpace(value); value == "" {
				continue
			}
			first, last, err := ParseNetwork(value)
			if err != nil {
				return err
			}
			ranges = append(ranges, [2]uint32{first, last})
		}
	}
	slices.SortFunc(ranges, func(a, b [2]uint32) int {
		return cmp.Or(cmp.Compare(a[0], b[0]), cmp.Compare(a[1], b[1]))
	})
	// Merge only overlapping or adjacent ranges; gaps remain unauthorized.
	var starts, ends []uint32
	for _, r := range ranges {
		if n := len(ends); n > 0 && uint64(r[0]) <= uint64(ends[n-1])+1 {
			ends[n-1] = max(ends[n-1], r[1])
			continue
		}
		starts, ends = append(starts, r[0]), append(ends, r[1])
	}
	p.signature, p.starts, p.ends = signature, starts, ends
	return nil
}

// asciiLines splits text the way Python's universal newlines do and rejects
// any byte outside ASCII, matching the previous ascii-decoded policy reader.
func asciiLines(data []byte) ([]string, error) {
	for _, b := range data {
		if b >= 0x80 {
			return nil, errors.New("policy file is not ASCII")
		}
	}
	text := strings.ReplaceAll(string(data), "\r\n", "\n")
	text = strings.ReplaceAll(text, "\r", "\n")
	return strings.Split(text, "\n"), nil
}

// trimSpace strips the ASCII characters Python's str.strip() treats as space.
func trimSpace(value string) string {
	return strings.TrimFunc(value, func(r rune) bool {
		return r == ' ' || (r >= '\t' && r <= '\r') || (r >= 0x1c && r <= 0x1f)
	})
}

// ParseIPv4 accepts only canonical dotted-decimal IPv4 without leading zeros.
func ParseIPv4(text string) (netip.Addr, bool) {
	address, err := netip.ParseAddr(text)
	if err != nil || !address.Is4() {
		return netip.Addr{}, false
	}
	return address, true
}

// Global mirrors Python's IPv4Address.is_global.
func Global(address netip.Addr) bool {
	if sharedAddressSpace.Contains(address) {
		return false
	}
	private := false
	for _, network := range privateNetworks {
		if network.Contains(address) {
			private = true
			break
		}
	}
	if private {
		for _, network := range privateExceptions {
			if network.Contains(address) {
				return true
			}
		}
	}
	return !private
}

// ParseNetwork parses a strict IPv4 network the way Python's IPv4Network does:
// a bare address is a /32, the mask may be a prefix length, netmask or
// hostmask, and host bits must be zero.
func ParseNetwork(value string) (first, last uint32, err error) {
	parts := strings.Split(value, "/")
	if len(parts) > 2 {
		return 0, 0, errors.New("invalid network")
	}
	address, ok := ParseIPv4(parts[0])
	if !ok {
		return 0, 0, errors.New("invalid network address")
	}
	bits := 32
	if len(parts) == 2 {
		if bits, err = parseMask(parts[1]); err != nil {
			return 0, 0, err
		}
	}
	var mask uint32
	if bits > 0 {
		mask = ^uint32(0) << (32 - bits)
	}
	first = toUint32(address)
	if first&^mask != 0 {
		return 0, 0, errors.New("network has host bits set")
	}
	return first, first | ^mask, nil
}

// ParsePrefix is ParseNetwork returning the canonical prefix.
func ParsePrefix(value string) (netip.Prefix, error) {
	first, last, err := ParseNetwork(value)
	if err != nil {
		return netip.Prefix{}, err
	}
	bits := 32
	for span := uint64(last) - uint64(first) + 1; span > 1; span >>= 1 {
		bits--
	}
	var octets [4]byte
	binary.BigEndian.PutUint32(octets[:], first)
	return netip.PrefixFrom(netip.AddrFrom4(octets), bits), nil
}

func parseMask(text string) (int, error) {
	if text != "" && strings.Trim(text, "0123456789") == "" {
		bits, err := strconv.Atoi(text)
		if err != nil || bits > 32 {
			return 0, errors.New("invalid prefix length")
		}
		return bits, nil
	}
	mask, ok := ParseIPv4(text)
	if !ok {
		return 0, errors.New("invalid netmask")
	}
	value := toUint32(mask)
	if bits, ok := contiguousPrefix(value); ok {
		return bits, nil
	}
	if bits, ok := contiguousPrefix(^value); ok {
		return bits, nil
	}
	return 0, errors.New("invalid netmask")
}

func contiguousPrefix(value uint32) (int, bool) {
	if value == 0 {
		return 0, true
	}
	zeros := 0
	for value&(1<<zeros) == 0 {
		zeros++
	}
	bits := 32 - zeros
	return bits, uint64(value>>zeros) == uint64(1)<<bits-1
}

func toUint32(address netip.Addr) uint32 {
	octets := address.As4()
	return binary.BigEndian.Uint32(octets[:])
}
