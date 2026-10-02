package policy

import (
	"math/rand"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func policyFile(t *testing.T, content string) (*Policy, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "policy.conf")
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
	return New(path), path
}

func TestOverlapsAdjacencyDuplicatesAndGaps(t *testing.T) {
	p, _ := policyFile(t, "8.8.9.0/24\n8.8.8.0/25\n8.8.8.64/26\n8.8.8.128/26\n8.8.10.0/24\n8.8.9.0/24\n")
	for _, ip := range []string{"8.8.8.0", "8.8.8.127", "8.8.8.128", "8.8.8.191", "8.8.9.0", "8.8.10.255"} {
		if !p.Allowed(ip) {
			t.Error("denied", ip)
		}
	}
	for _, ip := range []string{"8.8.7.255", "8.8.8.192", "8.8.8.255", "8.8.11.0"} {
		if p.Allowed(ip) {
			t.Error("allowed", ip)
		}
	}
	if p.Ranges() != 2 {
		t.Fatalf("merged ranges = %d, want 2", p.Ranges())
	}
}

func TestEmptyPolicyDeniesEverything(t *testing.T) {
	p, _ := policyFile(t, "")
	if p.Allowed("8.8.8.8") || p.Ranges() != 0 {
		t.Fatal("empty policy authorized an address")
	}
}

func TestCatchAllStillDeniesSpecialAddresses(t *testing.T) {
	p, _ := policyFile(t, "0.0.0.0/0\n")
	if !p.Allowed("8.8.8.8") {
		t.Fatal("catch-all denied a global address")
	}
	for _, ip := range []string{"0.0.0.0", "127.0.0.1", "10.0.0.1", "224.0.0.1", "255.255.255.255", "100.64.0.1", "192.0.0.8"} {
		if p.Allowed(ip) {
			t.Error("special address allowed", ip)
		}
	}
	for _, ip := range []string{"192.0.0.9", "192.0.0.10"} {
		if !p.Allowed(ip) {
			t.Error("globally reachable registry exception denied", ip)
		}
	}
}

func TestAtomicReplacementWithSameSizeAndMtimeRevokesOldRules(t *testing.T) {
	p, path := policyFile(t, "8.8.8.8/32\n")
	if !p.Allowed("8.8.8.8") {
		t.Fatal("initial rule missing")
	}
	before, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	replacement := path + ".new"
	if err := os.WriteFile(replacement, []byte("1.1.1.1/32\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(replacement, time.Time{}, before.ModTime()); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(replacement, path); err != nil {
		t.Fatal(err)
	}
	after, _ := os.Stat(path)
	if after.Size() != before.Size() || !after.ModTime().Equal(before.ModTime()) {
		t.Fatal("fixture did not preserve size and mtime")
	}
	if p.Allowed("8.8.8.8") || !p.Allowed("1.1.1.1") {
		t.Fatal("replaced policy kept stale rules")
	}
}

func TestInvalidReplacementDoesNotKeepPartialOrPreviousIndex(t *testing.T) {
	p, path := policyFile(t, "8.8.8.8/32\n")
	if !p.Allowed("8.8.8.8") {
		t.Fatal("initial rule missing")
	}
	os.WriteFile(path, []byte("1.1.1.1/32\ninvalid\n"), 0644)
	for _, ip := range []string{"8.8.8.8", "1.1.1.1"} {
		if p.Allowed(ip) {
			t.Error("invalid policy authorized", ip)
		}
	}
	if p.Ranges() != 0 {
		t.Fatal("invalid policy kept an index")
	}
	os.WriteFile(path, []byte("1.1.1.1/32\n"), 0644)
	if !p.Allowed("1.1.1.1") {
		t.Fatal("valid policy not reloaded")
	}
	os.Remove(path)
	if p.Allowed("1.1.1.1") {
		t.Fatal("missing policy authorized an address")
	}
}

func TestNetworkSyntaxMatchesStrictPythonParsing(t *testing.T) {
	valid := map[string][2]string{
		"1.2.3.0/24":            {"1.2.3.0", "1.2.3.255"},
		"1.2.3.4":               {"1.2.3.4", "1.2.3.4"},
		"1.2.3.0/255.255.255.0": {"1.2.3.0", "1.2.3.255"},
		"1.2.3.0/0.0.0.255":     {"1.2.3.0", "1.2.3.255"},
		"1.2.3.0/032":           {"1.2.3.0", "1.2.3.0"},
		"0.0.0.0/0":             {"0.0.0.0", "255.255.255.255"},
	}
	for value, want := range valid {
		first, last, err := ParseNetwork(value)
		if err != nil || first != toUint32(netip.MustParseAddr(want[0])) || last != toUint32(netip.MustParseAddr(want[1])) {
			t.Errorf("%s: %d %d %v", value, first, last, err)
		}
	}
	for _, value := range []string{"1.2.3.4/24", "1.2.3.0/33", "01.2.3.0/24", "1.2.3.0/", "1.2.3.0/24/1",
		"1.2.3.0/255.0.255.0", "::1/128", "1.2.3", "1.2.3.0/ 24", "1.2.3.0/+24"} {
		if _, _, err := ParseNetwork(value); err == nil {
			t.Error("accepted", value)
		}
	}
}

func TestPolicyFileTextRules(t *testing.T) {
	p, _ := policyFile(t, "# comment\r\n8.8.8.0/24 # trailing comment\r\n\t9.9.9.9\x1f\r10.0.0.0/8\n")
	for _, ip := range []string{"8.8.8.1", "9.9.9.9"} {
		if !p.Allowed(ip) {
			t.Error("denied", ip)
		}
	}
	nonASCII, _ := policyFile(t, "8.8.8.0/24 # caf\xc3\xa9\n")
	if nonASCII.Allowed("8.8.8.1") {
		t.Fatal("non-ASCII policy file accepted")
	}
}

func TestAddressSyntaxIsStrict(t *testing.T) {
	p, _ := policyFile(t, "0.0.0.0/0\n")
	for _, ip := range []string{"::1", "0x08080808", "008.008.008.008", "999.1.1.1", "8.8.8", "8.8.8.8 ",
		"::ffff:8.8.8.8", "8.8.8.8/32", "", "8.8.8.8%en0"} {
		if p.Allowed(ip) {
			t.Error("accepted", ip)
		}
	}
}

// The reference is the definition itself: global, not multicast and inside
// one of the listed networks.
func TestIndexMatchesLinearReferenceAtAllGeneratedBoundaries(t *testing.T) {
	rng := rand.New(rand.NewSource(20260926))
	var lines []string
	var networks [][2]uint32
	for i := 0; i < 128; i++ {
		bits := 8 + rng.Intn(25)
		mask := ^uint32(0) << (32 - bits)
		first := rng.Uint32() & mask
		networks = append(networks, [2]uint32{first, first | ^mask})
		lines = append(lines, netip.AddrFrom4([4]byte{byte(first >> 24), byte(first >> 16), byte(first >> 8), byte(first)}).String()+"/"+strconv.Itoa(bits))
	}
	p, _ := policyFile(t, strings.Join(lines, "\n")+"\n")
	values := map[uint32]bool{}
	for i := 0; i < 512; i++ {
		values[rng.Uint32()] = true
	}
	for _, n := range networks {
		for _, v := range []uint32{n[0], n[1]} {
			for _, d := range []int64{-1, 0, 1} {
				if w := int64(v) + d; w >= 0 && w <= 0xffffffff {
					values[uint32(w)] = true
				}
			}
		}
	}
	for value := range values {
		address := netip.AddrFrom4([4]byte{byte(value >> 24), byte(value >> 16), byte(value >> 8), byte(value)})
		expected := Global(address) && !multicast.Contains(address)
		if expected {
			expected = false
			for _, n := range networks {
				if value >= n[0] && value <= n[1] {
					expected = true
					break
				}
			}
		}
		if p.Allowed(address.String()) != expected {
			t.Fatalf("%s: allowed=%v want %v", address, !expected, expected)
		}
	}
}

// Repository lists are the reviewed production policy.
func TestRepositoryPolicyApprovesDomesticAndDeniesForeign(t *testing.T) {
	p := New("../../../config/china_ip_list.txt", "../../../config/domestic_extra_routes.txt")
	for _, ip := range []string{"223.5.5.5", "119.29.29.29", "128.14.180.34"} {
		if !p.Allowed(ip) {
			t.Error("denied", ip)
		}
	}
	for _, ip := range []string{"1.1.1.1", "8.8.8.8", "127.0.0.1", "192.168.1.1", "224.0.0.1", "47.241.205.204"} {
		if p.Allowed(ip) {
			t.Error("allowed", ip)
		}
	}
}
