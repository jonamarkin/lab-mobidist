package kademlia

import (
	"math/big"
	"math/rand/v2"
	"net/netip"
	"strings"
	"testing"
)

// idLow returns an ID whose only non-zero byte is the last one. This lets
// us reuse small worked examples (e.g. 4-bit IDs) in the 256-bit space.
func idLow(b byte) KademliaID {
	var id KademliaID
	id[IDLength-1] = b
	return id
}

func toBig(id KademliaID) *big.Int { return new(big.Int).SetBytes(id[:]) }

// The 4-bit worked example: self = 0110.
func TestBucketIndexWorkedExample(t *testing.T) {
	self := idLow(0b0110)
	cases := []struct {
		other  byte
		dist   byte
		bucket int
	}{
		{0b0111, 1, 0},
		{0b0100, 2, 1},
		{0b0101, 3, 1},
		{0b0010, 4, 2},
		{0b1000, 14, 3},
		{0b1111, 9, 3},
		{0b1110, 8, 3},
	}
	for _, c := range cases {
		other := idLow(c.other)
		if got := self.CalcDistance(other); got != idLow(c.dist) {
			t.Errorf("d(0110, %04b) = %v, want %d", c.other, got, c.dist)
		}
		if got := BucketIndex(self, other); got != c.bucket {
			t.Errorf("BucketIndex(0110, %04b) = %d, want %d", c.other, got, c.bucket)
		}
	}
}

func TestBucketIndexExtremes(t *testing.T) {
	var zero KademliaID
	msb := zero
	msb[0] = 0x80   // differs only in bit 255
	lsb := idLow(1) // differs only in bit 0

	if got := BucketIndex(zero, msb); got != 255 {
		t.Errorf("MSB differs: got %d, want 255", got)
	}
	if got := BucketIndex(zero, lsb); got != 0 {
		t.Errorf("LSB differs: got %d, want 0", got)
	}
	if got := BucketIndex(msb, msb); got != -1 {
		t.Errorf("equal IDs: got %d, want -1", got)
	}
}

func TestLeadingZeros(t *testing.T) {
	var zero KademliaID
	if got := zero.LeadingZeros(); got != IDBits {
		t.Errorf("zero ID: got %d, want %d", got, IDBits)
	}
	var id KademliaID
	id[2] = 0x10 // 2 zero bytes (16 bits) + 3 zero bits in 0001_0000
	if got := id.LeadingZeros(); got != 19 {
		t.Errorf("got %d, want 19", got)
	}
}

// XOR metric properties from paper §2.1, checked on random IDs.
func TestXorMetricProperties(t *testing.T) {
	r := rand.New(rand.NewPCG(1, 2))
	var zero KademliaID
	for range 1000 {
		a, b, c := NewRandomKademliaID(r), NewRandomKademliaID(r), NewRandomKademliaID(r)

		if a.CalcDistance(a) != zero {
			t.Fatal("d(a,a) != 0")
		}
		if a != b && a.CalcDistance(b) == zero {
			t.Fatal("d(a,b) == 0 for a != b")
		}
		if a.CalcDistance(b) != b.CalcDistance(a) {
			t.Fatal("d(a,b) != d(b,a)")
		}
		// Triangle inequality: d(a,c) <= d(a,b) + d(b,c).
		sum := new(big.Int).Add(toBig(a.CalcDistance(b)), toBig(b.CalcDistance(c)))
		if toBig(a.CalcDistance(c)).Cmp(sum) > 0 {
			t.Fatal("triangle inequality violated")
		}
		// Unidirectionality: the point at distance d from a is a^d.
		d := NewRandomKademliaID(r)
		if a.CalcDistance(a.CalcDistance(d)) != d {
			t.Fatal("a ^ (a ^ d) != d")
		}
		// CloserTo agrees with numeric comparison of distances.
		want := toBig(a.CalcDistance(c)).Cmp(toBig(b.CalcDistance(c))) < 0
		if got := CloserTo(c, a, b); got != want {
			t.Fatalf("CloserTo = %v, want %v", got, want)
		}
	}
}

func TestCmpAndLess(t *testing.T) {
	a, b := idLow(1), idLow(2)
	if a.Cmp(b) != -1 || b.Cmp(a) != 1 || a.Cmp(a) != 0 {
		t.Error("Cmp does not order IDs numerically")
	}
	if !a.Less(b) || b.Less(a) || a.Less(a) {
		t.Error("Less does not order IDs numerically")
	}
}

func TestNewKademliaIDRoundTrip(t *testing.T) {
	r := rand.New(rand.NewPCG(3, 4))
	id := NewRandomKademliaID(r)
	got, err := NewKademliaID(id.String())
	if err != nil || got != id {
		t.Fatalf("round trip failed: %v, %v", got, err)
	}
}

func TestNewKademliaIDErrors(t *testing.T) {
	for _, s := range []string{
		"",
		"abcd",                  // too short
		strings.Repeat("f", 40), // 160-bit ID (crashes the starter code)
		strings.Repeat("z", 64), // not hex
		strings.Repeat("0", 65), // too long
	} {
		if _, err := NewKademliaID(s); err == nil {
			t.Errorf("NewKademliaID(%q) succeeded, want error", s)
		}
	}
}

func TestNewRandomKademliaIDRepeatable(t *testing.T) {
	a := NewRandomKademliaID(rand.New(rand.NewPCG(5, 6)))
	b := NewRandomKademliaID(rand.New(rand.NewPCG(5, 6)))
	if a != b {
		t.Error("same seed gave different IDs")
	}
}

func TestShort(t *testing.T) {
	id, _ := NewKademliaID("3fa2" + strings.Repeat("0", 56) + "09bc")
	if got := id.Short(); got != "3fa2…09bc" {
		t.Errorf("Short() = %q", got)
	}
}

func TestNewNodeID(t *testing.T) {
	addr := netip.MustParseAddrPort("10.0.0.1:8000")
	a := NewNodeID(addr)
	if a != NewNodeID(addr) {
		t.Error("same address gave different IDs")
	}
	if a == NewNodeID(netip.MustParseAddrPort("10.0.0.1:8001")) {
		t.Error("different ports gave the same ID")
	}
	// Pin the exact input format "IP:port".
	if a != KeyFromValue([]byte("10.0.0.1:8000")) {
		t.Error("node ID is not SHA-256 of \"IP:port\"")
	}
	// An IPv4-mapped IPv6 address is the same node.
	if a != NewNodeID(netip.MustParseAddrPort("[::ffff:10.0.0.1]:8000")) {
		t.Error("IPv4-mapped address gave a different ID")
	}
}
