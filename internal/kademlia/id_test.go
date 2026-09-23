package kademlia

import (
	"math/big"
	"math/rand/v2"
	"strings"
	"testing"
)

// idLow returns an ID whose only non-zero byte is the last one. This lets
// us reuse small worked examples (e.g. 4-bit IDs) in the 256-bit space.
func idLow(b byte) ID {
	var id ID
	id[IDBytes-1] = b
	return id
}

// randomID draws an ID from a seeded RNG so failures are reproducible.
func randomID(r *rand.Rand) ID {
	var id ID
	for i := range id {
		id[i] = byte(r.UintN(256))
	}
	return id
}

func toBig(a ID) *big.Int { return new(big.Int).SetBytes(a[:]) }

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
	}
	for _, c := range cases {
		other := idLow(c.other)
		if got := self.Xor(other); got != idLow(c.dist) {
			t.Errorf("d(0110, %04b) = %v, want %d", c.other, got, c.dist)
		}
		if got := BucketIndex(self, other); got != c.bucket {
			t.Errorf("BucketIndex(0110, %04b) = %d, want %d", c.other, got, c.bucket)
		}
	}
}

func TestBucketIndexExtremes(t *testing.T) {
	var zero ID
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
	var zero ID
	if got := zero.LeadingZeros(); got != IDBits {
		t.Errorf("zero ID: got %d, want %d", got, IDBits)
	}
	var id ID
	id[2] = 0x10 // 2 zero bytes (16 bits) + 3 zero bits in 0001_0000
	if got := id.LeadingZeros(); got != 19 {
		t.Errorf("got %d, want 19", got)
	}
}

// XOR metric properties from paper §2.1, checked on random IDs.
func TestXorMetricProperties(t *testing.T) {
	r := rand.New(rand.NewPCG(1, 2))
	var zero ID
	for range 1000 {
		a, b, c := randomID(r), randomID(r), randomID(r)

		if a.Xor(a) != zero {
			t.Fatal("d(a,a) != 0")
		}
		if a != b && a.Xor(b) == zero {
			t.Fatal("d(a,b) == 0 for a != b")
		}
		if a.Xor(b) != b.Xor(a) {
			t.Fatal("d(a,b) != d(b,a)")
		}
		// Triangle inequality: d(a,c) <= d(a,b) + d(b,c).
		sum := new(big.Int).Add(toBig(a.Xor(b)), toBig(b.Xor(c)))
		if toBig(a.Xor(c)).Cmp(sum) > 0 {
			t.Fatal("triangle inequality violated")
		}
		// Unidirectionality: the point at distance d from a is a^d.
		d := randomID(r)
		if a.Xor(a.Xor(d)) != d {
			t.Fatal("a ^ (a ^ d) != d")
		}
		// CloserTo agrees with numeric comparison of distances.
		want := toBig(a.Xor(c)).Cmp(toBig(b.Xor(c))) < 0
		if got := CloserTo(c, a, b); got != want {
			t.Fatalf("CloserTo = %v, want %v", got, want)
		}
	}
}

func TestCmp(t *testing.T) {
	a, b := idLow(1), idLow(2)
	if a.Cmp(b) != -1 || b.Cmp(a) != 1 || a.Cmp(a) != 0 {
		t.Error("Cmp does not order IDs numerically")
	}
}

func TestParseIDRoundTrip(t *testing.T) {
	r := rand.New(rand.NewPCG(3, 4))
	id := randomID(r)
	got, err := ParseID(id.String())
	if err != nil || got != id {
		t.Fatalf("round trip failed: %v, %v", got, err)
	}
}

func TestParseIDErrors(t *testing.T) {
	for _, s := range []string{
		"",
		"abcd",                  // too short
		strings.Repeat("z", 64), // not hex
		strings.Repeat("0", 65), // too long
	} {
		if _, err := ParseID(s); err == nil {
			t.Errorf("ParseID(%q) succeeded, want error", s)
		}
	}
}

func TestShort(t *testing.T) {
	id, _ := ParseID("3fa2" + strings.Repeat("0", 56) + "09bc")
	if got := id.Short(); got != "3fa2…09bc" {
		t.Errorf("Short() = %q", got)
	}
}

func TestNodeIDFromAddr(t *testing.T) {
	a := NodeIDFromAddr("10.0.0.1", 8000)
	if a != NodeIDFromAddr("10.0.0.1", 8000) {
		t.Error("same address gave different IDs")
	}
	if a == NodeIDFromAddr("10.0.0.1", 8001) {
		t.Error("different ports gave the same ID")
	}
	// Pin the exact input format "IP:port".
	if a != KeyFromValue([]byte("10.0.0.1:8000")) {
		t.Error("node ID is not SHA-256 of \"IP:port\"")
	}
}
