// Package kademlia implements the core of the Kademlia DHT: identifiers,
// the routing table, and the lookup procedures.
package kademlia

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math/bits"
	"math/rand/v2"
	"net/netip"
)

// IDBits is B, the size of the key/ID space in bits.
const IDBits = 256

// IDLength is the size of a KademliaID in bytes.
const IDLength = IDBits / 8

// KademliaID is a B-bit identifier for a node or a key. Byte 0 is the most
// significant byte (big-endian), so comparing two IDs byte by byte
// compares them as unsigned integers.
//
// KademliaID is an array, not a slice or *big.Int: it is copied by value,
// can be compared with ==, and can be used as a map key.
type KademliaID [IDLength]byte

// NewKademliaID parses a 64-digit hex string into a KademliaID.
func NewKademliaID(s string) (KademliaID, error) {
	var id KademliaID
	if len(s) != 2*IDLength {
		return id, fmt.Errorf("id must be %d hex digits, got %d", 2*IDLength, len(s))
	}
	if _, err := hex.Decode(id[:], []byte(s)); err != nil {
		return id, fmt.Errorf("invalid id %q: %w", s, err)
	}
	return id, nil
}

// NewRandomKademliaID draws an ID from r. Taking the RNG as a parameter
// (instead of using a global one) keeps simulations and tests repeatable.
func NewRandomKademliaID(r *rand.Rand) KademliaID {
	var id KademliaID
	for i := range id {
		id[i] = byte(r.UintN(256))
	}
	return id
}

// RandomIDInBucket returns a random ID in bucket i of self's routing
// table (0 <= i < IDBits): it agrees with self on all bits above bit i,
// differs at bit i, and is random below. Used to refresh bucket i.
func RandomIDInBucket(self KademliaID, i int, r *rand.Rand) KademliaID {
	id := NewRandomKademliaID(r)
	pos := IDBits - 1 - i // position of bit i counted from the most significant bit
	byteIdx, bit := pos/8, byte(0x80>>(pos%8))
	copy(id[:byteIdx], self[:byteIdx]) // whole bytes above bit i
	above := ^(bit | (bit - 1))        // bits above bit i within its byte
	id[byteIdx] = self[byteIdx]&above | ^self[byteIdx]&bit | id[byteIdx]&(bit-1)
	return id
}

// NewNodeID computes a node's ID as SHA-256 of "IP:port". The exact string
// matters: every node must derive the same ID for the same address. An
// IPv4 address seen through a dual-stack socket as ::ffff:a.b.c.d is
// unmapped first, so it hashes the same as a.b.c.d.
func NewNodeID(addr netip.AddrPort) KademliaID {
	addr = netip.AddrPortFrom(addr.Addr().Unmap(), addr.Port())
	return sha256.Sum256([]byte(addr.String()))
}

// KeyFromValue computes the content-addressed key of a value: SHA-256(value).
func KeyFromValue(value []byte) KademliaID {
	return sha256.Sum256(value)
}

// String returns the full 64-digit hex representation.
func (id KademliaID) String() string {
	return hex.EncodeToString(id[:])
}

// MarshalText encodes the ID as hex in JSON (instead of an array of numbers).
func (id KademliaID) MarshalText() ([]byte, error) {
	return []byte(id.String()), nil
}

// UnmarshalText decodes a hex ID from JSON.
func (id *KademliaID) UnmarshalText(b []byte) error {
	v, err := NewKademliaID(string(b))
	if err != nil {
		return err
	}
	*id = v
	return nil
}

// Short returns the first and last 4 hex digits, e.g. "3fa2…09bc",
// for human-readable output such as "show rt".
func (id KademliaID) Short() string {
	s := id.String()
	return s[:4] + "…" + s[len(s)-4:]
}

// CalcDistance returns id XOR target. Read as an integer, this is the
// Kademlia distance d(id, target) (paper §2.1).
func (id KademliaID) CalcDistance(target KademliaID) KademliaID {
	var d KademliaID
	for i := range id {
		d[i] = id[i] ^ target[i]
	}
	return d
}

// Cmp compares id and other as unsigned big-endian integers and returns
// -1, 0, or +1.
func (id KademliaID) Cmp(other KademliaID) int {
	return bytes.Compare(id[:], other[:])
}

// Less reports whether id < other as unsigned integers.
func (id KademliaID) Less(other KademliaID) bool {
	return id.Cmp(other) < 0
}

// CloserTo reports whether a is strictly closer to target than b is,
// i.e. d(a, target) < d(b, target).
func CloserTo(target, a, b KademliaID) bool {
	return a.CalcDistance(target).Less(b.CalcDistance(target))
}

// LeadingZeros returns the number of leading zero bits in id
// (IDBits if id is all zeros).
func (id KademliaID) LeadingZeros() int {
	for i, x := range id {
		if x != 0 {
			return i*8 + bits.LeadingZeros8(x)
		}
	}
	return IDBits
}

// BucketIndex returns the index of the k-bucket in self's routing table
// that other belongs to: the position of the highest bit in which they
// differ. Bucket i holds nodes at distance [2^i, 2^(i+1)). Returns -1 if
// other == self (a node never stores itself).
func BucketIndex(self, other KademliaID) int {
	return IDBits - 1 - self.CalcDistance(other).LeadingZeros()
}
