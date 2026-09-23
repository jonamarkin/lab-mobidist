// Package kademlia implements the core of the Kademlia DHT: identifiers,
// the routing table, and the lookup procedures.
package kademlia

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math/bits"
	"net"
	"strconv"
)

// IDBits is B, the size of the key/ID space in bits.
const IDBits = 256

// IDBytes is the size of an ID in bytes.
const IDBytes = IDBits / 8

// ID is a B-bit identifier for a node or a key. Byte 0 is the most
// significant byte (big-endian), so comparing two IDs byte by byte
// compares them as unsigned integers.
//
// ID is an array, not a slice or *big.Int: it is copied by value, can be
// compared with ==, and can be used as a map key.
type ID [IDBytes]byte

// NodeIDFromAddr computes a node's ID as SHA-256 of "IP:port". The exact
// string format matters: every node must derive the same ID for the same
// address, so it is always built with net.JoinHostPort.
func NodeIDFromAddr(ip string, port int) ID {
	return sha256.Sum256([]byte(net.JoinHostPort(ip, strconv.Itoa(port))))
}

// KeyFromValue computes the content-addressed key of a value: SHA-256(value).
func KeyFromValue(value []byte) ID {
	return sha256.Sum256(value)
}

// ParseID parses a 64-digit hex string into an ID.
func ParseID(s string) (ID, error) {
	var id ID
	if len(s) != 2*IDBytes {
		return id, fmt.Errorf("id must be %d hex digits, got %d", 2*IDBytes, len(s))
	}
	if _, err := hex.Decode(id[:], []byte(s)); err != nil {
		return id, fmt.Errorf("invalid id %q: %w", s, err)
	}
	return id, nil
}

// String returns the full 64-digit hex representation.
func (a ID) String() string {
	return hex.EncodeToString(a[:])
}

// Short returns the first and last 4 hex digits, e.g. "3fa2…09bc",
// for human-readable output such as "show rt".
func (a ID) Short() string {
	s := a.String()
	return s[:4] + "…" + s[len(s)-4:]
}

// Xor returns a XOR b. Read as an integer, this is the Kademlia distance
// d(a, b) (paper §2.1).
func (a ID) Xor(b ID) ID {
	var d ID
	for i := range a {
		d[i] = a[i] ^ b[i]
	}
	return d
}

// Cmp compares a and b as unsigned big-endian integers and returns
// -1, 0, or +1.
func (a ID) Cmp(b ID) int {
	return bytes.Compare(a[:], b[:])
}

// CloserTo reports whether a is strictly closer to target than b is,
// i.e. d(a, target) < d(b, target).
func CloserTo(target, a, b ID) bool {
	return a.Xor(target).Cmp(b.Xor(target)) < 0
}

// LeadingZeros returns the number of leading zero bits in a
// (IDBits if a is all zeros).
func (a ID) LeadingZeros() int {
	for i, x := range a {
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
func BucketIndex(self, other ID) int {
	return IDBits - 1 - self.Xor(other).LeadingZeros()
}
