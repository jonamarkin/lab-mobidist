package kademlia

import (
	"fmt"
	"net/netip"
	"slices"
)

// Contact is what a node knows about another node: its ID and where to
// reach it. It is a small value type (copied, comparable with ==).
type Contact struct {
	ID      KademliaID
	Address netip.AddrPort
}

// NewContact returns a Contact. In a running network the ID is always
// NewNodeID(address); tests may pick IDs freely.
func NewContact(id KademliaID, address netip.AddrPort) Contact {
	return Contact{ID: id, Address: address}
}

// String returns a short human-readable form, e.g. "3fa2…09bc@10.0.0.1:8000".
func (c Contact) String() string {
	return fmt.Sprintf("%s@%s", c.ID.Short(), c.Address)
}

// SortContactsByDistance sorts contacts in place, closest to target first.
// Distances are kept in a temporary slice rather than stored in the
// Contact, so the same contacts can be sorted for different targets
// concurrently. Each distance is computed once (n XORs) instead of in
// every comparison (about 2·n·log n XORs). Distinct IDs never tie (XOR is
// unidirectional), so the order is unique.
func SortContactsByDistance(contacts []Contact, target KademliaID) {
	type entry struct {
		dist    KademliaID
		contact Contact
	}
	entries := make([]entry, len(contacts))
	for i, c := range contacts {
		entries[i] = entry{c.ID.CalcDistance(target), c}
	}
	slices.SortFunc(entries, func(a, b entry) int {
		return a.dist.Cmp(b.dist)
	})
	for i, e := range entries {
		contacts[i] = e.contact
	}
}
