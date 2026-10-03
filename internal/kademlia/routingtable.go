package kademlia

import (
	"maps"
	"slices"
	"sync"
)

// RoutingTable is the set of contacts a node knows about. The lookup and
// RPC code depend only on this interface, so the simple FlatRoutingTable
// can later be replaced by a k-bucket table without changing them.
//
// Implementations must be safe for concurrent use.
type RoutingTable interface {
	// AddContact records that we heard from c. The node's own contact
	// is ignored.
	AddContact(c Contact)

	// RemoveContact forgets the contact with the given ID (e.g. after it
	// stopped responding). Unknown IDs are ignored.
	RemoveContact(id KademliaID)

	// FindClosestContacts returns up to count known contacts, closest to
	// target first. The returned slice is the caller's to modify.
	FindClosestContacts(target KademliaID, count int) []Contact
}

// FlatRoutingTable is a simplified RoutingTable that keeps every contact
// it hears about, with no buckets, size limit, or eviction (the shortcut
// suggested in TIPS for getting lookups working early).
type FlatRoutingTable struct {
	me Contact

	mu       sync.Mutex // guards contacts
	contacts map[KademliaID]Contact
}

// Compile-time check that FlatRoutingTable implements RoutingTable.
var _ RoutingTable = (*FlatRoutingTable)(nil)

// NewFlatRoutingTable returns an empty table for the node me.
func NewFlatRoutingTable(me Contact) *FlatRoutingTable {
	return &FlatRoutingTable{
		me:       me,
		contacts: make(map[KademliaID]Contact),
	}
}

func (rt *FlatRoutingTable) AddContact(c Contact) {
	if c.ID == rt.me.ID {
		return
	}
	rt.mu.Lock()
	defer rt.mu.Unlock()
	rt.contacts[c.ID] = c
}

func (rt *FlatRoutingTable) RemoveContact(id KademliaID) {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	delete(rt.contacts, id)
}

func (rt *FlatRoutingTable) FindClosestContacts(target KademliaID, count int) []Contact {
	if count <= 0 {
		return nil
	}
	// Copy under the lock, sort outside it: the lock is held only as long
	// as needed to read the map safely.
	rt.mu.Lock()
	all := slices.Collect(maps.Values(rt.contacts))
	rt.mu.Unlock()

	SortContactsByDistance(all, target)
	if len(all) > count {
		all = all[:count]
	}
	return all
}
