package kademlia

import (
	"maps"
	"slices"
	"sync"
)

// RoutingTable is the set of contacts a node knows about. The lookup and
// RPC code depend only on this interface, so the table implementation
// (BucketRoutingTable, or FlatRoutingTable for comparisons) can be chosen
// without changing them.
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

// Pinger reports whether c answers a PING. A BucketRoutingTable calls it
// (without holding its lock) when a full bucket must decide whether to
// evict its least recently seen contact.
type Pinger func(c Contact) bool

// BucketRoutingTable is the routing table from the Kademlia paper (§2.2)
// with b = 1: IDBits k-buckets, where bucket i holds up to k contacts at
// distance [2^i, 2^(i+1)) from us, least recently seen first.
type BucketRoutingTable struct {
	me   Contact
	k    int
	ping Pinger

	mu      sync.Mutex // guards buckets and checking
	buckets [IDBits]bucket
	// checking[i] is true while an eviction check for bucket i runs; at
	// most one runs per bucket, so a flood of newcomers cannot cause a
	// flood of pings.
	checking [IDBits]bool

	checks sync.WaitGroup // running eviction checks
}

var _ RoutingTable = (*BucketRoutingTable)(nil)

// NewBucketRoutingTable returns an empty table for node me with bucket
// size k. ping is used to check the oldest contact of a full bucket.
func NewBucketRoutingTable(me Contact, k int, ping Pinger) *BucketRoutingTable {
	return &BucketRoutingTable{me: me, k: k, ping: ping}
}

// AddContact records that we heard from c (paper §2.2):
//   - already known: move it to the tail (most recently seen);
//   - bucket not full: append it at the tail;
//   - bucket full: check in the background whether the least recently
//     seen contact is still alive; c is only inserted if it is not.
func (rt *BucketRoutingTable) AddContact(c Contact) {
	i := BucketIndex(rt.me.ID, c.ID)
	if i < 0 {
		return // ourselves
	}
	rt.mu.Lock()
	defer rt.mu.Unlock()

	b := &rt.buckets[i]
	if j := b.indexOf(c.ID); j >= 0 {
		b.moveToTail(j)
		return
	}
	if len(b.contacts) < rt.k {
		b.contacts = append(b.contacts, c)
		return
	}
	if rt.checking[i] {
		return // a check is already running: discard c
	}
	rt.checking[i] = true
	oldest := b.contacts[0]
	rt.checks.Go(func() { rt.checkEviction(i, oldest, c) })
}

// checkEviction pings the least recently seen contact of a full bucket.
// The ping is a network round trip, so it runs without the lock; the
// bucket may have changed meanwhile, so positions are looked up again.
func (rt *BucketRoutingTable) checkEviction(i int, oldest, newcomer Contact) {
	alive := rt.ping(oldest)

	rt.mu.Lock()
	defer rt.mu.Unlock()
	rt.checking[i] = false
	b := &rt.buckets[i]
	j := b.indexOf(oldest.ID)
	if alive {
		// Prefer the long-lived contact; the newcomer is discarded.
		if j >= 0 {
			b.moveToTail(j)
		}
		return
	}
	if j >= 0 {
		b.remove(j)
	}
	if b.indexOf(newcomer.ID) < 0 && len(b.contacts) < rt.k {
		b.contacts = append(b.contacts, newcomer)
	}
}

func (rt *BucketRoutingTable) RemoveContact(id KademliaID) {
	i := BucketIndex(rt.me.ID, id)
	if i < 0 {
		return
	}
	rt.mu.Lock()
	defer rt.mu.Unlock()
	if j := rt.buckets[i].indexOf(id); j >= 0 {
		rt.buckets[i].remove(j)
	}
}

// FindClosestContacts collects all contacts and sorts them. The table
// holds about k·log2(N) contacts, so this is cheap and obviously correct
// (unlike walking buckets outward from the target's bucket, which can
// stop before seeing closer contacts).
func (rt *BucketRoutingTable) FindClosestContacts(target KademliaID, count int) []Contact {
	if count <= 0 {
		return nil
	}
	rt.mu.Lock()
	var all []Contact
	for i := range rt.buckets {
		all = append(all, rt.buckets[i].contacts...)
	}
	rt.mu.Unlock()

	SortContactsByDistance(all, target)
	if len(all) > count {
		all = all[:count]
	}
	return all
}

// Buckets returns a copy of every bucket's contacts (index i = bucket i),
// least recently seen first; for "show rt" and tests.
func (rt *BucketRoutingTable) Buckets() [][]Contact {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	out := make([][]Contact, IDBits)
	for i := range rt.buckets {
		out[i] = slices.Clone(rt.buckets[i].contacts)
	}
	return out
}

// FlatRoutingTable is a simplified RoutingTable that keeps every contact
// it hears about, with no buckets, size limit, or eviction. It is a
// baseline for comparison with BucketRoutingTable (Config.FlatRoutingTable).
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
