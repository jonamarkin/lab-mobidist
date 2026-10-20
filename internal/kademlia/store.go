package kademlia

import (
	"bytes"
	"errors"
	"slices"
	"sync"
	"time"
)

// ErrHashMismatch is returned when a value is offered under a key that is
// not its hash.
var ErrHashMismatch = errors.New("kademlia: key is not the hash of the value")

// ErrConflict is returned by PutMutable when the key no longer holds the
// expected value: another update got there first.
var ErrConflict = errors.New("kademlia: value changed concurrently")

// ErrWrongKind is returned when a mutable key is stored as content
// addressed, or a content-addressed key is updated.
var ErrWrongKind = errors.New("kademlia: key holds a value of the other kind")

// DataStore is a node's local data store: key -> value, kept in memory. Values
// never expire (the spec forbids expiration); periodic replication keeps
// them alive despite churn. Safe for concurrent use.
//
// Most keys are the hash of their value. Mutable keys (part 2's latest
// pointers) are independent of their value, which changes over time; they
// are written with PutMutable after a Validator has approved the change.
type DataStore struct {
	mu      sync.RWMutex // many readers (lookups) or one writer
	entries map[KademliaID]entry
}

type entry struct {
	value   []byte
	stored  time.Time // last Put or Touch: when this copy was last refreshed
	mutable bool      // the key is not the hash of the value
}

// NewDataStore returns an empty store.
func NewDataStore() *DataStore {
	return &DataStore{entries: make(map[KademliaID]entry)}
}

// Put stores value under key, but only if key == hash(value): the store
// enforces content addressing, so no code path can bypass the check.
// Storing a key again refreshes its timestamp (see Touch).
func (s *DataStore) Put(key KademliaID, value []byte) error {
	if KeyFromValue(value) != key {
		return ErrHashMismatch
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if e, ok := s.entries[key]; ok && e.mutable {
		return ErrWrongKind
	}
	s.entries[key] = entry{value: slices.Clone(value), stored: time.Now()} // our own copy
	return nil
}

// PutMutable stores value under key without the hash check, but only if
// the key still holds expected (nil: nothing yet). This compare-and-swap
// lets the caller validate the change outside the lock, which may take
// network round trips, and still be sure nothing changed meanwhile.
func (s *DataStore) PutMutable(key KademliaID, value, expected []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.entries[key]
	if ok && !e.mutable {
		return ErrWrongKind
	}
	if ok != (expected != nil) || (ok && !bytes.Equal(e.value, expected)) {
		return ErrConflict
	}
	s.entries[key] = entry{value: slices.Clone(value), stored: time.Now(), mutable: true}
	return nil
}

// Get returns the value for key. The returned slice must not be modified.
func (s *DataStore) Get(key KademliaID) ([]byte, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	e, ok := s.entries[key]
	return e.value, ok
}

// Entry returns the value for key and whether the key is mutable.
func (s *DataStore) Entry(key KademliaID) (value []byte, mutable, ok bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	e, ok := s.entries[key]
	return e.value, e.mutable, ok
}

// IsMutable reports whether key holds a mutable value.
func (s *DataStore) IsMutable(key KademliaID) bool {
	_, mutable, ok := s.Entry(key)
	return ok && mutable
}

// Touch marks key as just refreshed, e.g. after this node republished it.
func (s *DataStore) Touch(key KademliaID) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if e, ok := s.entries[key]; ok {
		e.stored = time.Now()
		s.entries[key] = e
	}
}

// Keys returns all stored keys in ascending order.
func (s *DataStore) Keys() []KademliaID {
	return s.keys(func(entry) bool { return true })
}

// KeysOlderThan returns the keys not stored or touched within age: the
// ones due for replication, since nobody has republished them recently.
func (s *DataStore) KeysOlderThan(age time.Duration) []KademliaID {
	cutoff := time.Now().Add(-age)
	return s.keys(func(e entry) bool { return e.stored.Before(cutoff) })
}

func (s *DataStore) keys(include func(entry) bool) []KademliaID {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var keys []KademliaID
	for k, e := range s.entries {
		if include(e) {
			keys = append(keys, k)
		}
	}
	slices.SortFunc(keys, KademliaID.Cmp)
	return keys
}
