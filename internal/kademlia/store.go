package kademlia

import (
	"errors"
	"slices"
	"sync"
	"time"
)

// ErrHashMismatch is returned when a value is offered under a key that is
// not its hash.
var ErrHashMismatch = errors.New("kademlia: key is not the hash of the value")

// Store is a node's local data store: key -> value, kept in memory. Values
// never expire (the spec forbids expiration); periodic replication keeps
// them alive despite churn. Safe for concurrent use.
type Store struct {
	mu      sync.RWMutex // many readers (lookups) or one writer
	entries map[KademliaID]entry
}

type entry struct {
	value  []byte
	stored time.Time // last Put or Touch: when this copy was last refreshed
}

// NewStore returns an empty store.
func NewStore() *Store {
	return &Store{entries: make(map[KademliaID]entry)}
}

// Put stores value under key, but only if key == hash(value): the store
// enforces content addressing, so no code path can bypass the check.
// Storing a key again refreshes its timestamp (see Touch).
func (s *Store) Put(key KademliaID, value []byte) error {
	if KeyFromValue(value) != key {
		return ErrHashMismatch
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.entries[key] = entry{value: slices.Clone(value), stored: time.Now()} // our own copy
	return nil
}

// Get returns the value for key. The returned slice must not be modified.
func (s *Store) Get(key KademliaID) ([]byte, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	e, ok := s.entries[key]
	return e.value, ok
}

// Touch marks key as just refreshed, e.g. after this node republished it.
func (s *Store) Touch(key KademliaID) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if e, ok := s.entries[key]; ok {
		e.stored = time.Now()
		s.entries[key] = e
	}
}

// Keys returns all stored keys in ascending order.
func (s *Store) Keys() []KademliaID {
	return s.keys(func(entry) bool { return true })
}

// KeysOlderThan returns the keys not stored or touched within age: the
// ones due for replication, since nobody has republished them recently.
func (s *Store) KeysOlderThan(age time.Duration) []KademliaID {
	cutoff := time.Now().Add(-age)
	return s.keys(func(e entry) bool { return e.stored.Before(cutoff) })
}

func (s *Store) keys(include func(entry) bool) []KademliaID {
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
