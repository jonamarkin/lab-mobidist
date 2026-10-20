package kademlia

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"sync"
)

// Mutable keys are part 2's exception to "a key is the hash of its value":
// a package's latest pointer lives under a key derived from the package
// name, and its value changes as versions are published. The node knows
// nothing about packages or signatures; it enforces the exception through
// the Validator in its Config, which decides whether a new value may
// replace the current one.

// FetchFunc reads the value stored under key, from this node's store or
// the network. The validator uses it to read what a value refers to.
type FetchFunc func(ctx context.Context, key KademliaID) ([]byte, error)

// Validator decides whether newValue may be stored under the mutable key,
// given the value the node currently holds (nil if none). A non-nil error
// refuses the update; its message is reported to the sender.
type Validator interface {
	Validate(ctx context.Context, key KademliaID, newValue, current []byte, fetch FetchFunc) error
}

// ErrNoValidator is returned for UPDATE on a node without a Validator.
var ErrNoValidator = errors.New("kademlia: mutable values are not enabled on this node")

// fetch is the FetchFunc given to the validator: a value lookup, which
// serves from the local store first.
func (k *Kademlia) fetch(ctx context.Context, key KademliaID) ([]byte, error) {
	res, err := k.LookupData(ctx, key)
	if err != nil {
		return nil, err
	}
	return res.Value, nil
}

// updateLocal stores value under the mutable key if the validator accepts
// it against the value held now. Validation runs without the store lock,
// since it may take network round trips, so the store is written with a
// compare-and-swap and the validation repeated if another update got in
// between: two updates validated against the same old value can never
// both be stored in arrival order. Every retry means another update
// succeeded, so the loop ends when the contention does; ctx bounds it.
func (k *Kademlia) updateLocal(ctx context.Context, key KademliaID, value []byte) error {
	if k.cfg.Validator == nil {
		return ErrNoValidator
	}
	for ctx.Err() == nil {
		current, mutable, ok := k.store.Entry(key)
		if ok && !mutable {
			return ErrWrongKind
		}
		if ok && bytes.Equal(current, value) {
			k.store.Touch(key) // a retransmission or a replica: nothing to decide
			return nil
		}
		if err := k.cfg.Validator.Validate(ctx, key, value, current, k.fetch); err != nil {
			k.log.Info("update_refused", "key", key.Short(), "err", err.Error())
			return err
		}
		err := k.store.PutMutable(key, value, current)
		if err == nil {
			k.log.Info("update", "key", key.Short(), "size", len(value), "replaced", ok)
			return nil
		}
		if !errors.Is(err, ErrConflict) {
			return err
		}
		// Another update changed the key while we validated: validate
		// again, against what is there now.
	}
	return ctx.Err()
}

// Refusal is one node's reason for refusing an update.
type Refusal struct {
	Node   Contact
	Reason string
}

// UpdateResult is the outcome of updating a mutable key in the network.
type UpdateResult struct {
	Key      KademliaID
	Accepted []Contact // nodes that stored the value (may include us)
	Refused  []Refusal // nodes whose validator said no
	Failed   int       // nodes that could not be reached
}

// Update stores value under the mutable key on the k nodes closest to it,
// as Store does for content-addressed values, except that the key is the
// caller's and every node runs its validator before accepting. It fails
// only if no node accepted; the result says who refused and why.
func (k *Kademlia) Update(ctx context.Context, key KademliaID, value []byte) (UpdateResult, error) {
	res := UpdateResult{Key: key}
	if len(value) > MaxValueSize {
		return res, fmt.Errorf("value of %d bytes exceeds the %d byte limit", len(value), MaxValueSize)
	}
	look, err := k.LookupContact(ctx, key)
	if err != nil && !errors.Is(err, ErrNoContacts) {
		return res, err
	}
	targets := append(look.Contacts, k.me)
	SortContactsByDistance(targets, key)
	targets = targets[:min(len(targets), k.cfg.K)]

	var mu sync.Mutex
	var wg sync.WaitGroup
	for _, c := range targets {
		wg.Go(func() {
			var err error
			if c == k.me {
				err = k.updateLocal(ctx, key, value)
			} else {
				err = k.updateAt(ctx, c, key, value)
			}
			mu.Lock()
			defer mu.Unlock()
			var refused *RefusedError
			switch {
			case err == nil:
				res.Accepted = append(res.Accepted, c)
			case errors.As(err, &refused):
				res.Refused = append(res.Refused, Refusal{c, refused.Reason})
			case c == k.me:
				res.Refused = append(res.Refused, Refusal{c, err.Error()}) // our own validator
			default:
				res.Failed++
				k.log.Warn("update_failed", "key", key.Short(), "to", c.ID.Short(), "err", err.Error())
			}
		})
	}
	wg.Wait()
	SortContactsByDistance(res.Accepted, key)

	k.log.Info("update_done", "key", key.Short(), "size", len(value),
		"accepted", len(res.Accepted), "refused", len(res.Refused), "failed", res.Failed)
	if len(res.Accepted) == 0 {
		if len(res.Refused) > 0 {
			return res, fmt.Errorf("kademlia: update refused by every node: %s", res.Refused[0].Reason)
		}
		return res, errors.New("kademlia: value could not be stored on any node")
	}
	return res, nil
}

// Copy is one node's value for a key.
type Copy struct {
	From  Contact
	Value []byte
}

// LookupAll returns the value each reachable holder of key has, ours
// included, closest holder first. The values are not checked against the
// key: this is for mutable keys, whose holders may disagree, and the
// caller decides which copy to believe.
func (k *Kademlia) LookupAll(ctx context.Context, key KademliaID) ([]Copy, error) {
	look, err := k.LookupContact(ctx, key)
	if err != nil && !errors.Is(err, ErrNoContacts) {
		return nil, err
	}
	var copies []Copy
	if value, ok := k.store.Get(key); ok {
		copies = append(copies, Copy{From: k.me, Value: value})
	}
	var mu sync.Mutex
	var wg sync.WaitGroup
	for _, c := range look.Contacts {
		wg.Go(func() {
			value, err := k.fetchRaw(ctx, c, key)
			if err != nil {
				return // no copy there, or unreachable
			}
			mu.Lock()
			copies = append(copies, Copy{From: c, Value: value})
			mu.Unlock()
		})
	}
	wg.Wait()
	// Closest first, so the order is the same on every run.
	byDistance := make([]Contact, len(copies))
	for i, c := range copies {
		byDistance[i] = c.From
	}
	SortContactsByDistance(byDistance, key)
	sorted := make([]Copy, 0, len(copies))
	for _, from := range byDistance {
		for _, c := range copies {
			if c.From == from {
				sorted = append(sorted, c)
				break
			}
		}
	}
	k.log.Info("lookup_all", "key", key.Short(), "asked", len(look.Contacts), "copies", len(sorted))
	return sorted, nil
}
