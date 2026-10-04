package kademlia

import (
	"context"
	"errors"
	"fmt"
	"sync"
)

// StoreResult is the outcome of storing a value in the network.
type StoreResult struct {
	Key      KademliaID
	StoredAt []Contact // nodes that accepted the value (may include us)
	Failed   int       // nodes that could not be reached or rejected it
}

// Store publishes value under key = hash(value) (paper §2.3): look up the
// k nodes closest to the key and send each of them the value over the
// data plane. If this node is itself among the k closest, it keeps a copy
// as one of the k.
func (k *Kademlia) Store(ctx context.Context, value []byte) (StoreResult, error) {
	res := StoreResult{Key: KeyFromValue(value)}
	if len(value) > MaxValueSize {
		return res, fmt.Errorf("value of %d bytes exceeds the %d byte limit", len(value), MaxValueSize)
	}

	look, err := k.LookupContact(ctx, res.Key)
	if err != nil && !errors.Is(err, ErrNoContacts) {
		return res, err
	}
	// The k closest of the lookup result plus ourselves.
	targets := append(look.Contacts, k.me)
	SortContactsByDistance(targets, res.Key)
	targets = targets[:min(len(targets), k.cfg.K)]

	var mu sync.Mutex
	var wg sync.WaitGroup
	for _, c := range targets {
		wg.Go(func() {
			var err error
			if c == k.me {
				err = k.store.Put(res.Key, value)
			} else {
				err = k.storeAt(ctx, c, res.Key, value)
			}
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				res.Failed++
				k.log.Warn("store_failed", "key", res.Key.Short(), "to", c.ID.Short(), "err", err.Error())
			} else {
				res.StoredAt = append(res.StoredAt, c)
			}
		})
	}
	wg.Wait()
	SortContactsByDistance(res.StoredAt, res.Key)

	k.log.Info("store", "key", res.Key.Short(), "size", len(value), "stored", len(res.StoredAt), "failed", res.Failed)
	if len(res.StoredAt) == 0 {
		return res, errors.New("kademlia: value could not be stored on any node")
	}
	return res, nil
}
