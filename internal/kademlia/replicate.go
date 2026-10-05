package kademlia

import "time"

// replicateLoop republishes stale values every ReplicateInterval until
// Close (paper, section 2.5).
//
// The first round starts at a random point within the first interval, so
// that nodes started together (e.g. 50 containers) do not all replicate
// at the same moment. Spread out, the first holder of a key to republish
// refreshes the other holders' copies, and they skip it that round.
func (k *Kademlia) replicateLoop() {
	k.mu.Lock()
	first := time.Duration(k.rng.Int64N(int64(k.cfg.ReplicateInterval)))
	k.mu.Unlock()

	timer := time.NewTimer(first)
	defer timer.Stop()
	for {
		select {
		case <-k.ctx.Done():
			return
		case <-timer.C:
			k.replicateStale()
			timer.Reset(k.cfg.ReplicateInterval)
		}
	}
}

// replicateStale republishes every value that nobody has stored or
// republished within ReplicateInterval: look up the k nodes currently
// closest to its key and store it there. As nodes leave and join, this
// moves the copies to whichever nodes are now the closest.
func (k *Kademlia) replicateStale() {
	keys := k.store.KeysOlderThan(k.cfg.ReplicateInterval)
	replicated := 0
	for _, key := range keys {
		if k.ctx.Err() != nil {
			return // node is closing
		}
		value, ok := k.store.Get(key)
		if !ok {
			continue
		}
		res, err := k.Store(k.ctx, value)
		// Our own copy counts as refreshed even if we are no longer among
		// the k closest; otherwise we would republish it every round.
		k.store.Touch(key)
		if err != nil {
			k.log.Warn("replicate_failed", "key", key.Short(), "err", err.Error())
			continue
		}
		replicated++
		k.log.Info("replicate", "key", key.Short(), "stored", len(res.StoredAt), "failed", res.Failed)
	}
	k.log.Info("replicate_round", "due", len(keys), "replicated", replicated,
		"held", len(k.store.Keys()))
}
