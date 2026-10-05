package kademlia

import (
	"context"
	"errors"
	"log/slog"
	"time"
)

// ErrNotFound is returned by LookupData when no node has the value.
var ErrNotFound = errors.New("kademlia: value not found")

// LookupResult is the outcome of an iterative lookup.
type LookupResult struct {
	Contacts []Contact // up to k closest contacts that responded, closest first
	Probes   int       // FIND_NODE/FIND_VALUE RPCs started (each may retransmit internally)
	Failed   int       // probes that got no response

	// Hops is the length of the chain of RPCs that led to the closest node
	// found (or, for LookupData, to the node that had the value): a contact
	// from our own routing table is one hop away, a contact learned from a
	// contact h hops away is h+1 hops away. This is the "hop count" that
	// Kademlia's O(log N) analysis is about.
	Hops int

	Value []byte  // LookupData only: the value, verified against its key
	From  Contact // LookupData only: the node the value came from
}

// probeFunc asks contact c about the lookup's target. It returns the
// closer contacts c knows, or (value lookups only) the verified value.
type probeFunc func(ctx context.Context, c Contact) (contacts []Contact, value []byte, err error)

// LookupContact finds the k nodes closest to target (paper §2.3) using
// bounded parallelism: at most alpha probes are in flight, and a new one
// starts as soon as any probe finishes.
func (k *Kademlia) LookupContact(ctx context.Context, target KademliaID) (LookupResult, error) {
	return k.lookup(ctx, target, "node", func(ctx context.Context, c Contact) ([]Contact, []byte, error) {
		contacts, err := k.findNode(ctx, c, target)
		return contacts, nil, err
	})
}

// LookupData finds the value stored under key ( FIND_VALUE):
// the same iterative lookup, but it stops as soon as some node delivers
// a value whose hash matches the key.
func (k *Kademlia) LookupData(ctx context.Context, key KademliaID) (LookupResult, error) {
	if value, ok := k.store.Get(key); ok {
		// A local hit is a successful lookup too, so it is logged (with
		// local=true and no probes, so analyses can tell it apart).
		k.log.Info("lookup_done", "lookup", k.lookups.Add(1), "kind", "value", "target", key.Short(),
			"ok", true, "probes", 0, "failed", 0, "found", 0, "hops", 0, "value", true, "local", true, "ms", 0)
		return LookupResult{Value: value, From: k.me}, nil
	}
	res, err := k.lookup(ctx, key, "value", func(ctx context.Context, c Contact) ([]Contact, []byte, error) {
		return k.findValue(ctx, c, key)
	})
	if err == nil && res.Value == nil {
		err = ErrNotFound
	}
	return res, err
}

// lookup runs one iterative lookup and logs its start and outcome.
func (k *Kademlia) lookup(ctx context.Context, target KademliaID, kind string, probe probeFunc) (LookupResult, error) {
	log := k.log.With("lookup", k.lookups.Add(1))
	start := time.Now()
	k.touchBucket(target)

	sl := newShortlist(target, k.me.ID, k.cfg.K)
	sl.add(k.rt.FindClosestContacts(target, k.cfg.K))
	log.Info("lookup_start", "kind", kind, "target", target.Short(), "known", len(sl.order))

	res, err := k.runLookup(ctx, log, sl, probe)

	log.Info("lookup_done", "kind", kind, "target", target.Short(), "ok", err == nil,
		"probes", res.Probes, "failed", res.Failed, "found", len(res.Contacts),
		"hops", res.Hops, "value", res.Value != nil, "ms", time.Since(start).Milliseconds())
	return res, err
}

type probeResult struct {
	from     Contact
	contacts []Contact
	value    []byte
	err      error
}

// runLookup is the coordinator. A single goroutine (this one) owns the
// shortlist; probe goroutines only send their results back over a
// channel, so the shortlist needs no lock.
func (k *Kademlia) runLookup(ctx context.Context, log *slog.Logger, sl *shortlist, probe probeFunc) (LookupResult, error) {
	var res LookupResult

	// Cancelling stops probes still in flight when the lookup is done.
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	// Buffered for alpha results: at most alpha probes are ever in flight,
	// so a probe finishing after the lookup ended never blocks.
	results := make(chan probeResult, k.cfg.Alpha)
	inFlight := 0

	for !sl.done() {
		for inFlight < k.cfg.Alpha {
			c, ok := sl.next()
			if !ok {
				break
			}
			sl.state[c.ID] = stateInFlight
			inFlight++
			res.Probes++
			log.Info("probe", "to", c.ID.Short(), "addr", c.Address.String())
			go func() {
				contacts, value, err := probe(ctx, c)
				results <- probeResult{c, contacts, value, err}
			}()
		}

		// While not done, some top-k candidate is unqueried (launched
		// above) or in flight, so inFlight > 0 and a result will come.
		select {
		case r := <-results:
			inFlight--
			switch {
			case r.err != nil:
				res.Failed++
				sl.state[r.from.ID] = stateFailed
				log.Info("probe_failed", "to", r.from.ID.Short(), "err", r.err.Error())
			case r.value != nil:
				sl.state[r.from.ID] = stateResponded
				log.Info("probe_ok", "to", r.from.ID.Short(), "value", true)
				res.Contacts = sl.responded()
				res.Value, res.From = r.value, r.from
				res.Hops = sl.hops[r.from.ID]
				return res, nil // found it: stop (in-flight probes are cancelled)
			default:
				sl.state[r.from.ID] = stateResponded
				sl.addFrom(r.contacts, sl.hops[r.from.ID]+1)
				log.Info("probe_ok", "to", r.from.ID.Short(), "returned", len(r.contacts))
			}
		case <-ctx.Done():
			res.Contacts = sl.responded()
			return res, ctx.Err()
		}
	}

	res.Contacts = sl.responded()
	if len(res.Contacts) == 0 {
		return res, ErrNoContacts
	}
	res.Hops = sl.hops[res.Contacts[0].ID]
	return res, nil
}

type candidateState int

const (
	stateUnqueried candidateState = iota
	stateInFlight
	stateResponded
	stateFailed
)

// shortlist holds every candidate seen during one lookup, sorted by
// distance to the target, with each candidate's state. It is used only
// by the lookup's coordinator goroutine.
type shortlist struct {
	target KademliaID
	self   KademliaID // never a candidate
	k      int
	order  []Contact // closest to target first
	state  map[KademliaID]candidateState
	hops   map[KademliaID]int // see LookupResult.Hops
}

func newShortlist(target, self KademliaID, k int) *shortlist {
	return &shortlist{target: target, self: self, k: k,
		state: make(map[KademliaID]candidateState), hops: make(map[KademliaID]int)}
}

// add inserts candidates from our own routing table (one hop away).
func (s *shortlist) add(contacts []Contact) { s.addFrom(contacts, 1) }

// addFrom inserts new candidates that are the given number of hops away
// (ignoring ourselves and ones already known).
func (s *shortlist) addFrom(contacts []Contact, hops int) {
	added := false
	for _, c := range contacts {
		if _, known := s.state[c.ID]; known || c.ID == s.self {
			continue
		}
		s.state[c.ID] = stateUnqueried
		s.hops[c.ID] = hops
		s.order = append(s.order, c)
		added = true
	}
	if added {
		SortContactsByDistance(s.order, s.target)
	}
}

// top returns the k closest candidates that have not failed. These are
// the lookup's current answer; failed nodes drop out and let the next
// closest move up.
func (s *shortlist) top() []Contact {
	var top []Contact
	for _, c := range s.order {
		if s.state[c.ID] == stateFailed {
			continue
		}
		top = append(top, c)
		if len(top) == s.k {
			break
		}
	}
	return top
}

// next returns the closest unqueried candidate among the top k.
func (s *shortlist) next() (Contact, bool) {
	for _, c := range s.top() {
		if s.state[c.ID] == stateUnqueried {
			return c, true
		}
	}
	return Contact{}, false
}

// done reports whether every one of the top k has responded: the
// termination condition "k probed and known to be active contacts".
func (s *shortlist) done() bool {
	for _, c := range s.top() {
		if s.state[c.ID] != stateResponded {
			return false
		}
	}
	return true
}

// responded returns the top-k candidates that have responded.
func (s *shortlist) responded() []Contact {
	var out []Contact
	for _, c := range s.top() {
		if s.state[c.ID] == stateResponded {
			out = append(out, c)
		}
	}
	return out
}
