package kademlia

import (
	"context"
	"log/slog"
	"time"
)

// LookupResult is the outcome of an iterative node lookup.
type LookupResult struct {
	Contacts []Contact // up to k closest contacts that responded, closest first
	Probes   int       // FIND_NODE RPCs started (each may retransmit internally)
	Failed   int       // probes that got no response
}

// LookupContact finds the k nodes closest to target (paper §2.3) using
// bounded parallelism: at most alpha probes are in flight, and a new one
// starts as soon as any probe finishes.
//
// A single coordinator goroutine (this one) owns the shortlist. Probe
// goroutines only send their results back over a channel, so the
// shortlist needs no lock.
func (k *Kademlia) LookupContact(ctx context.Context, target KademliaID) (LookupResult, error) {
	log := k.log.With("lookup", k.lookups.Add(1))
	start := time.Now()

	sl := newShortlist(target, k.me.ID, k.cfg.K)
	sl.add(k.rt.FindClosestContacts(target, k.cfg.K))
	log.Info("lookup_start", "target", target.Short(), "known", len(sl.order))

	res, err := k.runLookup(ctx, log, sl)

	log.Info("lookup_done", "target", target.Short(), "ok", err == nil,
		"probes", res.Probes, "failed", res.Failed, "found", len(res.Contacts),
		"ms", time.Since(start).Milliseconds())
	return res, err
}

type probeResult struct {
	from     Contact
	contacts []Contact
	err      error
}

func (k *Kademlia) runLookup(ctx context.Context, log *slog.Logger, sl *shortlist) (LookupResult, error) {
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
				contacts, err := k.findNode(ctx, c, sl.target)
				results <- probeResult{c, contacts, err}
			}()
		}

		// While not done, some top-k candidate is unqueried (launched
		// above) or in flight, so inFlight > 0 and a result will come.
		select {
		case r := <-results:
			inFlight--
			if r.err != nil {
				res.Failed++
				sl.state[r.from.ID] = stateFailed
				log.Info("probe_failed", "to", r.from.ID.Short(), "err", r.err.Error())
			} else {
				sl.state[r.from.ID] = stateResponded
				sl.add(r.contacts)
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
}

func newShortlist(target, self KademliaID, k int) *shortlist {
	return &shortlist{target: target, self: self, k: k, state: make(map[KademliaID]candidateState)}
}

// add inserts new candidates (ignoring ourselves and ones already known).
func (s *shortlist) add(contacts []Contact) {
	added := false
	for _, c := range contacts {
		if _, known := s.state[c.ID]; known || c.ID == s.self {
			continue
		}
		s.state[c.ID] = stateUnqueried
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
