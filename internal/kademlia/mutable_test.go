package kademlia

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jonamarkin/lab-mobidist/internal/network"
)

// Trivial validators: the DHT's support for mutable keys is tested
// without any registry logic.

// monotonic accepts a value only if it is lexicographically greater than
// the current one, and counts its calls.
type monotonic struct {
	calls atomic.Int64
	delay time.Duration // widens the window for concurrent updates
}

func (m *monotonic) Validate(_ context.Context, _ KademliaID, newValue, current []byte, _ FetchFunc) error {
	m.calls.Add(1)
	time.Sleep(m.delay)
	if current != nil && bytes.Compare(newValue, current) <= 0 {
		return fmt.Errorf("not newer: %q <= %q", newValue, current)
	}
	return nil
}

// refuseAll refuses everything with a fixed reason.
type refuseAll struct{ reason string }

func (r refuseAll) Validate(context.Context, KademliaID, []byte, []byte, FetchFunc) error {
	return errors.New(r.reason)
}

// fetching accepts a value that names (in hex) a key whose value can be
// fetched: it exercises the fetch function handed to the validator.
type fetching struct{}

func (fetching) Validate(ctx context.Context, _ KademliaID, newValue, _ []byte, fetch FetchFunc) error {
	ref, err := NewKademliaID(string(newValue))
	if err != nil {
		return err
	}
	if _, err := fetch(ctx, ref); err != nil {
		return fmt.Errorf("cannot fetch %s: %w", ref.Short(), err)
	}
	return nil
}

func mutableConfig(v Validator) Config {
	cfg := testConfig(3)
	cfg.Validator = v
	return cfg
}

var mkey = KeyFromValue([]byte("some.domain:pkg:latest"))

// mutableHolders returns the nodes that hold key as a mutable value.
func mutableHolders(nodes []*Kademlia, key KademliaID) []Contact {
	var out []Contact
	for _, n := range nodes {
		if n.DataStore().IsMutable(key) {
			out = append(out, n.Me())
		}
	}
	return out
}

func TestPutMutable(t *testing.T) {
	s := NewDataStore()
	k := KeyFromValue([]byte("name"))
	if err := s.PutMutable(k, []byte("v1"), []byte("v0")); !errors.Is(err, ErrConflict) {
		t.Errorf("expected a value where there is none: %v", err)
	}
	if err := s.PutMutable(k, []byte("v1"), nil); err != nil {
		t.Fatal(err)
	}
	if v, mutable, ok := s.Entry(k); !ok || !mutable || string(v) != "v1" {
		t.Errorf("Entry = %q, %v, %v", v, mutable, ok)
	}
	if !s.IsMutable(k) || s.IsMutable(KeyFromValue([]byte("x"))) {
		t.Error("IsMutable wrong")
	}
	if err := s.PutMutable(k, []byte("v2"), nil); !errors.Is(err, ErrConflict) {
		t.Errorf("expected nothing where there is a value: %v", err)
	}
	if err := s.PutMutable(k, []byte("v2"), []byte("v0")); !errors.Is(err, ErrConflict) {
		t.Errorf("expected a stale value: %v", err)
	}
	if err := s.PutMutable(k, []byte("v2"), []byte("v1")); err != nil {
		t.Fatal(err)
	}
	if v, _ := s.Get(k); string(v) != "v2" {
		t.Errorf("Get = %q", v)
	}
	// The kinds never mix.
	if err := s.Put(k, []byte("v2")); !errors.Is(err, ErrHashMismatch) {
		t.Errorf("Put under a mutable key: %v", err)
	}
	blob := []byte("blob")
	s.Put(KeyFromValue(blob), blob)
	if err := s.PutMutable(KeyFromValue(blob), []byte("x"), blob); !errors.Is(err, ErrWrongKind) {
		t.Errorf("PutMutable under a content key: %v", err)
	}
	// Keys and KeysOlderThan include mutable entries; Touch refreshes them.
	if len(s.Keys()) != 2 {
		t.Errorf("Keys = %v", s.Keys())
	}
	s.mu.Lock()
	e := s.entries[k]
	e.stored = time.Now().Add(-2 * time.Hour)
	s.entries[k] = e
	s.mu.Unlock()
	if got := s.KeysOlderThan(time.Hour); len(got) != 1 || got[0] != k {
		t.Errorf("KeysOlderThan = %v", got)
	}
	s.Touch(k)
	if got := s.KeysOlderThan(time.Hour); len(got) != 0 {
		t.Errorf("after Touch: %v", got)
	}
}

func TestUpdateReachesClosest(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	sim := network.NewSimNetwork(network.SimConfig{})
	nodes := newTestNetwork(t, sim, 30, mutableConfig(&monotonic{}))

	res, err := nodes[3].Update(ctx, mkey, []byte("v1"))
	if err != nil {
		t.Fatal(err)
	}
	want := bruteForceClosest(contactsOf(nodes), mkey, 10)
	if fmt.Sprint(res.Accepted) != fmt.Sprint(want) {
		t.Errorf("accepted %v\nwant %v", res.Accepted, want)
	}
	if len(res.Refused) != 0 || res.Failed != 0 {
		t.Errorf("refused %v, failed %d", res.Refused, res.Failed)
	}
	if got := mutableHolders(nodes, mkey); len(got) != 10 {
		t.Errorf("%d holders, want 10", len(got))
	}
	// Every holder serves the value to LookupAll, closest first.
	copies, err := nodes[20].LookupAll(ctx, mkey)
	if err != nil || len(copies) != 10 {
		t.Fatalf("LookupAll: %d copies, %v", len(copies), err)
	}
	for i, c := range copies {
		if string(c.Value) != "v1" || c.From != want[i] {
			t.Errorf("copy %d from %v = %q", i, c.From, c.Value)
		}
	}
	// A mutable key is not "found" by a value lookup: its value cannot pass
	// the hash check, so FIND_VALUE does not offer it.
	if _, err := nodes[20].LookupData(ctx, mkey); !errors.Is(err, ErrNotFound) {
		t.Errorf("LookupData of a mutable key: %v", err)
	}
	// Plain content-addressed values still work beside it.
	if _, err := nodes[20].Store(ctx, []byte("a blob")); err != nil {
		t.Error(err)
	}
}

func TestUpdateRefusedWithReason(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	sim := network.NewSimNetwork(network.SimConfig{})
	nodes := newTestNetwork(t, sim, 20, mutableConfig(refuseAll{"no way"}))
	res, err := nodes[0].Update(ctx, mkey, []byte("v1"))
	if err == nil || !strings.Contains(err.Error(), "no way") {
		t.Fatalf("err = %v", err)
	}
	if len(res.Accepted) != 0 || len(res.Refused) != 10 || res.Failed != 0 {
		t.Errorf("result %+v", res)
	}
	for _, r := range res.Refused {
		if r.Reason != "no way" {
			t.Errorf("reason %q", r.Reason)
		}
	}
	if len(mutableHolders(nodes, mkey)) != 0 {
		t.Error("a refused value was stored")
	}
}

func TestUpdateWithoutValidator(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	sim := network.NewSimNetwork(network.SimConfig{})
	nodes := newTestNetwork(t, sim, 5, testConfig(3)) // no Validator
	res, err := nodes[0].Update(ctx, mkey, []byte("v1"))
	if err == nil || !strings.Contains(err.Error(), "not enabled") {
		t.Fatalf("err = %v", err)
	}
	if len(res.Accepted) != 0 || len(res.Refused) != 5 {
		t.Errorf("result %+v", res)
	}
}

func TestUpdateRollbackAndIdempotence(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	v := &monotonic{}
	sim := network.NewSimNetwork(network.SimConfig{})
	nodes := newTestNetwork(t, sim, 20, mutableConfig(v))

	if _, err := nodes[0].Update(ctx, mkey, []byte("v2")); err != nil {
		t.Fatal(err)
	}
	calls := v.calls.Load()
	// The same bytes again: accepted everywhere without consulting the
	// validator (a retransmission or a replica must be free and safe).
	res, err := nodes[1].Update(ctx, mkey, []byte("v2"))
	if err != nil || len(res.Accepted) != 10 {
		t.Fatalf("same value: %+v, %v", res, err)
	}
	if v.calls.Load() != calls {
		t.Errorf("validator called %d more times for identical bytes", v.calls.Load()-calls)
	}
	// An older value: refused by every holder, nothing changes.
	res, err = nodes[2].Update(ctx, mkey, []byte("v1"))
	if err == nil || len(res.Accepted) != 0 || len(res.Refused) != 10 {
		t.Fatalf("rollback: %+v, %v", res, err)
	}
	copies, _ := nodes[3].LookupAll(ctx, mkey)
	for _, c := range copies {
		if string(c.Value) != "v2" {
			t.Errorf("%v holds %q after a refused rollback", c.From, c.Value)
		}
	}
	// A newer value replaces it.
	if res, err := nodes[4].Update(ctx, mkey, []byte("v3")); err != nil || len(res.Accepted) != 10 {
		t.Fatalf("v3: %+v, %v", res, err)
	}
}

// Concurrent updates to one key: the final value must be the highest
// one, never an older value stored after a newer one (the compare-and-
// swap in updateLocal). The validator sleeps to widen the race window.
func TestUpdateLocalConcurrent(t *testing.T) {
	t.Parallel()
	sim := network.NewSimNetwork(network.SimConfig{})
	node := newTestNetwork(t, sim, 1, mutableConfig(&monotonic{delay: time.Millisecond}))[0]

	var wg sync.WaitGroup
	for i := range 20 {
		wg.Go(func() {
			value := fmt.Appendf(nil, "v%03d", i)
			err := node.updateLocal(context.Background(), mkey, value)
			if err != nil && !strings.Contains(err.Error(), "not newer") && !errors.Is(err, ErrConflict) {
				t.Errorf("update %d: %v", i, err)
			}
		})
	}
	wg.Wait()
	if v, _ := node.DataStore().Get(mkey); string(v) != "v019" {
		t.Errorf("final value %q, want v019", v)
	}
}

func TestUpdateConcurrentAcrossNetwork(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	sim := network.NewSimNetwork(network.SimConfig{})
	nodes := newTestNetwork(t, sim, 15, mutableConfig(&monotonic{delay: time.Millisecond}))
	var wg sync.WaitGroup
	for i := range 10 {
		wg.Go(func() {
			nodes[i].Update(ctx, mkey, fmt.Appendf(nil, "v%03d", i)) // some are refused: fine
		})
	}
	wg.Wait()
	// Every holder has one of the values, none has anything above the
	// highest, and the highest reached at least one holder. (A holder can
	// be a step behind if a lookup timed out while the updates raced: a
	// probe that missed it is not a rollback.)
	copies, _ := nodes[14].LookupAll(ctx, mkey)
	if len(copies) == 0 {
		t.Fatal("no copies")
	}
	var winner *Kademlia
	for _, c := range copies {
		if v := string(c.Value); v < "v000" || v > "v009" {
			t.Errorf("%v holds %q", c.From, c.Value)
		} else if v == "v009" {
			winner = byID(nodes, c.From.ID)
		}
	}
	if winner == nil {
		t.Fatal("no holder has the highest value")
	}
	// One replication round from a holder of the highest value brings
	// every holder up to date; none of them rolls back.
	winner.cfg.ReplicateInterval = time.Hour
	winner.store.mu.Lock()
	e := winner.store.entries[mkey]
	e.stored = time.Now().Add(-2 * time.Hour)
	winner.store.entries[mkey] = e
	winner.store.mu.Unlock()
	winner.replicateStale()
	copies, _ = nodes[14].LookupAll(ctx, mkey)
	for _, c := range copies {
		if string(c.Value) != "v009" {
			t.Errorf("%v holds %q after replication, want v009", c.From, c.Value)
		}
	}
}

func TestUpdateValidatorFetches(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	sim := network.NewSimNetwork(network.SimConfig{})
	nodes := newTestNetwork(t, sim, 20, mutableConfig(fetching{}))

	blob := []byte("referenced blob")
	if _, err := nodes[0].Store(ctx, blob); err != nil {
		t.Fatal(err)
	}
	ref := []byte(KeyFromValue(blob).String())
	if res, err := nodes[1].Update(ctx, mkey, ref); err != nil || len(res.Accepted) != 10 {
		t.Fatalf("referencing a stored blob: %+v, %v", res, err)
	}
	missing := []byte(KeyFromValue([]byte("nowhere")).String())
	res, err := nodes[2].Update(ctx, KeyFromValue([]byte("other key")), missing)
	if err == nil || len(res.Refused) != 10 || !strings.Contains(res.Refused[0].Reason, "cannot fetch") {
		t.Fatalf("referencing a missing blob: %+v, %v", res, err)
	}
}

func TestReplicationHealsStaleHolder(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	sim := network.NewSimNetwork(network.SimConfig{})
	cfg := mutableConfig(&monotonic{})
	nodes := newTestNetwork(t, sim, 25, cfg)
	for _, n := range nodes {
		n.cfg.ReplicateInterval = time.Hour // replicateStale's threshold; no loop runs
	}
	res, err := nodes[0].Update(ctx, mkey, []byte("v2"))
	if err != nil {
		t.Fatal(err)
	}
	// Make one holder stale: it kept an older value (as if it missed v2).
	stale := byID(nodes, res.Accepted[9].ID)
	if err := stale.store.PutMutable(mkey, []byte("v1"), []byte("v2")); err != nil {
		t.Fatal(err)
	}
	// The stale holder republishes: everyone else refuses its old value.
	stale.store.mu.Lock()
	e := stale.store.entries[mkey]
	e.stored = time.Now().Add(-2 * time.Hour)
	stale.store.entries[mkey] = e
	stale.store.mu.Unlock()
	stale.replicateStale()
	if v, _ := byID(nodes, res.Accepted[0].ID).store.Get(mkey); string(v) != "v2" {
		t.Errorf("a stale republish changed a fresh holder to %q", v)
	}
	// A fresh holder republishes: the stale one validates and catches up.
	fresh := byID(nodes, res.Accepted[0].ID)
	fresh.store.mu.Lock()
	e = fresh.store.entries[mkey]
	e.stored = time.Now().Add(-2 * time.Hour)
	fresh.store.entries[mkey] = e
	fresh.store.mu.Unlock()
	fresh.replicateStale()
	if v, _ := stale.store.Get(mkey); string(v) != "v2" {
		t.Errorf("stale holder still has %q after replication", v)
	}
}

func TestUpdateAlone(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	sim := network.NewSimNetwork(network.SimConfig{})
	node := newTestNetwork(t, sim, 1, mutableConfig(&monotonic{}))[0]
	res, err := node.Update(ctx, mkey, []byte("v1"))
	if err != nil || len(res.Accepted) != 1 || res.Accepted[0] != node.Me() {
		t.Fatalf("alone: %+v, %v", res, err)
	}
	copies, err := node.LookupAll(ctx, mkey)
	if err != nil || len(copies) != 1 || string(copies[0].Value) != "v1" {
		t.Fatalf("LookupAll alone: %v, %v", copies, err)
	}
	if _, err := node.Update(ctx, mkey, make([]byte, MaxValueSize+1)); err == nil {
		t.Error("an oversize value was accepted")
	}
}

func TestUpdateOverUDP(t *testing.T) {
	ctx := context.Background()
	cfg := mutableConfig(&monotonic{})
	var nodes []*Kademlia
	for i := range 4 {
		n, err := NewKademlia(network.UDPNetwork{}, netip.MustParseAddrPort("127.0.0.1:0"), cfg)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { n.Close() })
		if i > 0 {
			if err := n.Join(ctx, nodes[0].Me().Address); err != nil {
				t.Fatal(err)
			}
		}
		nodes = append(nodes, n)
	}
	if res, err := nodes[1].Update(ctx, mkey, []byte("v1")); err != nil || len(res.Accepted) != 4 {
		t.Fatalf("Update over UDP/TCP: %+v, %v", res, err)
	}
	copies, err := nodes[3].LookupAll(ctx, mkey)
	if err != nil || len(copies) != 4 {
		t.Fatalf("LookupAll over TCP: %d copies, %v", len(copies), err)
	}
}
