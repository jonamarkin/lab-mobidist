package kademlia

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"slices"
	"testing"
	"time"

	"github.com/jonamarkin/lab-mobidist/internal/network"
)

func TestStoreKeysOlderThanAndTouch(t *testing.T) {
	s := NewDataStore()
	v := []byte("v")
	key := KeyFromValue(v)
	s.Put(key, v)
	if got := s.KeysOlderThan(time.Hour); len(got) != 0 {
		t.Errorf("fresh key reported stale: %v", got)
	}
	s.entries[key] = entry{value: v, stored: time.Now().Add(-2 * time.Hour)}
	if got := s.KeysOlderThan(time.Hour); len(got) != 1 || got[0] != key {
		t.Errorf("old key not reported: %v", got)
	}
	s.Touch(key)
	if got := s.KeysOlderThan(time.Hour); len(got) != 0 {
		t.Errorf("touched key still stale: %v", got)
	}
	s.Touch(KeyFromValue([]byte("absent"))) // no effect, no panic
	if len(s.Keys()) != 1 {
		t.Error("Touch created an entry")
	}
}

// aliveNodes returns the nodes not in dead.
func aliveNodes(nodes []*Kademlia, dead map[Contact]bool) []*Kademlia {
	var out []*Kademlia
	for _, n := range nodes {
		if !dead[n.Me()] {
			out = append(out, n)
		}
	}
	return out
}

// churn stores a value, kills 7 of its 10 holders, gives replication a
// chance to run (if enabled), then kills the 3 remaining original holders
// too. It returns whether the value can still be found.
func churn(t *testing.T, replicate bool) bool {
	cfg := testConfig(3)
	if replicate {
		cfg.ReplicateInterval = 300 * time.Millisecond
	}
	sim := network.NewSimNetwork(network.SimConfig{})
	nodes := newTestNetwork(t, sim, 40, cfg)
	ctx := context.Background()

	value := []byte("a package that must survive churn")
	res, err := nodes[0].Store(ctx, value)
	if err != nil || len(res.StoredAt) != 10 {
		t.Fatalf("Store: %+v, %v", res, err)
	}
	original := res.StoredAt
	dead := make(map[Contact]bool)
	kill := func(cs []Contact) {
		for _, c := range cs {
			byID(nodes, c.ID).Close()
			dead[c] = true
		}
	}

	kill(original[:7])
	if replicate {
		// Wait until the value is on the true k closest live nodes again.
		alive := aliveNodes(nodes, dead)
		want := bruteForceClosest(contactsOf(alive), res.Key, 10)
		deadline := time.Now().Add(15 * time.Second)
		for {
			got := holders(alive, res.Key)
			SortContactsByDistance(got, res.Key)
			if slices.Equal(got[:min(len(got), 10)], want) {
				break
			}
			if time.Now().After(deadline) {
				t.Fatalf("not re-replicated: holders %v\nwant %v", got, want)
			}
			time.Sleep(50 * time.Millisecond)
		}
	}
	kill(original[7:]) // every original holder is now gone

	reader := aliveNodes(nodes, dead)[0]
	found, err := reader.LookupData(ctx, res.Key)
	if err != nil && !errors.Is(err, ErrNotFound) {
		t.Fatalf("LookupData: %v", err)
	}
	return err == nil && bytes.Equal(found.Value, value)
}

// The key test: with replication, a value outlives all of its original
// holders, because the survivors copied it to the new k closest nodes
// before they too left.
func TestReplicationSurvivesChurn(t *testing.T) {
	t.Parallel()
	if !churn(t, true) {
		t.Error("value lost despite replication")
	}
}

// The control: the same churn without replication loses the value.
func TestNoReplicationLosesValue(t *testing.T) {
	t.Parallel()
	if churn(t, false) {
		t.Error("value survived without replication: the churn test proves nothing")
	}
}

// A value stored within the interval is skipped (someone else republished
// it); once it is older than the interval it is republished to the k
// closest nodes, and our own copy counts as refreshed.
func TestReplicateStaleSkipsFreshValues(t *testing.T) {
	sim := network.NewSimNetwork(network.SimConfig{})
	nodes := newTestNetwork(t, sim, 15, testConfig(3))
	n := nodes[4]
	n.cfg.ReplicateInterval = time.Hour // replicateStale's threshold; no loop runs
	var logs syncBuffer
	n.log = slog.New(slog.NewJSONHandler(&logs, nil))

	value := []byte("held only by n")
	key := KeyFromValue(value)
	n.DataStore().Put(key, value)

	n.replicateStale()
	if bytes.Contains(logs.bytes(), []byte(`"msg":"replicate"`)) {
		t.Error("fresh value was replicated")
	}

	n.store.mu.Lock()
	n.store.entries[key] = entry{value: value, stored: time.Now().Add(-2 * time.Hour)}
	n.store.mu.Unlock()
	n.replicateStale()

	if !bytes.Contains(logs.bytes(), []byte(`"msg":"replicate"`)) {
		t.Fatal("stale value was not replicated")
	}
	want := bruteForceClosest(contactsOf(nodes), key, 10)
	for _, c := range want {
		if _, ok := byID(nodes, c.ID).DataStore().Get(key); !ok {
			t.Errorf("%v (one of the k closest) did not receive the value", c)
		}
	}
	if stale := n.DataStore().KeysOlderThan(time.Hour); len(stale) != 0 {
		t.Error("own copy not refreshed after replicating")
	}
}

// The background loop runs rounds and stops on Close.
func TestReplicateLoop(t *testing.T) {
	var logs syncBuffer
	cfg := testConfig(3)
	cfg.ReplicateInterval = 50 * time.Millisecond
	cfg.Logger = slog.New(slog.NewJSONHandler(&logs, nil))
	sim := network.NewSimNetwork(network.SimConfig{})
	newTestNetwork(t, sim, 5, cfg)

	deadline := time.Now().Add(5 * time.Second)
	for !bytes.Contains(logs.bytes(), []byte(`"msg":"replicate_round"`)) {
		if time.Now().After(deadline) {
			t.Fatal("no replication round logged")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// A replication that cannot store anywhere is logged, not fatal.
func TestReplicateFailureIsLogged(t *testing.T) {
	sim := network.NewSimNetwork(network.SimConfig{})
	k := newTestNetwork(t, sim, 1, testConfig(3))[0]
	k.cfg.ReplicateInterval = time.Hour
	var logs syncBuffer
	k.log = slog.New(slog.NewJSONHandler(&logs, nil))

	value := make([]byte, MaxValueSize+1) // Store refuses it
	key := KeyFromValue(value)
	k.store.entries[key] = entry{value: value, stored: time.Now().Add(-2 * time.Hour)}
	k.replicateStale()
	if !bytes.Contains(logs.bytes(), []byte(`"msg":"replicate_failed"`)) {
		t.Error("failure not logged")
	}
}
