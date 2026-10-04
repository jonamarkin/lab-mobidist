package kademlia

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"slices"
	"sync"
	"testing"

	"github.com/jonamarkin/lab-mobidist/internal/network"
)

func TestStorePutGet(t *testing.T) {
	s := NewStore()
	v := []byte("hello")
	if err := s.Put(KeyFromValue(v), v); err != nil {
		t.Fatal(err)
	}
	v[0] = 'X' // the store keeps its own copy
	if got, ok := s.Get(KeyFromValue([]byte("hello"))); !ok || string(got) != "hello" {
		t.Errorf("Get = %q, %v", got, ok)
	}
	if _, ok := s.Get(KeyFromValue([]byte("other"))); ok {
		t.Error("Get of a missing key succeeded")
	}
}

// The spec: K -> V is accepted iff K = hash(V).
func TestStoreRejectsWrongKey(t *testing.T) {
	s := NewStore()
	if err := s.Put(KeyFromValue([]byte("a")), []byte("b")); !errors.Is(err, ErrHashMismatch) {
		t.Errorf("got %v, want ErrHashMismatch", err)
	}
	if len(s.Keys()) != 0 {
		t.Error("mismatching value was stored")
	}
}

func TestStoreKeysSorted(t *testing.T) {
	s := NewStore()
	for i := range 20 {
		v := fmt.Appendf(nil, "value %d", i)
		s.Put(KeyFromValue(v), v)
	}
	keys := s.Keys()
	if len(keys) != 20 || !slices.IsSortedFunc(keys, KademliaID.Cmp) {
		t.Errorf("Keys() = %d keys, sorted %v", len(keys), slices.IsSortedFunc(keys, KademliaID.Cmp))
	}
}

func TestStoreConcurrent(t *testing.T) {
	s := NewStore()
	var wg sync.WaitGroup
	for g := range 8 {
		wg.Go(func() {
			for i := range 50 {
				v := fmt.Appendf(nil, "%d-%d", g, i)
				s.Put(KeyFromValue(v), v)
				s.Get(KeyFromValue(v))
				s.Keys()
			}
		})
	}
	wg.Wait()
}

// holders returns the nodes whose local store has key.
func holders(nodes []*Kademlia, key KademliaID) []Contact {
	var out []Contact
	for _, n := range nodes {
		if _, ok := n.DataStore().Get(key); ok {
			out = append(out, n.Me())
		}
	}
	return out
}

// After Store, the value is on exactly the true k closest nodes (oracle),
// and a lookup from any other node finds it.
func TestStoreAndLookupData(t *testing.T) {
	t.Parallel()
	sim := network.NewSimNetwork(network.SimConfig{})
	nodes := newTestNetwork(t, sim, 60, testConfig(3))
	r := rand.New(rand.NewPCG(30, 30))
	ctx := context.Background()

	for i := range 10 {
		value := fmt.Appendf(nil, "package contents %d", i)
		publisher := nodes[r.IntN(len(nodes))]
		res, err := publisher.Store(ctx, value)
		if err != nil {
			t.Fatal(err)
		}
		key := KeyFromValue(value)
		if res.Key != key || res.Failed != 0 {
			t.Errorf("result %+v", res)
		}

		want := bruteForceClosest(contactsOf(nodes), key, 10)
		got := holders(nodes, key)
		SortContactsByDistance(got, key)
		if !slices.Equal(got, want) || !slices.Equal(res.StoredAt, want) {
			t.Fatalf("stored at %v\nwant %v", got, want)
		}

		reader := nodes[r.IntN(len(nodes))]
		found, err := reader.LookupData(ctx, key)
		if err != nil || !bytes.Equal(found.Value, value) {
			t.Fatalf("LookupData: %q, %v", found.Value, err)
		}
		if !slices.Contains(want, found.From) {
			t.Errorf("value came from %v, not one of the holders", found.From)
		}
	}
}

func contactsOf(nodes []*Kademlia) []Contact {
	out := make([]Contact, len(nodes))
	for i, n := range nodes {
		out[i] = n.Me()
	}
	return out
}

func TestLookupDataNotFound(t *testing.T) {
	sim := network.NewSimNetwork(network.SimConfig{})
	nodes := newTestNetwork(t, sim, 20, testConfig(3))
	res, err := nodes[3].LookupData(context.Background(), KeyFromValue([]byte("never stored")))
	if !errors.Is(err, ErrNotFound) || res.Value != nil {
		t.Errorf("got %q, %v; want ErrNotFound", res.Value, err)
	}
}

// A node that is alone stores locally and finds the value itself.
func TestStoreAlone(t *testing.T) {
	sim := network.NewSimNetwork(network.SimConfig{})
	k := newTestNetwork(t, sim, 1, testConfig(3))[0]
	res, err := k.Store(context.Background(), []byte("solo"))
	if err != nil || len(res.StoredAt) != 1 || res.StoredAt[0] != k.Me() {
		t.Fatalf("Store = %+v, %v", res, err)
	}
	found, err := k.LookupData(context.Background(), res.Key)
	if err != nil || string(found.Value) != "solo" || found.From != k.Me() {
		t.Errorf("LookupData = %+v, %v", found, err)
	}
}

func TestStoreTooLarge(t *testing.T) {
	sim := network.NewSimNetwork(network.SimConfig{})
	k := newTestNetwork(t, sim, 1, testConfig(3))[0]
	if _, err := k.Store(context.Background(), make([]byte, MaxValueSize+1)); err == nil {
		t.Error("oversize value accepted")
	}
}

// Values far beyond one packet travel over the data plane.
func TestStoreLargeValue(t *testing.T) {
	sim := network.NewSimNetwork(network.SimConfig{})
	nodes := newTestNetwork(t, sim, 15, testConfig(3))
	value := make([]byte, 2<<20)              // 2 MiB
	rand.NewChaCha8([32]byte{31}).Read(value) // repeatable random bytes
	res, err := nodes[1].Store(context.Background(), value)
	if err != nil {
		t.Fatal(err)
	}
	found, err := nodes[9].LookupData(context.Background(), res.Key)
	if err != nil || !bytes.Equal(found.Value, value) {
		t.Errorf("LookupData: %d bytes, %v", len(found.Value), err)
	}
}

// A node that holds a corrupted copy is detected (hash_mismatch is logged
// as an error) and skipped: the value comes from another holder.
func TestLookupDataSkipsCorruptCopy(t *testing.T) {
	var logs syncBuffer
	sim := network.NewSimNetwork(network.SimConfig{})
	nodes := newTestNetwork(t, sim, 30, testConfig(1)) // alpha 1: probes in order
	ctx := context.Background()

	value := []byte("genuine")
	res, err := nodes[0].Store(ctx, value)
	if err != nil {
		t.Fatal(err)
	}
	// Corrupt the copy on the holder closest to the key, bypassing Put.
	closest := byID(nodes, res.StoredAt[0].ID)
	closest.store.mu.Lock()
	closest.store.entries[res.Key] = entry{value: []byte("tampered")}
	closest.store.mu.Unlock()

	var reader *Kademlia
	for _, n := range nodes {
		if !slices.Contains(res.StoredAt, n.Me()) {
			reader = n
			break
		}
	}
	reader.log = slog.New(slog.NewJSONHandler(&logs, nil))
	found, err := reader.LookupData(ctx, res.Key)
	if err != nil || string(found.Value) != "genuine" {
		t.Fatalf("LookupData = %q, %v", found.Value, err)
	}
	if found.From == closest.Me() {
		t.Error("value accepted from the corrupt holder")
	}
	if bytes.Contains(logs.bytes(), []byte(`"msg":"hash_mismatch"`)) {
		return
	}
	// With alpha = 1 the closest holder is not necessarily probed first,
	// so check the fetch path directly as well.
	if _, err := reader.fetchFrom(ctx, closest.Me(), res.Key); !errors.Is(err, ErrHashMismatch) {
		t.Errorf("fetch from corrupt holder: %v", err)
	}
	if !bytes.Contains(logs.bytes(), []byte(`"msg":"hash_mismatch"`)) {
		t.Error("hash mismatch not logged")
	}
}

func byID(nodes []*Kademlia, id KademliaID) *Kademlia {
	for _, n := range nodes {
		if n.Me().ID == id {
			return n
		}
	}
	return nil
}

// If every holder is corrupt, the lookup reports not found.
func TestLookupDataAllCopiesCorrupt(t *testing.T) {
	sim := network.NewSimNetwork(network.SimConfig{})
	nodes := newTestNetwork(t, sim, 20, testConfig(3)) // more nodes than k, so some are not holders
	ctx := context.Background()
	res, _ := nodes[0].Store(ctx, []byte("v"))
	for _, c := range res.StoredAt {
		n := byID(nodes, c.ID)
		n.store.mu.Lock()
		n.store.entries[res.Key] = entry{value: []byte("bad")}
		n.store.mu.Unlock()
	}
	var reader *Kademlia
	for _, n := range nodes {
		if !slices.Contains(res.StoredAt, n.Me()) {
			reader = n
		}
	}
	if _, err := reader.LookupData(ctx, res.Key); !errors.Is(err, ErrNotFound) {
		t.Errorf("got %v, want ErrNotFound", err)
	}
}

// The data-plane server itself rejects a STORE whose key is not the hash
// of the value, an oversize announcement, garbage, and unknown ops.
func TestDataPlaneServerRejects(t *testing.T) {
	sim := network.NewSimNetwork(network.SimConfig{})
	nodes := newTestNetwork(t, sim, 2, testConfig(3))
	server, client := nodes[0], nodes[1]
	ctx := context.Background()

	err := client.storeAt(ctx, server.Me(), KeyFromValue([]byte("a")), []byte("b"))
	if err == nil || !bytes.Contains([]byte(err.Error()), []byte("hash")) {
		t.Errorf("wrong key: %v", err)
	}
	if len(server.DataStore().Keys()) != 0 {
		t.Error("mismatching value was stored")
	}

	for _, req := range []string{
		`{"op":"STORE","key":"` + KeyFromValue(nil).String() + `","size":999999999999}` + "\n",
		"not json\n",
		`{"op":"DELETE","key":"` + KeyFromValue(nil).String() + `"}` + "\n",
		string(bytes.Repeat([]byte("x"), 2*maxHeaderSize)) + "\n",
	} {
		conn, r, err := client.dial(ctx, server.Me())
		if err != nil {
			t.Fatal(err)
		}
		go conn.Write([]byte(req))
		var resp streamResponse
		if err := readHeader(r, &resp); err != nil || resp.OK {
			t.Errorf("request %.40q: response %+v, %v", req, resp, err)
		}
		conn.Close()
	}

	if _, err := client.fetchFrom(ctx, server.Me(), KeyFromValue([]byte("absent"))); err == nil {
		t.Error("fetch of absent key succeeded")
	}
}

func TestDataPlaneUnreachable(t *testing.T) {
	sim := network.NewSimNetwork(network.SimConfig{})
	nodes := newTestNetwork(t, sim, 2, testConfig(3))
	gone := nodes[1].Me()
	nodes[1].Close()
	ctx := context.Background()
	if err := nodes[0].storeAt(ctx, gone, KeyFromValue(nil), nil); err == nil {
		t.Error("store to a departed node succeeded")
	}
	if _, err := nodes[0].fetchFrom(ctx, gone, KeyFromValue(nil)); err == nil {
		t.Error("fetch from a departed node succeeded")
	}
}

func TestReadValueBounds(t *testing.T) {
	if _, err := readValue(bufio.NewReader(bytes.NewReader(nil)), -1); err == nil {
		t.Error("negative size accepted")
	}
	if _, err := readValue(bufio.NewReader(bytes.NewReader([]byte("ab"))), 5); err == nil {
		t.Error("short value accepted")
	}
}
