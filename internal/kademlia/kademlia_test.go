package kademlia

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"net/netip"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/jonamarkin/lab-mobidist/internal/network"
	"github.com/jonamarkin/lab-mobidist/internal/rpc"
)

// testConfig uses shorter timeouts than the default so tests with dead
// nodes stay fast, but long enough that a busy machine (-race, parallel
// tests) does not make live nodes look dead.
func testConfig(alpha int) Config {
	return Config{K: 10, Alpha: alpha, RPC: rpc.Config{Timeout: 200 * time.Millisecond, Retries: 1}}
}

// newTestNetwork starts n nodes at testAddr(0..n-1); node 0 is the
// bootstrap node and every other node joins through it, one at a time.
func newTestNetwork(t *testing.T, sim *network.SimNetwork, n int, cfg Config) []*Kademlia {
	t.Helper()
	nodes := make([]*Kademlia, n)
	for i := range n {
		k, err := NewKademlia(sim, testAddr(i), cfg)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { k.Close() })
		if i > 0 {
			if err := k.Join(context.Background(), nodes[0].Me().Address); err != nil {
				t.Fatalf("node %d join: %v", i, err)
			}
		}
		nodes[i] = k
	}
	return nodes
}

// oracle returns the true k closest live nodes to target, excluding the
// node doing the lookup: the answer a perfect lookup would give.
func oracle(nodes []*Kademlia, exclude KademliaID, target KademliaID, k int) []Contact {
	var all []Contact
	for _, n := range nodes {
		if n.Me().ID != exclude {
			all = append(all, n.Me())
		}
	}
	return bruteForceClosest(all, target, k)
}

func TestPing(t *testing.T) {
	sim := network.NewSimNetwork(network.SimConfig{})
	nodes := newTestNetwork(t, sim, 2, testConfig(3))
	a, b := nodes[0], nodes[1]

	if _, err := a.Ping(context.Background(), b.Me().Address); err != nil {
		t.Fatal(err)
	}
	// Both sides learned about each other: a from the response, b from the request.
	if got := a.RoutingTable().FindClosestContacts(b.Me().ID, 1); len(got) != 1 || got[0] != b.Me() {
		t.Errorf("a's table: %v", got)
	}
	if got := b.RoutingTable().FindClosestContacts(a.Me().ID, 1); len(got) != 1 || got[0] != a.Me() {
		t.Errorf("b's table: %v", got)
	}
}

func TestPingDeadNodeIsRemoved(t *testing.T) {
	sim := network.NewSimNetwork(network.SimConfig{})
	nodes := newTestNetwork(t, sim, 2, testConfig(3))
	a, b := nodes[0], nodes[1]
	b.Close()

	if _, err := a.Ping(context.Background(), b.Me().Address); !errors.Is(err, rpc.ErrTimeout) {
		t.Fatalf("got %v, want ErrTimeout", err)
	}
	if got := a.RoutingTable().FindClosestContacts(b.Me().ID, 10); len(got) != 0 {
		t.Errorf("dead node still in table: %v", got)
	}
}

func TestJoinUnreachableBootstrap(t *testing.T) {
	sim := network.NewSimNetwork(network.SimConfig{})
	k, err := NewKademlia(sim, testAddr(1), testConfig(3))
	if err != nil {
		t.Fatal(err)
	}
	defer k.Close()
	if err := k.Join(context.Background(), testAddr(99)); !errors.Is(err, rpc.ErrTimeout) {
		t.Errorf("got %v, want ErrTimeout", err)
	}
}

func TestNewKademliaAddrInUse(t *testing.T) {
	sim := network.NewSimNetwork(network.SimConfig{})
	newTestNetwork(t, sim, 1, testConfig(3))
	if _, err := NewKademlia(sim, testAddr(0), testConfig(3)); !errors.Is(err, network.ErrAddrInUse) {
		t.Errorf("got %v, want ErrAddrInUse", err)
	}
}

func TestLookupAloneHasNoContacts(t *testing.T) {
	sim := network.NewSimNetwork(network.SimConfig{})
	nodes := newTestNetwork(t, sim, 1, testConfig(3))
	if _, err := nodes[0].LookupContact(context.Background(), testContact(5).ID); !errors.Is(err, ErrNoContacts) {
		t.Errorf("got %v, want ErrNoContacts", err)
	}
}

// The main correctness test: lookups from random nodes for random targets
// must find exactly the true k closest nodes, for alpha = 1 and alpha = 3.
func TestLookupMatchesOracle(t *testing.T) {
	for _, alpha := range []int{1, 3} {
		t.Run(fmt.Sprintf("alpha=%d", alpha), func(t *testing.T) {
			t.Parallel()
			sim := network.NewSimNetwork(network.SimConfig{})
			nodes := newTestNetwork(t, sim, 100, testConfig(alpha))
			r := rand.New(rand.NewPCG(10, uint64(alpha)))

			for range 25 {
				from := nodes[r.IntN(len(nodes))]
				target := NewRandomKademliaID(r)
				res, err := from.LookupContact(context.Background(), target)
				if err != nil {
					t.Fatal(err)
				}
				want := oracle(nodes, from.Me().ID, target, 10)
				if !slices.Equal(res.Contacts, want) {
					t.Fatalf("target %v:\n got  %v\n want %v", target.Short(), res.Contacts, want)
				}
			}
		})
	}
}

// recall is the fraction of the true closest nodes (want) that a lookup found.
func recall(got, want []Contact) (found, total int) {
	for _, c := range want {
		if slices.Contains(got, c) {
			found++
		}
	}
	return found, len(want)
}

// After a quarter of the nodes leave at once, lookups never return a dead
// node and still find most of the true k closest live nodes. (Not all:
// responders still list dead contacts they have not detected yet, which
// can push a live node out of every k-sized reply.)
func TestLookupSkipsDeadNodes(t *testing.T) {
	t.Parallel()
	sim := network.NewSimNetwork(network.SimConfig{})
	nodes := newTestNetwork(t, sim, 60, testConfig(3))
	r := rand.New(rand.NewPCG(11, 11))

	var alive []*Kademlia
	dead := make(map[Contact]bool)
	for i, n := range nodes {
		if i > 0 && r.IntN(4) == 0 { // about a quarter leave (never the bootstrap)
			n.Close()
			dead[n.Me()] = true
		} else {
			alive = append(alive, n)
		}
	}
	found, total := 0, 0
	for range 10 {
		from := alive[r.IntN(len(alive))]
		target := NewRandomKademliaID(r)
		res, err := from.LookupContact(context.Background(), target)
		if err != nil {
			t.Fatal(err)
		}
		for _, c := range res.Contacts {
			if dead[c] {
				t.Errorf("lookup returned dead node %v", c)
			}
		}
		f, n := recall(res.Contacts, oracle(alive, from.Me().ID, target, 10))
		found, total = found+f, total+n
	}
	if r := float64(found) / float64(total); r < 0.8 {
		t.Errorf("found %.0f%% of the true closest live nodes, want >= 80%%", 100*r)
	}
}

// With packet loss some probes fail, but lookups should still find most
// of the true k closest nodes (retries and alternative contacts).
func TestLookupWithPacketLoss(t *testing.T) {
	t.Parallel()
	sim := network.NewSimNetwork(network.SimConfig{Seed: 12})
	nodes := newTestNetwork(t, sim, 100, testConfig(3))
	sim.SetLossRate(0.1)
	r := rand.New(rand.NewPCG(12, 12))

	found, total := 0, 0
	for range 20 {
		from := nodes[r.IntN(len(nodes))]
		target := NewRandomKademliaID(r)
		res, _ := from.LookupContact(context.Background(), target)
		f, n := recall(res.Contacts, oracle(nodes, from.Me().ID, target, 10))
		found, total = found+f, total+n
	}
	if recall := float64(found) / float64(total); recall < 0.8 {
		t.Errorf("found %.0f%% of the true closest nodes, want >= 80%%", 100*recall)
	}
}

func TestLookupContextCancel(t *testing.T) {
	sim := network.NewSimNetwork(network.SimConfig{})
	nodes := newTestNetwork(t, sim, 20, testConfig(3))
	sim.SetLossRate(1) // nothing gets through: probes hang until cancelled

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := nodes[5].LookupContact(ctx, testContact(99).ID); !errors.Is(err, context.Canceled) {
		t.Errorf("got %v, want context.Canceled", err)
	}
}

func TestHandleUnknownMethodAndBadArgs(t *testing.T) {
	sim := network.NewSimNetwork(network.SimConfig{})
	nodes := newTestNetwork(t, sim, 1, testConfig(3))
	conn, _ := sim.ListenPacket(testAddr(50))
	client := rpc.NewEndpoint(conn, nil, testConfig(3).RPC)
	defer client.Close()
	ctx := context.Background()

	var re *rpc.RemoteError
	if err := client.Call(ctx, nodes[0].Me().Address, "NOPE", nil, nil); !errors.As(err, &re) {
		t.Errorf("unknown method: got %v", err)
	}
	if err := client.Call(ctx, nodes[0].Me().Address, MethodFindNode, map[string]string{"target": "zz"}, nil); !errors.As(err, &re) {
		t.Errorf("bad args: got %v", err)
	}
}

// A peer that returns more than k contacts is truncated to k.
func TestFindNodeTruncatesOversizedReply(t *testing.T) {
	sim := network.NewSimNetwork(network.SimConfig{})
	cfg := testConfig(3)
	k, _ := NewKademlia(sim, testAddr(0), cfg)
	defer k.Close()

	liar, _ := sim.ListenPacket(testAddr(1))
	greedy := func(from netip.AddrPort, method string, body json.RawMessage) (any, error) {
		var many []netip.AddrPort
		for i := range 30 {
			many = append(many, testAddr(100+i))
		}
		return findNodeReply{Contacts: many}, nil
	}
	e := rpc.NewEndpoint(liar, greedy, cfg.RPC)
	defer e.Close()

	got, err := k.findNode(context.Background(), NewContact(NewNodeID(testAddr(1)), testAddr(1)), testContact(5).ID)
	if err != nil || len(got) != cfg.K {
		t.Errorf("got %d contacts (%v), want %d", len(got), err, cfg.K)
	}
}

// syncBuffer is an io.Writer that is safe for the concurrent log writes
// of many nodes.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) reset() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.buf.Reset()
}

func (b *syncBuffer) bytes() []byte {
	b.mu.Lock()
	defer b.mu.Unlock()
	return bytes.Clone(b.buf.Bytes())
}

// The log is machine-readable (one JSON object per line), records every
// probe, and shows that no more than alpha probes are ever in flight.
func TestLookupLogging(t *testing.T) {
	t.Parallel()
	const alpha = 3
	var logs syncBuffer
	cfg := testConfig(alpha)
	sim := network.NewSimNetwork(network.SimConfig{})
	nodes := newTestNetwork(t, sim, 50, cfg)

	cfg.Logger = slog.New(slog.NewJSONHandler(&logs, nil))
	k, err := NewKademlia(sim, testAddr(1000), cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer k.Close()
	k.RoutingTable().AddContact(nodes[0].Me())
	res, err := k.LookupContact(context.Background(), testContact(7).ID)
	if err != nil {
		t.Fatal(err)
	}

	probes, inFlight, maxInFlight, done := 0, 0, 0, 0
	for line := range bytes.Lines(logs.buf.Bytes()) {
		var rec map[string]any
		if err := json.Unmarshal(line, &rec); err != nil {
			t.Fatalf("log line is not JSON: %s", line)
		}
		switch rec["msg"] {
		case "probe":
			probes++
			inFlight++
			maxInFlight = max(maxInFlight, inFlight)
		case "probe_ok", "probe_failed":
			inFlight--
		case "lookup_done":
			done++
			if rec["ok"] != true || int(rec["probes"].(float64)) != res.Probes {
				t.Errorf("lookup_done record: %v", rec)
			}
		}
	}
	if probes != res.Probes || done != 1 {
		t.Errorf("logged %d probes and %d lookup_done, result says %d probes", probes, done, res.Probes)
	}
	if maxInFlight > alpha {
		t.Errorf("%d probes in flight at once, alpha = %d", maxInFlight, alpha)
	}
}

func TestRoutingTableChoice(t *testing.T) {
	sim := network.NewSimNetwork(network.SimConfig{})
	cfg := testConfig(3)
	k, _ := NewKademlia(sim, testAddr(0), cfg)
	defer k.Close()
	if _, ok := k.RoutingTable().(*BucketRoutingTable); !ok {
		t.Errorf("default table is %T, want *BucketRoutingTable", k.RoutingTable())
	}
	cfg.FlatRoutingTable = true
	f, _ := NewKademlia(sim, testAddr(1), cfg)
	defer f.Close()
	if _, ok := f.RoutingTable().(*FlatRoutingTable); !ok {
		t.Errorf("flat table is %T", f.RoutingTable())
	}
}

// pingOldest: a live node is kept, a dead one (timeout) is evicted.
func TestPingOldest(t *testing.T) {
	sim := network.NewSimNetwork(network.SimConfig{})
	nodes := newTestNetwork(t, sim, 3, testConfig(3))
	nodes[2].Close()
	if !nodes[0].pingOldest(nodes[1].Me()) {
		t.Error("live node reported dead")
	}
	if nodes[0].pingOldest(nodes[2].Me()) {
		t.Error("dead node reported alive")
	}
}

// With a short RefreshInterval, idle nodes refresh their buckets in the
// background, and Close stops the refresh loop.
func TestPeriodicRefresh(t *testing.T) {
	var logs syncBuffer
	cfg := testConfig(3)
	cfg.RefreshInterval = 50 * time.Millisecond
	cfg.Logger = slog.New(slog.NewJSONHandler(&logs, nil))
	sim := network.NewSimNetwork(network.SimConfig{})
	newTestNetwork(t, sim, 10, cfg)

	deadline := time.Now().Add(5 * time.Second)
	for !bytes.Contains(logs.bytes(), []byte(`"reason":"periodic"`)) {
		if time.Now().After(deadline) {
			t.Fatal("no periodic refresh logged")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// A lookup marks its bucket as recently used: right after a refresh pass,
// a second pass has nothing to do. Once no lookups have happened for
// RefreshInterval, every bucket from the closest neighbor's up is stale.
func TestRefreshSkipsRecentlyUsedBuckets(t *testing.T) {
	var logs syncBuffer
	cfg := testConfig(3)
	cfg.RefreshInterval = time.Hour // the loop never fires during the test
	sim := network.NewSimNetwork(network.SimConfig{})
	nodes := newTestNetwork(t, sim, 10, cfg)

	k := nodes[5]
	k.log = slog.New(slog.NewJSONHandler(&logs, nil))
	k.refreshStale() // buckets nodes 6-9 moved into after k joined are stale
	logs.reset()
	k.refreshStale()
	if bytes.Contains(logs.bytes(), []byte(`"msg":"refresh"`)) {
		t.Errorf("refreshed recently used buckets:\n%s", logs.bytes())
	}

	k.mu.Lock()
	k.lastLookup = [IDBits]time.Time{} // pretend no lookups ever happened
	k.mu.Unlock()
	k.refreshStale()
	closest := k.RoutingTable().FindClosestContacts(k.Me().ID, 1)[0]
	want := IDBits - BucketIndex(k.Me().ID, closest.ID)
	if got := bytes.Count(logs.bytes(), []byte(`"reason":"periodic"`)); got != want {
		t.Errorf("refreshed %d buckets, want %d", got, want)
	}
}

func TestRefreshStaleWithEmptyTable(t *testing.T) {
	sim := network.NewSimNetwork(network.SimConfig{})
	k, _ := NewKademlia(sim, testAddr(0), testConfig(3))
	defer k.Close()
	k.refreshStale() // nothing to do, must not panic
}
