package testnet

import (
	"bytes"
	"context"
	"fmt"
	"math/rand/v2"
	"slices"
	"testing"
	"time"

	"github.com/jonamarkin/lab-mobidist/internal/kademlia"
	"github.com/jonamarkin/lab-mobidist/internal/rpc"
)

func config() kademlia.Config {
	return kademlia.Config{K: 10, Alpha: 3, RPC: rpc.Config{Timeout: 200 * time.Millisecond, Retries: 1}}
}

// The spec's large-scale requirement: 1000 nodes on the simulated network.
// Lookups must find the true k closest nodes, and values stored by random
// nodes must be retrievable from other random nodes.
func TestThousandNodes(t *testing.T) {
	if testing.Short() {
		t.Skip("1000-node test skipped with -short")
	}
	ctx := context.Background()
	start := time.Now()
	nw, err := Build(ctx, Options{N: 1000, Seed: 1, Node: config()})
	if err != nil {
		t.Fatal(err)
	}
	defer nw.Close()
	t.Logf("built 1000 nodes in %v", time.Since(start).Round(time.Millisecond))

	const lookups = 30
	exact, probes, hops := 0, 0, 0
	for range lookups {
		from := nw.Nodes[nw.Rand.IntN(len(nw.Nodes))]
		target := kademlia.NewRandomKademliaID(nw.Rand)
		res, err := from.LookupContact(ctx, target)
		if err != nil {
			t.Fatal(err)
		}
		if slices.Equal(res.Contacts, nw.Closest(target, from.Me().ID, 10)) {
			exact++
		}
		probes += res.Probes
		hops += res.Hops
	}
	t.Logf("%d/%d lookups exact; mean %.1f probes, %.2f hops", exact, lookups, float64(probes)/lookups, float64(hops)/lookups)
	if exact < lookups*9/10 {
		t.Errorf("only %d/%d lookups found the true k closest nodes", exact, lookups)
	}

	for i := range 10 {
		value := fmt.Appendf(nil, "random value %d: %x", i, nw.Rand.Uint64())
		res, err := nw.Nodes[nw.Rand.IntN(len(nw.Nodes))].Store(ctx, value)
		if err != nil || len(res.StoredAt) != 10 {
			t.Fatalf("Store: %+v, %v", res, err)
		}
		found, err := nw.Nodes[nw.Rand.IntN(len(nw.Nodes))].LookupData(ctx, res.Key)
		if err != nil || !bytes.Equal(found.Value, value) {
			t.Fatalf("LookupData: %q, %v", found.Value, err)
		}
	}
}

func TestRandomAddrsDistinctAndRepeatable(t *testing.T) {
	a := RandomAddrs(newRand(5), 2000)
	b := RandomAddrs(newRand(5), 2000)
	if !slices.Equal(a, b) {
		t.Error("same seed gave different addresses")
	}
	seen := map[string]bool{}
	for _, x := range a {
		if seen[x.String()] || !x.Addr().Is4() {
			t.Fatalf("duplicate or non-IPv4 address %v", x)
		}
		seen[x.String()] = true
	}
}

func TestBuildSmallAndOracle(t *testing.T) {
	nw, err := Build(context.Background(), Options{N: 30, Seed: 2, Node: config(), JoinParallelism: 4})
	if err != nil {
		t.Fatal(err)
	}
	defer nw.Close()
	if len(nw.Nodes) != 30 || len(nw.Contacts()) != 30 {
		t.Fatalf("%d nodes", len(nw.Nodes))
	}
	me := nw.Nodes[3].Me()
	closest := nw.Closest(me.ID, me.ID, 100)
	if len(closest) != 29 || slices.Contains(closest, me) {
		t.Errorf("Closest excluded wrongly: %d contacts", len(closest))
	}
}

// Building fails cleanly if two nodes cannot be created, e.g. with a
// network that refuses joins.
func TestBuildJoinFailure(t *testing.T) {
	cfg := config()
	cfg.RPC = rpc.Config{Timeout: 10 * time.Millisecond}
	opts := Options{N: 5, Seed: 3, Node: cfg}
	opts.Sim.LossRate = 1 // nothing gets through: every join fails
	if _, err := Build(context.Background(), opts); err == nil {
		t.Error("build with 100% loss succeeded")
	}
}

func newRand(seed uint64) *rand.Rand { return rand.New(rand.NewPCG(seed, seed)) }
