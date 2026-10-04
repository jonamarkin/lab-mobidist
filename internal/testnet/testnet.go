// Package testnet builds networks of many Kademlia nodes on the simulated
// network, for large tests and for experiments.
package testnet

import (
	"context"
	"fmt"
	"math/rand/v2"
	"net/netip"
	"sync"

	"github.com/jonamarkin/lab-mobidist/internal/kademlia"
	"github.com/jonamarkin/lab-mobidist/internal/network"
)

// Options describes a network to build.
type Options struct {
	N    int               // number of nodes
	Seed uint64            // seeds addresses (so IDs) and bootstrap choices
	Node kademlia.Config   // configuration of every node
	Sim  network.SimConfig // the simulated network (its Seed is set from Seed)

	// JoinParallelism is how many nodes join at the same time (default 16).
	JoinParallelism int
}

// Network is a built network.
type Network struct {
	Sim   *network.SimNetwork
	Nodes []*kademlia.Kademlia
	Rand  *rand.Rand // seeded from Options.Seed; for choosing targets, keys, ...
}

// RandomAddrs returns n distinct random addresses 10.a.b.c:port, i.e. a
// random topology: the addresses determine the node IDs.
func RandomAddrs(r *rand.Rand, n int) []netip.AddrPort {
	seen := make(map[netip.AddrPort]bool, n)
	addrs := make([]netip.AddrPort, 0, n)
	for len(addrs) < n {
		ip := netip.AddrFrom4([4]byte{10, byte(r.UintN(256)), byte(r.UintN(256)), byte(1 + r.UintN(254))})
		a := netip.AddrPortFrom(ip, uint16(1024+r.UintN(64000)))
		if !seen[a] {
			seen[a] = true
			addrs = append(addrs, a)
		}
	}
	return addrs
}

// Build starts opts.N nodes at random addresses. Node 0 starts the
// network; every other node joins through a random node that has already
// finished joining. Up to JoinParallelism nodes join at once: node i only
// starts once nodes 0..i-P have finished, so it can join through any of
// them.
//
// Addresses, IDs, and bootstrap choices depend only on the seed. The exact
// routing tables also depend on the timing of the concurrent joins.
func Build(ctx context.Context, opts Options) (*Network, error) {
	p := opts.JoinParallelism
	if p <= 0 {
		p = 16
	}
	r := rand.New(rand.NewPCG(opts.Seed, 0x7e57))
	opts.Sim.Seed = opts.Seed
	nw := &Network{Sim: network.NewSimNetwork(opts.Sim), Rand: r}

	addrs := RandomAddrs(r, opts.N)
	for _, a := range addrs {
		k, err := kademlia.NewKademlia(nw.Sim, a, opts.Node)
		if err != nil {
			nw.Close()
			return nil, err
		}
		nw.Nodes = append(nw.Nodes, k)
	}

	done := make([]chan struct{}, opts.N)
	for i := range done {
		done[i] = make(chan struct{})
	}
	close(done[0]) // node 0 starts the network

	var mu sync.Mutex
	var firstErr error
	var wg sync.WaitGroup
	for i := 1; i < opts.N; i++ {
		if i-p >= 0 {
			<-done[i-p] // nodes 0..i-p have all finished joining
		}
		bootstrap := nw.Nodes[r.IntN(max(1, i-p+1))].Me().Address
		wg.Go(func() {
			defer close(done[i])
			if err := nw.Nodes[i].Join(ctx, bootstrap); err != nil {
				mu.Lock()
				if firstErr == nil {
					firstErr = fmt.Errorf("node %d: %w", i, err)
				}
				mu.Unlock()
			}
		})
	}
	wg.Wait()
	if firstErr != nil {
		nw.Close()
		return nil, firstErr
	}
	return nw, nil
}

// Close stops every node.
func (n *Network) Close() {
	var wg sync.WaitGroup
	for _, k := range n.Nodes {
		wg.Go(func() { k.Close() })
	}
	wg.Wait()
}

// Contacts returns every node's contact.
func (n *Network) Contacts() []kademlia.Contact {
	out := make([]kademlia.Contact, len(n.Nodes))
	for i, k := range n.Nodes {
		out[i] = k.Me()
	}
	return out
}

// Closest is the oracle: the true count closest nodes to target among all
// nodes, excluding the node with ID exclude (e.g. the one looking).
func (n *Network) Closest(target, exclude kademlia.KademliaID, count int) []kademlia.Contact {
	var all []kademlia.Contact
	for _, c := range n.Contacts() {
		if c.ID != exclude {
			all = append(all, c)
		}
	}
	kademlia.SortContactsByDistance(all, target)
	return all[:min(count, len(all))]
}
