package kademlia

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jonamarkin/lab-mobidist/internal/network"
	"github.com/jonamarkin/lab-mobidist/internal/rpc"
)

// RPC method names on the wire.
const (
	MethodPing     = "PING"
	MethodFindNode = "FIND_NODE"
)

// ErrNoContacts is returned by a lookup that has no live contact to ask.
var ErrNoContacts = errors.New("kademlia: no live contacts")

// Config holds the protocol parameters.
type Config struct {
	K      int        // replication factor / bucket size (spec default 10)
	Alpha  int        // lookup parallelism (spec default 3)
	RPC    rpc.Config // timeout/retry policy
	Logger *slog.Logger
}

// DefaultConfig returns the spec's defaults: k = 10, alpha = 3.
func DefaultConfig() Config {
	return Config{K: 10, Alpha: 3, RPC: rpc.DefaultConfig()}
}

// Kademlia is one node: its contact, routing table, and RPC endpoint.
type Kademlia struct {
	me  Contact
	cfg Config
	rt  RoutingTable
	rpc *rpc.Endpoint
	log *slog.Logger

	lookups atomic.Int64 // numbers lookups in the log

	rngMu sync.Mutex // guards rng
	rng   *rand.Rand // seeded from our ID, so runs are repeatable
}

// FIND_NODE messages. Contacts travel as addresses only: the receiver
// derives each ID as hash(address), so no node can claim a false ID.
type findNodeArgs struct {
	Target KademliaID `json:"target"`
}

type findNodeReply struct {
	Contacts []netip.AddrPort `json:"contacts"`
}

// NewKademlia starts a node listening on addr. Its ID is NewNodeID(addr).
func NewKademlia(nw network.Network, addr netip.AddrPort, cfg Config) (*Kademlia, error) {
	conn, err := nw.ListenPacket(addr)
	if err != nil {
		return nil, err
	}
	logger := cfg.Logger
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}
	me := NewContact(NewNodeID(addr), addr)
	k := &Kademlia{
		me:  me,
		cfg: cfg,
		rt:  NewFlatRoutingTable(me),
		log: logger.With("node", me.ID.Short()),
		rng: rand.New(rand.NewPCG(binary.BigEndian.Uint64(me.ID[:8]), binary.BigEndian.Uint64(me.ID[8:16]))),
	}
	k.rpc = rpc.NewEndpoint(conn, k.handle, cfg.RPC)
	return k, nil
}

// Me returns this node's own contact.
func (k *Kademlia) Me() Contact { return k.me }

// RoutingTable returns the node's routing table.
func (k *Kademlia) RoutingTable() RoutingTable { return k.rt }

// Close stops the node.
func (k *Kademlia) Close() error { return k.rpc.Close() }

// Ping sends PING to addr and returns the round-trip time (including any
// retransmissions).
func (k *Kademlia) Ping(ctx context.Context, addr netip.AddrPort) (time.Duration, error) {
	start := time.Now()
	if err := k.call(ctx, NewContact(NewNodeID(addr), addr), MethodPing, nil, nil); err != nil {
		return 0, err
	}
	return time.Since(start), nil
}

// Join enters the network through a node already in it (paper §2.3):
//  1. contact the bootstrap node;
//  2. look up our own ID, which finds and announces us to our neighbors;
//  3. refresh every bucket farther away than our closest neighbor, so we
//     also have contacts in distant parts of the ID space (without this,
//     lookups can get stuck among nodes that only know their own region).
func (k *Kademlia) Join(ctx context.Context, bootstrap netip.AddrPort) error {
	if _, err := k.Ping(ctx, bootstrap); err != nil {
		return fmt.Errorf("kademlia: join via %v: %w", bootstrap, err)
	}
	res, err := k.LookupContact(ctx, k.me.ID)
	if err != nil {
		return fmt.Errorf("kademlia: join: %w", err)
	}
	for i := BucketIndex(k.me.ID, res.Contacts[0].ID) + 1; i < IDBits; i++ {
		k.RefreshBucket(ctx, i)
	}
	return nil
}

// RefreshBucket looks up a random ID in bucket i (paper §2.3). Every node
// that answers is added to our routing table, and learns about us.
func (k *Kademlia) RefreshBucket(ctx context.Context, i int) {
	k.rngMu.Lock()
	target := RandomIDInBucket(k.me.ID, i, k.rng)
	k.rngMu.Unlock()
	k.log.Info("refresh", "bucket", i)
	k.LookupContact(ctx, target)
}

// call makes an RPC to c and maintains the routing table (paper §2.2): a
// response means c is alive; a timeout (after all retries) means it is
// presumed dead.
func (k *Kademlia) call(ctx context.Context, c Contact, method string, args, reply any) error {
	err := k.rpc.Call(ctx, c.Address, method, args, reply)
	switch {
	case err == nil:
		k.rt.AddContact(c)
	case errors.Is(err, rpc.ErrTimeout):
		k.rt.RemoveContact(c.ID)
		k.log.Info("dead_node", "contact", c.ID.Short(), "addr", c.Address.String())
	}
	return err
}

// findNode sends FIND_NODE(target) to c and returns the contacts it knows.
func (k *Kademlia) findNode(ctx context.Context, c Contact, target KademliaID) ([]Contact, error) {
	var reply findNodeReply
	if err := k.call(ctx, c, MethodFindNode, findNodeArgs{Target: target}, &reply); err != nil {
		return nil, err
	}
	n := min(len(reply.Contacts), k.cfg.K) // don't trust a peer to send at most k
	contacts := make([]Contact, n)
	for i, addr := range reply.Contacts[:n] {
		contacts[i] = NewContact(NewNodeID(addr), addr)
	}
	return contacts, nil
}

// handle serves incoming RPCs. Each request also tells us its sender is
// alive, so the sender goes into the routing table (paper §2.2).
func (k *Kademlia) handle(from netip.AddrPort, method string, body json.RawMessage) (any, error) {
	k.rt.AddContact(NewContact(NewNodeID(from), from))

	switch method {
	case MethodPing:
		return nil, nil
	case MethodFindNode:
		var args findNodeArgs
		if err := json.Unmarshal(body, &args); err != nil {
			return nil, fmt.Errorf("bad %s args: %w", method, err)
		}
		closest := k.rt.FindClosestContacts(args.Target, k.cfg.K)
		addrs := make([]netip.AddrPort, len(closest))
		for i, c := range closest {
			addrs[i] = c.Address
		}
		return findNodeReply{Contacts: addrs}, nil
	default:
		return nil, fmt.Errorf("unknown method %q", method)
	}
}
