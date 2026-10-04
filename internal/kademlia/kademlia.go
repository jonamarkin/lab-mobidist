package kademlia

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jonamarkin/lab-mobidist/internal/network"
	"github.com/jonamarkin/lab-mobidist/internal/rpc"
)

// RPC method names on the wire.
const (
	MethodPing      = "PING"
	MethodFindNode  = "FIND_NODE"
	MethodFindValue = "FIND_VALUE"
)

// ErrNoContacts is returned by a lookup that has no live contact to ask.
var ErrNoContacts = errors.New("kademlia: no live contacts")

// Config holds the protocol parameters.
type Config struct {
	K     int        // replication factor / bucket size (spec default 10)
	Alpha int        // lookup parallelism (spec default 3)
	RPC   rpc.Config // timeout/retry policy

	// RefreshInterval: a bucket with no lookup into its range for this
	// long is refreshed (paper: one hour). 0 disables periodic refresh.
	RefreshInterval time.Duration

	// FlatRoutingTable selects the simplified table that keeps every
	// contact, instead of k-buckets (for comparisons only).
	FlatRoutingTable bool

	// TransferTimeout bounds one data-plane transfer (STORE or FETCH).
	TransferTimeout time.Duration

	// ReplicateInterval: each node republishes every value it holds that
	// nobody has stored or republished within this interval (paper: one
	// hour). 0 disables replication.
	ReplicateInterval time.Duration

	Logger *slog.Logger
}

// DefaultConfig returns the spec's and paper's defaults: k = 10,
// alpha = 3, bucket refresh and replication every hour.
func DefaultConfig() Config {
	return Config{K: 10, Alpha: 3, RPC: rpc.DefaultConfig(), RefreshInterval: time.Hour,
		TransferTimeout: 30 * time.Second, ReplicateInterval: time.Hour}
}

// Kademlia is one node: its contact, routing table, data store, RPC
// endpoint (control plane), and stream listener (data plane).
type Kademlia struct {
	me      Contact
	cfg     Config
	net     network.Network
	rt      RoutingTable
	store   *DataStore
	rpc     *rpc.Endpoint
	streams net.Listener
	log     *slog.Logger

	lookups atomic.Int64 // numbers lookups in the log

	mu         sync.Mutex        // guards rng and lastLookup
	rng        *rand.Rand        // seeded from our ID, so runs are repeatable
	lastLookup [IDBits]time.Time // last lookup into each bucket's range

	// ctx is cancelled by Close, stopping background work: the refresh
	// and replication loops and pending eviction pings.
	ctx    context.Context
	cancel context.CancelFunc
	bg     sync.WaitGroup
}

// FIND_NODE messages. Contacts travel as addresses only: the receiver
// derives each ID as hash(address), so no node can claim a false ID.
type findNodeArgs struct {
	Target KademliaID `json:"target"`
}

type findNodeReply struct {
	Contacts []netip.AddrPort `json:"contacts"`
}

// FIND_VALUE reply: either Found (fetch the value over the data plane) or
// the closer contacts, as for FIND_NODE. The request is a findNodeArgs.
type findValueReply struct {
	Found    bool             `json:"found,omitempty"`
	Contacts []netip.AddrPort `json:"contacts,omitempty"`
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
	// Use the address the endpoint actually got (e.g. the port the OS
	// picked for port 0): the ID must match what other nodes see.
	addr = conn.LocalAddr()
	// The data plane listens on the same IP and port, over streams (TCP
	// and UDP port numbers are separate), so no extra address is needed.
	streams, err := nw.ListenStream(addr)
	if err != nil {
		conn.Close()
		return nil, err
	}
	if cfg.TransferTimeout <= 0 {
		cfg.TransferTimeout = DefaultConfig().TransferTimeout
	}
	me := NewContact(NewNodeID(addr), addr)
	k := &Kademlia{
		me:      me,
		cfg:     cfg,
		net:     nw,
		store:   NewDataStore(),
		streams: streams,
		log:     logger.With("node", me.ID.Short()),
		rng:     rand.New(rand.NewPCG(binary.BigEndian.Uint64(me.ID[:8]), binary.BigEndian.Uint64(me.ID[8:16]))),
	}
	if cfg.FlatRoutingTable {
		k.rt = NewFlatRoutingTable(me)
	} else {
		k.rt = NewBucketRoutingTable(me, cfg.K, k.pingOldest)
	}
	k.ctx, k.cancel = context.WithCancel(context.Background())
	k.rpc = rpc.NewEndpoint(conn, k.handle, cfg.RPC)
	k.bg.Go(k.serveStreams)
	if cfg.RefreshInterval > 0 {
		k.bg.Go(k.refreshLoop)
	}
	if cfg.ReplicateInterval > 0 {
		k.bg.Go(k.replicateLoop)
	}
	return k, nil
}

// Config returns the node's parameters.
func (k *Kademlia) Config() Config { return k.cfg }

// Me returns this node's own contact.
func (k *Kademlia) Me() Contact { return k.me }

// RoutingTable returns the node's routing table.
func (k *Kademlia) RoutingTable() RoutingTable { return k.rt }

// DataStore returns the node's local data store.
func (k *Kademlia) DataStore() *DataStore { return k.store }

// Close stops background work and both planes.
func (k *Kademlia) Close() error {
	k.cancel()
	k.streams.Close()
	k.bg.Wait()
	return k.rpc.Close()
}

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
		k.refreshBucket(ctx, i, "join")
	}
	return nil
}

// refreshBucket looks up a random ID in bucket i (paper §2.3). Every node
// that answers is added to our routing table, and learns about us.
func (k *Kademlia) refreshBucket(ctx context.Context, i int, reason string) {
	k.mu.Lock()
	target := RandomIDInBucket(k.me.ID, i, k.rng)
	k.mu.Unlock()
	k.log.Info("refresh", "bucket", i, "reason", reason)
	k.LookupContact(ctx, target)
}

// touchBucket records a lookup into the range of the bucket that target
// falls in, so periodic refresh can skip buckets that see traffic anyway.
func (k *Kademlia) touchBucket(target KademliaID) {
	if i := BucketIndex(k.me.ID, target); i >= 0 {
		k.mu.Lock()
		k.lastLookup[i] = time.Now()
		k.mu.Unlock()
	}
}

// refreshLoop periodically refreshes stale buckets until Close.
func (k *Kademlia) refreshLoop() {
	ticker := time.NewTicker(k.cfg.RefreshInterval)
	defer ticker.Stop()
	for {
		select {
		case <-k.ctx.Done():
			return
		case <-ticker.C:
			k.refreshStale()
		}
	}
}

// refreshStale refreshes every bucket from our closest neighbor's bucket
// up to the farthest one that has had no lookup within RefreshInterval.
// (Lower buckets cover ID ranges too small to contain any node.)
func (k *Kademlia) refreshStale() {
	closest := k.rt.FindClosestContacts(k.me.ID, 1)
	if len(closest) == 0 {
		return
	}
	for i := BucketIndex(k.me.ID, closest[0].ID); i < IDBits && k.ctx.Err() == nil; i++ {
		k.mu.Lock()
		stale := time.Since(k.lastLookup[i]) >= k.cfg.RefreshInterval
		k.mu.Unlock()
		if stale {
			k.refreshBucket(k.ctx, i, "periodic")
		}
	}
}

// pingOldest is the routing table's Pinger: is the least recently seen
// contact of a full bucket still alive? Only a timeout counts as dead
// (not, e.g., our own endpoint closing).
func (k *Kademlia) pingOldest(c Contact) bool {
	err := k.rpc.Call(k.ctx, c.Address, MethodPing, nil, nil)
	alive := !errors.Is(err, rpc.ErrTimeout)
	if alive {
		k.log.Info("evict_check", "contact", c.ID.Short(), "result", "kept")
	} else {
		k.log.Info("evict_check", "contact", c.ID.Short(), "result", "evicted")
	}
	return alive
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
	return k.toContacts(reply.Contacts), nil
}

// findValue sends FIND_VALUE(key) to c. If c has the value, it is fetched
// over the data plane and checked against the key; a node that fails to
// deliver a valid copy is treated as a node without the value, so the
// lookup continues with others.
func (k *Kademlia) findValue(ctx context.Context, c Contact, key KademliaID) ([]Contact, []byte, error) {
	var reply findValueReply
	if err := k.call(ctx, c, MethodFindValue, findNodeArgs{Target: key}, &reply); err != nil {
		return nil, nil, err
	}
	if !reply.Found {
		return k.toContacts(reply.Contacts), nil, nil
	}
	value, err := k.fetchFrom(ctx, c, key)
	if err != nil {
		k.log.Warn("fetch_failed", "key", key.Short(), "from", c.ID.Short(), "err", err.Error())
		return nil, nil, nil
	}
	return nil, value, nil
}

// toContacts turns addresses from a reply into contacts (ID = hash of the
// address), keeping at most k: don't trust a peer to send at most k.
func (k *Kademlia) toContacts(addrs []netip.AddrPort) []Contact {
	n := min(len(addrs), k.cfg.K)
	contacts := make([]Contact, n)
	for i, addr := range addrs[:n] {
		contacts[i] = NewContact(NewNodeID(addr), addr)
	}
	return contacts
}

// closestAddrs returns the addresses of our k contacts closest to target.
func (k *Kademlia) closestAddrs(target KademliaID) []netip.AddrPort {
	closest := k.rt.FindClosestContacts(target, k.cfg.K)
	addrs := make([]netip.AddrPort, len(closest))
	for i, c := range closest {
		addrs[i] = c.Address
	}
	return addrs
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
		return findNodeReply{Contacts: k.closestAddrs(args.Target)}, nil
	case MethodFindValue:
		var args findNodeArgs
		if err := json.Unmarshal(body, &args); err != nil {
			return nil, fmt.Errorf("bad %s args: %w", method, err)
		}
		if _, ok := k.store.Get(args.Target); ok {
			return findValueReply{Found: true}, nil
		}
		return findValueReply{Contacts: k.closestAddrs(args.Target)}, nil
	default:
		return nil, fmt.Errorf("unknown method %q", method)
	}
}
