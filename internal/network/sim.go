package network

import (
	"bytes"
	"math/rand/v2"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"
)

// SimConfig controls the behavior of a SimNetwork.
type SimConfig struct {
	// LossRate is the probability (0..1) that a packet is silently dropped.
	LossRate float64

	// Each packet is delayed by a uniformly random duration in
	// [MinLatency, MaxLatency]. Independent delays also reorder packets.
	MinLatency time.Duration
	MaxLatency time.Duration

	// QueueSize is the number of undelivered packets an endpoint buffers;
	// packets arriving at a full queue are dropped. Default 1024.
	QueueSize int

	// Seed makes loss and latency draws repeatable. With concurrent senders
	// the order of draws (and therefore exactly which packets are lost)
	// still varies between runs; the statistics do not.
	Seed uint64
}

// SimStats counts what happened to packets. Lost counts drops due to
// LossRate; Undeliverable counts packets with no listener or a full queue.
type SimStats struct {
	Sent, Lost, Undeliverable, Delivered int64
}

// SimNetwork is an in-process network: every endpoint is a Go channel, and
// packets are routed between them by address.
type SimNetwork struct {
	cfg SimConfig

	mu    sync.Mutex // guards conns and rng
	conns map[netip.AddrPort]*simConn
	rng   *rand.Rand

	sent, lost, undeliverable, delivered atomic.Int64
}

var _ Network = (*SimNetwork)(nil)

// NewSimNetwork returns an empty simulated network.
func NewSimNetwork(cfg SimConfig) *SimNetwork {
	if cfg.QueueSize <= 0 {
		cfg.QueueSize = 1024
	}
	return &SimNetwork{
		cfg:   cfg,
		conns: make(map[netip.AddrPort]*simConn),
		rng:   rand.New(rand.NewPCG(cfg.Seed, 0)),
	}
}

// ListenPacket opens an endpoint at addr. The address can be reused once
// the previous endpoint is closed (a node leaving and rejoining).
func (n *SimNetwork) ListenPacket(addr netip.AddrPort) (PacketConn, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	if _, ok := n.conns[addr]; ok {
		return nil, ErrAddrInUse
	}
	c := &simConn{
		net:   n,
		addr:  addr,
		inbox: make(chan Packet, n.cfg.QueueSize),
		done:  make(chan struct{}),
	}
	n.conns[addr] = c
	return c, nil
}

// Stats returns a snapshot of the packet counters.
func (n *SimNetwork) Stats() SimStats {
	return SimStats{
		Sent:          n.sent.Load(),
		Lost:          n.lost.Load(),
		Undeliverable: n.undeliverable.Load(),
		Delivered:     n.delivered.Load(),
	}
}

func (n *SimNetwork) send(from, to netip.AddrPort, data []byte) error {
	if len(data) > MaxPacketSize {
		return ErrTooLarge
	}
	n.sent.Add(1)
	// Copy: like a real socket, the caller may reuse its buffer after Send.
	pkt := Packet{From: from, Data: bytes.Clone(data)}

	n.mu.Lock()
	lost := n.rng.Float64() < n.cfg.LossRate
	delay := n.cfg.MinLatency
	if span := n.cfg.MaxLatency - n.cfg.MinLatency; span > 0 {
		delay += time.Duration(n.rng.Int64N(int64(span) + 1))
	}
	n.mu.Unlock()

	if lost {
		n.lost.Add(1)
		return nil
	}
	if delay == 0 {
		n.deliver(to, pkt)
	} else {
		time.AfterFunc(delay, func() { n.deliver(to, pkt) })
	}
	return nil
}

// deliver looks up the destination at arrival time, so packets to a node
// that left while they were in flight are dropped.
func (n *SimNetwork) deliver(to netip.AddrPort, pkt Packet) {
	n.mu.Lock()
	c := n.conns[to]
	n.mu.Unlock()

	if c == nil || !c.enqueue(pkt) {
		n.undeliverable.Add(1)
		return
	}
	n.delivered.Add(1)
}

type simConn struct {
	net  *SimNetwork
	addr netip.AddrPort

	// inbox is never closed, so a late delivery can never panic with
	// "send on closed channel"; done signals closure instead.
	inbox     chan Packet
	done      chan struct{}
	closeOnce sync.Once
}

func (c *simConn) LocalAddr() netip.AddrPort { return c.addr }

func (c *simConn) Send(to netip.AddrPort, data []byte) error {
	if c.isClosed() {
		return ErrClosed
	}
	return c.net.send(c.addr, to, data)
}

func (c *simConn) Recv() (Packet, error) {
	if c.isClosed() {
		return Packet{}, ErrClosed
	}
	select {
	case p := <-c.inbox:
		return p, nil
	case <-c.done:
		return Packet{}, ErrClosed
	}
}

func (c *simConn) Close() error {
	c.closeOnce.Do(func() {
		close(c.done)
		c.net.mu.Lock()
		delete(c.net.conns, c.addr)
		c.net.mu.Unlock()
	})
	return nil
}

func (c *simConn) isClosed() bool {
	select {
	case <-c.done:
		return true
	default:
		return false
	}
}

// enqueue adds p to the inbox without blocking. It reports false if the
// endpoint is closed or its queue is full.
func (c *simConn) enqueue(p Packet) bool {
	if c.isClosed() {
		return false
	}
	select {
	case c.inbox <- p:
		return true
	default:
		return false
	}
}
