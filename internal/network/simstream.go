package network

import (
	"context"
	"net"
	"net/netip"
	"sync"
)

// The simulated data plane: each stream is a net.Pipe, an in-memory,
// full-duplex connection from the standard library. As the spec allows,
// it is reliable (no loss or latency); a stream fails only if the other
// node is gone.

// ListenStream accepts simulated stream connections on addr.
func (n *SimNetwork) ListenStream(addr netip.AddrPort) (net.Listener, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	if _, ok := n.streams[addr]; ok {
		return nil, ErrAddrInUse
	}
	l := &simListener{net: n, addr: addr, conns: make(chan net.Conn), done: make(chan struct{})}
	n.streams[addr] = l
	return l, nil
}

// DialStream connects to the listener at addr. Like TCP (and unlike
// packets), it reports an error if nobody is listening.
func (n *SimNetwork) DialStream(ctx context.Context, addr netip.AddrPort) (net.Conn, error) {
	n.mu.Lock()
	l := n.streams[addr]
	n.mu.Unlock()
	if l == nil {
		return nil, ErrRefused
	}
	client, server := net.Pipe()
	select {
	case l.conns <- server: // handed to the listener's Accept
		return client, nil
	case <-l.done:
	case <-ctx.Done():
	}
	client.Close()
	server.Close()
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	return nil, ErrRefused
}

type simListener struct {
	net       *SimNetwork
	addr      netip.AddrPort
	conns     chan net.Conn // unbuffered: a dial waits until Accept takes it
	done      chan struct{}
	closeOnce sync.Once
}

func (l *simListener) Accept() (net.Conn, error) {
	select {
	case c := <-l.conns:
		return c, nil
	case <-l.done:
		return nil, net.ErrClosed
	}
}

func (l *simListener) Close() error {
	l.closeOnce.Do(func() {
		close(l.done)
		l.net.mu.Lock()
		delete(l.net.streams, l.addr)
		l.net.mu.Unlock()
	})
	return nil
}

func (l *simListener) Addr() net.Addr { return net.TCPAddrFromAddrPort(l.addr) }
