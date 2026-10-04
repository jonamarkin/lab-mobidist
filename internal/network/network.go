// Package network hides how nodes communicate. The Kademlia code only sees
// the Network interface, so the same code runs on the in-process simulated
// network (tests, 1000+ node experiments) and on real sockets (containers).
//
// There are two planes: the control plane carries small RPC messages as
// unreliable packets (UDP), and the data plane carries values over
// reliable streams (TCP), which have no size limit.
package network

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
)

// MaxPacketSize is the largest payload a single packet may carry. It is
// far below the UDP limit (65507 bytes) on purpose: RPC messages are small,
// and large values go over a separate data plane instead.
const MaxPacketSize = 8192

var (
	ErrClosed    = errors.New("network: connection closed")
	ErrAddrInUse = errors.New("network: address already in use")
	ErrRefused   = errors.New("network: connection refused")
	ErrTooLarge  = fmt.Errorf("network: packet larger than %d bytes", MaxPacketSize)
)

// Packet is one received datagram.
type Packet struct {
	From netip.AddrPort
	Data []byte
}

// PacketConn is a node's UDP-like endpoint. Delivery is unreliable: packets
// may be lost, delayed, or reordered, and the sender is never told.
// Implementations must be safe for concurrent use.
type PacketConn interface {
	// LocalAddr returns the address this endpoint listens on.
	LocalAddr() netip.AddrPort

	// Send sends data to the given address. A nil error does not mean the
	// packet arrived; errors are only reported for local problems
	// (connection closed, packet too large).
	Send(to netip.AddrPort, data []byte) error

	// Recv blocks until a packet arrives or the endpoint is closed, in which
	// case it returns ErrClosed.
	Recv() (Packet, error)

	// Close stops the endpoint and unblocks any pending Recv.
	Close() error
}

// Network creates endpoints for both planes.
type Network interface {
	// ListenPacket opens a control-plane (packet) endpoint.
	ListenPacket(addr netip.AddrPort) (PacketConn, error)

	// ListenStream accepts data-plane (stream) connections on addr.
	ListenStream(addr netip.AddrPort) (net.Listener, error)

	// DialStream opens a data-plane connection to addr. Unlike packets,
	// a failed connection attempt is reported (as with TCP).
	DialStream(ctx context.Context, addr netip.AddrPort) (net.Conn, error)
}
