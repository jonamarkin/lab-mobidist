package network

import (
	"bytes"
	"errors"
	"net"
	"net/netip"
)

// UDPNetwork is the real network: each endpoint is a UDP socket.
type UDPNetwork struct{}

var _ Network = UDPNetwork{}

// ListenPacket opens a UDP socket on addr. addr needs a concrete IP (not
// 0.0.0.0): a node's ID is derived from the address it reports, so it must
// be the address other nodes see. Port 0 picks a free port; LocalAddr
// reports which.
func (UDPNetwork) ListenPacket(addr netip.AddrPort) (PacketConn, error) {
	conn, err := net.ListenUDP("udp", net.UDPAddrFromAddrPort(addr))
	if err != nil {
		return nil, err
	}
	return &udpConn{conn: conn, local: unmap(conn.LocalAddr().(*net.UDPAddr).AddrPort())}, nil
}

type udpConn struct {
	conn  *net.UDPConn // safe for concurrent use
	local netip.AddrPort
}

func (c *udpConn) LocalAddr() netip.AddrPort { return c.local }

func (c *udpConn) Send(to netip.AddrPort, data []byte) error {
	if len(data) > MaxPacketSize {
		return ErrTooLarge
	}
	_, err := c.conn.WriteToUDPAddrPort(data, to)
	if errors.Is(err, net.ErrClosed) {
		return ErrClosed
	}
	return err
}

// Recv returns the next packet. Packets larger than MaxPacketSize are
// dropped, as in the simulator. Read errors other than "closed" (e.g. an
// ICMP error reported by the OS) skip the packet instead of failing, so
// one bad packet cannot stop the node's read loop.
func (c *udpConn) Recv() (Packet, error) {
	buf := make([]byte, MaxPacketSize+1) // one extra byte detects oversize packets
	for {
		n, from, err := c.conn.ReadFromUDPAddrPort(buf)
		if errors.Is(err, net.ErrClosed) {
			return Packet{}, ErrClosed
		}
		if err != nil || n > MaxPacketSize {
			continue
		}
		return Packet{From: unmap(from), Data: bytes.Clone(buf[:n])}, nil
	}
}

func (c *udpConn) Close() error { return c.conn.Close() }

// unmap turns an IPv4-mapped IPv6 address (::ffff:a.b.c.d) into plain IPv4.
func unmap(a netip.AddrPort) netip.AddrPort {
	return netip.AddrPortFrom(a.Addr().Unmap(), a.Port())
}
