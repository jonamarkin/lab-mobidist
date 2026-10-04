package network

import (
	"errors"
	"net"
	"net/netip"
	"testing"
	"time"
)

var loopback = netip.MustParseAddrPort("127.0.0.1:0") // port 0: any free port

func listenUDP(t *testing.T) PacketConn {
	t.Helper()
	c, err := UDPNetwork{}.ListenPacket(loopback)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	return c
}

func TestUDPSendRecv(t *testing.T) {
	a, b := listenUDP(t), listenUDP(t)
	if b.LocalAddr().Port() == 0 {
		t.Fatal("LocalAddr does not report the chosen port")
	}
	if err := a.Send(b.LocalAddr(), []byte("hello")); err != nil {
		t.Fatal(err)
	}
	p, ok := recvWithin(b, 2*time.Second)
	if !ok {
		t.Fatal("no packet received")
	}
	if p.From != a.LocalAddr() || string(p.Data) != "hello" {
		t.Errorf("got %v %q, want %v %q", p.From, p.Data, a.LocalAddr(), "hello")
	}
}

func TestUDPTooLarge(t *testing.T) {
	a, b := listenUDP(t), listenUDP(t)
	if err := a.Send(b.LocalAddr(), make([]byte, MaxPacketSize+1)); !errors.Is(err, ErrTooLarge) {
		t.Errorf("Send: got %v, want ErrTooLarge", err)
	}

	// An oversize packet from a raw socket is dropped; the next one arrives.
	raw, err := net.ListenUDP("udp", net.UDPAddrFromAddrPort(loopback))
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	to := net.UDPAddrFromAddrPort(b.LocalAddr())
	raw.WriteToUDP(make([]byte, MaxPacketSize+1), to)
	raw.WriteToUDP([]byte("small"), to)
	if p, ok := recvWithin(b, 2*time.Second); !ok || string(p.Data) != "small" {
		t.Errorf("got %q, %v; want the small packet", p.Data, ok)
	}
}

func TestUDPClose(t *testing.T) {
	a, b := listenUDP(t), listenUDP(t)
	errCh := make(chan error, 1)
	go func() { _, err := b.Recv(); errCh <- err }()
	time.Sleep(10 * time.Millisecond)
	b.Close()
	select {
	case err := <-errCh:
		if !errors.Is(err, ErrClosed) {
			t.Errorf("Recv after Close: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Recv not unblocked by Close")
	}
	if err := b.Send(a.LocalAddr(), []byte("x")); !errors.Is(err, ErrClosed) {
		t.Errorf("Send after Close: %v", err)
	}
}

func TestUDPAddrInUse(t *testing.T) {
	a := listenUDP(t)
	if _, err := (UDPNetwork{}).ListenPacket(a.LocalAddr()); err == nil {
		t.Error("second listener on the same address succeeded")
	}
}

func TestUnmap(t *testing.T) {
	mapped := netip.MustParseAddrPort("[::ffff:10.0.0.1]:4000")
	if got := unmap(mapped); got != netip.MustParseAddrPort("10.0.0.1:4000") {
		t.Errorf("unmap = %v", got)
	}
}
