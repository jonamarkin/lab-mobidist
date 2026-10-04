package network

import (
	"errors"
	"math"
	"net/netip"
	"sync"
	"testing"
	"time"
)

func addr(port uint16) netip.AddrPort {
	return netip.AddrPortFrom(netip.MustParseAddr("10.0.0.1"), port)
}

func listen(t *testing.T, n Network, port uint16) PacketConn {
	t.Helper()
	c, err := n.ListenPacket(addr(port))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	return c
}

// recvWithin waits up to d for a packet. Recv itself blocks forever, so it
// runs in a goroutine that the test's Cleanup (Close) eventually unblocks.
func recvWithin(c PacketConn, d time.Duration) (Packet, bool) {
	ch := make(chan Packet, 1)
	go func() {
		if p, err := c.Recv(); err == nil {
			ch <- p
		}
	}()
	select {
	case p := <-ch:
		return p, true
	case <-time.After(d):
		return Packet{}, false
	}
}

func TestSimSendRecv(t *testing.T) {
	n := NewSimNetwork(SimConfig{})
	a, b := listen(t, n, 1), listen(t, n, 2)

	if err := a.Send(b.LocalAddr(), []byte("hello")); err != nil {
		t.Fatal(err)
	}
	p, ok := recvWithin(b, time.Second)
	if !ok {
		t.Fatal("no packet received")
	}
	if p.From != a.LocalAddr() || string(p.Data) != "hello" {
		t.Errorf("got %v %q", p.From, p.Data)
	}
}

// Like a real socket, Send copies the data: the caller may reuse its buffer.
func TestSimSendCopiesData(t *testing.T) {
	n := NewSimNetwork(SimConfig{})
	a, b := listen(t, n, 1), listen(t, n, 2)

	buf := []byte("abc")
	a.Send(b.LocalAddr(), buf)
	buf[0] = 'X'

	p, _ := recvWithin(b, time.Second)
	if string(p.Data) != "abc" {
		t.Errorf("got %q, want %q", p.Data, "abc")
	}
}

// Like UDP: sending to nobody is not an error, the packet just vanishes.
func TestSimUnknownDestinationIsSilent(t *testing.T) {
	n := NewSimNetwork(SimConfig{})
	a := listen(t, n, 1)

	if err := a.Send(addr(99), []byte("x")); err != nil {
		t.Errorf("Send to unknown address returned %v, want nil", err)
	}
	if s := n.Stats(); s.Undeliverable != 1 || s.Delivered != 0 {
		t.Errorf("stats = %+v", s)
	}
}

func TestSimLossRate(t *testing.T) {
	const total = 10000
	for _, rate := range []float64{0, 0.3, 1} {
		n := NewSimNetwork(SimConfig{LossRate: rate, QueueSize: total, Seed: 42})
		a, b := listen(t, n, 1), listen(t, n, 2)
		for range total {
			a.Send(b.LocalAddr(), []byte("x"))
		}
		s := n.Stats()
		if s.Sent != total || s.Lost+s.Delivered != total {
			t.Fatalf("rate %v: stats = %+v", rate, s)
		}
		// Within 3 standard deviations of the expected loss count.
		want := rate * total
		tol := 3*math.Sqrt(total*rate*(1-rate)) + 1
		if math.Abs(float64(s.Lost)-want) > tol {
			t.Errorf("rate %v: lost %d, want %.0f ± %.0f", rate, s.Lost, want, tol)
		}
	}
}

func TestSimSetLossRate(t *testing.T) {
	n := NewSimNetwork(SimConfig{})
	a, b := listen(t, n, 1), listen(t, n, 2)
	a.Send(b.LocalAddr(), []byte("x"))
	n.SetLossRate(1)
	a.Send(b.LocalAddr(), []byte("x"))
	if s := n.Stats(); s.Delivered != 1 || s.Lost != 1 {
		t.Errorf("stats = %+v", s)
	}
}

func TestSimLatency(t *testing.T) {
	const minLat = 20 * time.Millisecond
	n := NewSimNetwork(SimConfig{MinLatency: minLat, MaxLatency: 30 * time.Millisecond})
	a, b := listen(t, n, 1), listen(t, n, 2)

	start := time.Now()
	a.Send(b.LocalAddr(), []byte("x"))
	if _, ok := recvWithin(b, time.Second); !ok {
		t.Fatal("no packet received")
	}
	if elapsed := time.Since(start); elapsed < minLat {
		t.Errorf("packet arrived after %v, want >= %v", elapsed, minLat)
	}
}

// A full queue drops packets instead of blocking the sender.
func TestSimFullQueueDrops(t *testing.T) {
	n := NewSimNetwork(SimConfig{QueueSize: 2})
	a, b := listen(t, n, 1), listen(t, n, 2)
	for range 5 {
		a.Send(b.LocalAddr(), []byte("x"))
	}
	if s := n.Stats(); s.Delivered != 2 || s.Undeliverable != 3 {
		t.Errorf("stats = %+v", s)
	}
}

func TestSimTooLarge(t *testing.T) {
	n := NewSimNetwork(SimConfig{})
	a, b := listen(t, n, 1), listen(t, n, 2)
	if err := a.Send(b.LocalAddr(), make([]byte, MaxPacketSize+1)); !errors.Is(err, ErrTooLarge) {
		t.Errorf("got %v, want ErrTooLarge", err)
	}
	if err := a.Send(b.LocalAddr(), make([]byte, MaxPacketSize)); err != nil {
		t.Errorf("max-size packet: %v", err)
	}
}

func TestSimAddrInUse(t *testing.T) {
	n := NewSimNetwork(SimConfig{})
	listen(t, n, 1)
	if _, err := n.ListenPacket(addr(1)); !errors.Is(err, ErrAddrInUse) {
		t.Errorf("got %v, want ErrAddrInUse", err)
	}
}

func TestSimClose(t *testing.T) {
	n := NewSimNetwork(SimConfig{})
	a, b := listen(t, n, 1), listen(t, n, 2)

	// A blocked Recv is woken up by Close.
	errCh := make(chan error, 1)
	go func() { _, err := b.Recv(); errCh <- err }()
	time.Sleep(10 * time.Millisecond)
	b.Close()
	select {
	case err := <-errCh:
		if !errors.Is(err, ErrClosed) {
			t.Errorf("Recv after Close: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Recv not unblocked by Close")
	}

	if _, err := b.Recv(); !errors.Is(err, ErrClosed) {
		t.Errorf("second Recv: %v", err)
	}
	if err := b.Send(a.LocalAddr(), []byte("x")); !errors.Is(err, ErrClosed) {
		t.Errorf("Send on closed: %v", err)
	}
	if err := b.Close(); err != nil {
		t.Errorf("double Close: %v", err)
	}

	// Packets to the departed node are dropped silently.
	a.Send(addr(2), []byte("x"))
	if s := n.Stats(); s.Undeliverable != 1 {
		t.Errorf("stats = %+v", s)
	}

	// The address can be reused (node rejoins).
	if _, err := n.ListenPacket(addr(2)); err != nil {
		t.Errorf("rejoin: %v", err)
	}
}

// A packet in flight when the receiver leaves is dropped, not delivered to
// a closed endpoint and not a panic.
func TestSimCloseWhileInFlight(t *testing.T) {
	n := NewSimNetwork(SimConfig{MinLatency: 20 * time.Millisecond, MaxLatency: 20 * time.Millisecond})
	a := listen(t, n, 1)
	b, _ := n.ListenPacket(addr(2))

	a.Send(b.LocalAddr(), []byte("x"))
	b.Close()
	time.Sleep(50 * time.Millisecond)

	if s := n.Stats(); s.Undeliverable != 1 || s.Delivered != 0 {
		t.Errorf("stats = %+v", s)
	}
}

// Run with -race: many senders, one receiver, concurrent Close.
func TestSimConcurrent(t *testing.T) {
	const senders, perSender = 8, 100
	n := NewSimNetwork(SimConfig{MaxLatency: time.Millisecond, QueueSize: senders * perSender})
	b := listen(t, n, 1000)

	var wg sync.WaitGroup
	for s := range senders {
		c := listen(t, n, uint16(s+1))
		wg.Go(func() {
			for range perSender {
				c.Send(b.LocalAddr(), []byte("x"))
			}
		})
	}
	received := 0
	for received < senders*perSender {
		if _, ok := recvWithin(b, time.Second); !ok {
			break
		}
		received++
	}
	wg.Wait()
	if received != senders*perSender {
		t.Errorf("received %d of %d", received, senders*perSender)
	}
}
