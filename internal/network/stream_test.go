package network

import (
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"
)

// echoServer accepts connections on l and echoes one message per conn.
func echoServer(l net.Listener) {
	for {
		c, err := l.Accept()
		if err != nil {
			return
		}
		go func() {
			defer c.Close()
			io.Copy(c, c)
		}()
	}
}

// roundTrip sends msg over a new stream to addr and reads it back.
func roundTrip(t *testing.T, n Network, addr netip.AddrPort, msg string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	c, err := n.DialStream(ctx, addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	// Write in the background while reading: with a large message, writing
	// everything before reading would deadlock (the echo server blocks
	// writing back until we read, so it stops reading what we write).
	go c.Write([]byte(msg))
	buf := make([]byte, len(msg))
	if _, err := io.ReadFull(c, buf); err != nil || string(buf) != msg {
		t.Fatalf("read %q, %v", buf, err)
	}
}

func testStreams(t *testing.T, n Network, at netip.AddrPort) {
	l, err := n.ListenStream(at)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	go echoServer(l)
	addr := l.Addr().(*net.TCPAddr).AddrPort()

	roundTrip(t, n, addr, "hello")
	big := string(make([]byte, 1<<20)) // 1 MiB: far beyond one packet
	roundTrip(t, n, addr, big)

	l.Close()
	if _, err := n.DialStream(context.Background(), addr); err == nil {
		t.Error("dial after listener closed succeeded")
	}
}

func TestSimStreams(t *testing.T) {
	testStreams(t, NewSimNetwork(SimConfig{}), addr(1))
}

func TestTCPStreams(t *testing.T) {
	testStreams(t, UDPNetwork{}, loopback)
}

func TestSimStreamRefused(t *testing.T) {
	n := NewSimNetwork(SimConfig{})
	if _, err := n.DialStream(context.Background(), addr(9)); !errors.Is(err, ErrRefused) {
		t.Errorf("got %v, want ErrRefused", err)
	}
}

func TestSimStreamAddrInUse(t *testing.T) {
	n := NewSimNetwork(SimConfig{})
	l, _ := n.ListenStream(addr(1))
	defer l.Close()
	if _, err := n.ListenStream(addr(1)); !errors.Is(err, ErrAddrInUse) {
		t.Errorf("got %v, want ErrAddrInUse", err)
	}
	if l.Addr().String() != "10.0.0.1:1" {
		t.Errorf("Addr() = %v", l.Addr())
	}
}

func TestSimStreamAccept(t *testing.T) {
	n := NewSimNetwork(SimConfig{})
	l, _ := n.ListenStream(addr(1))

	// A dial waits until the listener accepts; cancelling the context
	// gives up.
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if _, err := n.DialStream(ctx, addr(1)); !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("dial without Accept: got %v", err)
	}

	// Closing the listener unblocks Accept and pending dials.
	errCh := make(chan error, 2)
	go func() { _, err := l.Accept(); errCh <- err }()
	go func() {
		time.Sleep(10 * time.Millisecond)
		l.Close()
		l.Close() // second Close is a no-op
	}()
	if err := <-errCh; !errors.Is(err, net.ErrClosed) {
		t.Errorf("Accept after Close: %v", err)
	}
}

func TestSimDialWhileListenerCloses(t *testing.T) {
	n := NewSimNetwork(SimConfig{})
	l, _ := n.ListenStream(addr(1))
	go func() {
		time.Sleep(20 * time.Millisecond)
		l.Close()
	}()
	if _, err := n.DialStream(context.Background(), addr(1)); !errors.Is(err, ErrRefused) {
		t.Errorf("got %v, want ErrRefused", err)
	}
}
