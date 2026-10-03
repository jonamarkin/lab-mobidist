package rpc

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jonamarkin/lab-mobidist/internal/network"
)

func addr(port uint16) netip.AddrPort {
	return netip.AddrPortFrom(netip.MustParseAddr("10.0.0.1"), port)
}

// fastConfig keeps tests quick: 20 ms per attempt, 2 retries.
var fastConfig = Config{Timeout: 20 * time.Millisecond, Retries: 2}

// echo replies with its arguments; method "fail" returns an error.
func echo(from netip.AddrPort, method string, body json.RawMessage) (any, error) {
	if method == "fail" {
		return nil, errors.New("boom")
	}
	return body, nil
}

func listen(t *testing.T, n network.Network, port uint16) network.PacketConn {
	t.Helper()
	c, err := n.ListenPacket(addr(port))
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func endpoint(t *testing.T, conn network.PacketConn, h Handler) *Endpoint {
	t.Helper()
	e := NewEndpoint(conn, h, fastConfig)
	t.Cleanup(func() { e.Close() })
	return e
}

// dropFirst wraps a PacketConn and silently drops its first n sends, so
// tests can lose a specific packet deterministically.
type dropFirst struct {
	network.PacketConn
	remaining atomic.Int64
}

func newDropFirst(c network.PacketConn, n int64) *dropFirst {
	d := &dropFirst{PacketConn: c}
	d.remaining.Store(n)
	return d
}

func (d *dropFirst) Send(to netip.AddrPort, data []byte) error {
	if d.remaining.Add(-1) >= 0 {
		return nil
	}
	return d.PacketConn.Send(to, data)
}

func TestCallEcho(t *testing.T) {
	n := network.NewSimNetwork(network.SimConfig{})
	client := endpoint(t, listen(t, n, 1), nil)
	server := endpoint(t, listen(t, n, 2), echo)

	var got string
	if err := client.Call(context.Background(), server.LocalAddr(), "echo", "hello", &got); err != nil {
		t.Fatal(err)
	}
	if got != "hello" {
		t.Errorf("got %q", got)
	}
	if s := client.Stats(); s.Sent != 1 || s.Retransmits != 0 {
		t.Errorf("stats = %+v", s)
	}
}

func TestCallNilReply(t *testing.T) {
	n := network.NewSimNetwork(network.SimConfig{})
	client := endpoint(t, listen(t, n, 1), nil)
	server := endpoint(t, listen(t, n, 2), echo)
	if err := client.Call(context.Background(), server.LocalAddr(), "ping", nil, nil); err != nil {
		t.Fatal(err)
	}
}

func TestCallRemoteError(t *testing.T) {
	n := network.NewSimNetwork(network.SimConfig{})
	client := endpoint(t, listen(t, n, 1), nil)
	server := endpoint(t, listen(t, n, 2), echo)
	noHandler := endpoint(t, listen(t, n, 3), nil)

	var re *RemoteError
	err := client.Call(context.Background(), server.LocalAddr(), "fail", nil, nil)
	if !errors.As(err, &re) || re.Msg != "boom" || re.Method != "fail" {
		t.Errorf("got %v, want RemoteError boom", err)
	}
	err = client.Call(context.Background(), noHandler.LocalAddr(), "x", nil, nil)
	if !errors.As(err, &re) || re.Msg != "no handler" {
		t.Errorf("got %v, want RemoteError no handler", err)
	}
}

// Nobody listens: 1+Retries attempts, each waiting Timeout, then ErrTimeout.
func TestCallTimeout(t *testing.T) {
	n := network.NewSimNetwork(network.SimConfig{})
	client := endpoint(t, listen(t, n, 1), nil)

	start := time.Now()
	err := client.Call(context.Background(), addr(99), "echo", "x", nil)
	if !errors.Is(err, ErrTimeout) {
		t.Fatalf("got %v, want ErrTimeout", err)
	}
	want := time.Duration(fastConfig.Retries+1) * fastConfig.Timeout
	if elapsed := time.Since(start); elapsed < want {
		t.Errorf("gave up after %v, want >= %v", elapsed, want)
	}
	if s := client.Stats(); s.Sent != 3 || s.Retransmits != 2 || s.Timeouts != 1 {
		t.Errorf("stats = %+v", s)
	}
}

// The request is lost once; the retransmission succeeds.
func TestCallRetransmitsLostRequest(t *testing.T) {
	n := network.NewSimNetwork(network.SimConfig{})
	client := endpoint(t, newDropFirst(listen(t, n, 1), 1), nil)
	server := endpoint(t, listen(t, n, 2), echo)

	var got string
	if err := client.Call(context.Background(), server.LocalAddr(), "echo", "hi", &got); err != nil {
		t.Fatal(err)
	}
	if s := client.Stats(); s.Sent != 2 || s.Retransmits != 1 {
		t.Errorf("stats = %+v", s)
	}
}

// The response is lost once: the server receives the request twice and
// runs the handler twice (why handlers must be idempotent).
func TestCallRetransmitsLostResponse(t *testing.T) {
	n := network.NewSimNetwork(network.SimConfig{})
	var calls atomic.Int64
	counting := func(from netip.AddrPort, method string, body json.RawMessage) (any, error) {
		calls.Add(1)
		return "ok", nil
	}
	client := endpoint(t, listen(t, n, 1), nil)
	endpoint(t, newDropFirst(listen(t, n, 2), 1), counting)

	if err := client.Call(context.Background(), addr(2), "x", nil, nil); err != nil {
		t.Fatal(err)
	}
	if got := calls.Load(); got != 2 {
		t.Errorf("handler ran %d times, want 2", got)
	}
}

// A slow (not lost) response arrives after the retransmission. The first
// response completes the call; the duplicate is counted as unmatched.
func TestCallLateResponseStillCounts(t *testing.T) {
	n := network.NewSimNetwork(network.SimConfig{})
	slow := func(from netip.AddrPort, method string, body json.RawMessage) (any, error) {
		time.Sleep(30 * time.Millisecond) // longer than one Timeout (20 ms)
		return "ok", nil
	}
	client := endpoint(t, listen(t, n, 1), nil)
	endpoint(t, listen(t, n, 2), slow)

	if err := client.Call(context.Background(), addr(2), "x", nil, nil); err != nil {
		t.Fatal(err)
	}
	time.Sleep(50 * time.Millisecond) // let the duplicate response arrive
	if s := client.Stats(); s.Retransmits < 1 || s.Unmatched < 1 {
		t.Errorf("stats = %+v, want a retransmit and an unmatched duplicate", s)
	}
}

// The spec's forgery requirement: a response is accepted only with the
// right RPC ID AND from the address the request was sent to.
func TestForgedResponsesRejected(t *testing.T) {
	n := network.NewSimNetwork(network.SimConfig{})
	client := endpoint(t, listen(t, n, 1), nil)
	server := listen(t, n, 2)   // raw conn: the test plays the server
	attacker := listen(t, n, 3) // can send anything, but cannot see requests
	defer server.Close()
	defer attacker.Close()

	result := make(chan string, 1)
	go func() {
		var got string
		if err := client.Call(context.Background(), addr(2), "echo", "x", &got); err != nil {
			got = "error: " + err.Error()
		}
		result <- got
	}()

	pkt, err := server.Recv()
	if err != nil {
		t.Fatal(err)
	}
	var req envelope
	if err := json.Unmarshal(pkt.Data, &req); err != nil {
		t.Fatal(err)
	}
	respond := func(from network.PacketConn, id RPCID, body string) {
		data, _ := json.Marshal(envelope{ID: id, Response: true, Method: "echo", Body: json.RawMessage(fmt.Sprintf("%q", body))})
		from.Send(addr(1), data)
	}

	respond(attacker, req.ID, "forged: right ID, wrong address")
	respond(server, newRPCID(), "forged: right address, wrong ID")
	respond(server, req.ID, "genuine")

	if got := <-result; got != "genuine" {
		t.Errorf("call returned %q", got)
	}
	if s := client.Stats(); s.Unmatched != 2 {
		t.Errorf("unmatched = %d, want 2", s.Unmatched)
	}
}

// Many concurrent calls with random latency (so responses are reordered):
// every caller must get its own answer.
func TestConcurrentCallsMatchResponses(t *testing.T) {
	n := network.NewSimNetwork(network.SimConfig{MaxLatency: 5 * time.Millisecond, Seed: 1})
	client := endpoint(t, listen(t, n, 1), nil)
	server := endpoint(t, listen(t, n, 2), echo)

	var wg sync.WaitGroup
	for i := range 50 {
		wg.Go(func() {
			var got int
			if err := client.Call(context.Background(), server.LocalAddr(), "echo", i, &got); err != nil {
				t.Error(err)
			} else if got != i {
				t.Errorf("call %d got response %d", i, got)
			}
		})
	}
	wg.Wait()
}

func TestMalformedPacketsIgnored(t *testing.T) {
	n := network.NewSimNetwork(network.SimConfig{})
	raw := listen(t, n, 1)
	defer raw.Close()
	server := endpoint(t, listen(t, n, 2), echo)

	raw.Send(addr(2), []byte("not json"))
	raw.Send(addr(2), []byte(`{"id":"zz"}`))                      // bad ID
	raw.Send(addr(2), []byte(`{"id":"`+newRPCID().String()+`"}`)) // no method

	// The server still works afterwards.
	client := endpoint(t, listen(t, n, 3), nil)
	if err := client.Call(context.Background(), addr(2), "echo", 1, nil); err != nil {
		t.Fatal(err)
	}
	if s := server.Stats(); s.Malformed != 3 {
		t.Errorf("malformed = %d, want 3", s.Malformed)
	}
}

func TestCallEncodingErrors(t *testing.T) {
	n := network.NewSimNetwork(network.SimConfig{})
	client := endpoint(t, listen(t, n, 1), nil)
	badReply := func(from netip.AddrPort, method string, body json.RawMessage) (any, error) {
		return make(chan int), nil // channels cannot be JSON-encoded
	}
	endpoint(t, listen(t, n, 2), echo)
	endpoint(t, listen(t, n, 3), badReply)
	ctx := context.Background()

	if err := client.Call(ctx, addr(2), "echo", make(chan int), nil); err == nil {
		t.Error("unencodable args: no error")
	}
	var wrongType int
	if err := client.Call(ctx, addr(2), "echo", "not a number", &wrongType); err == nil {
		t.Error("undecodable reply: no error")
	}
	var re *RemoteError
	if err := client.Call(ctx, addr(3), "x", nil, nil); !errors.As(err, &re) {
		t.Errorf("unencodable reply: got %v, want RemoteError", err)
	}
}

func TestCallContextCancel(t *testing.T) {
	n := network.NewSimNetwork(network.SimConfig{})
	e := NewEndpoint(listen(t, n, 1), nil, Config{Timeout: time.Second})
	defer e.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	start := time.Now()
	if err := e.Call(ctx, addr(99), "x", nil, nil); !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("got %v, want DeadlineExceeded", err)
	}
	if time.Since(start) > 500*time.Millisecond {
		t.Error("cancel did not interrupt the call")
	}
}

func TestCloseFailsPendingCalls(t *testing.T) {
	n := network.NewSimNetwork(network.SimConfig{})
	e := NewEndpoint(listen(t, n, 1), nil, Config{Timeout: time.Second})

	errCh := make(chan error, 1)
	go func() { errCh <- e.Call(context.Background(), addr(99), "x", nil, nil) }()
	time.Sleep(10 * time.Millisecond)
	e.Close()

	if err := <-errCh; !errors.Is(err, ErrClosed) {
		t.Errorf("pending call: got %v, want ErrClosed", err)
	}
	if err := e.Call(context.Background(), addr(99), "x", nil, nil); !errors.Is(err, ErrClosed) {
		t.Errorf("call after close: got %v, want ErrClosed", err)
	}
	e.Close() // second Close is a no-op
}

func TestSendErrorIsReturned(t *testing.T) {
	n := network.NewSimNetwork(network.SimConfig{})
	client := endpoint(t, listen(t, n, 1), nil)
	big := make([]byte, network.MaxPacketSize)
	if err := client.Call(context.Background(), addr(2), "x", big, nil); !errors.Is(err, network.ErrTooLarge) {
		t.Errorf("got %v, want ErrTooLarge", err)
	}
}

func TestRPCIDText(t *testing.T) {
	id := newRPCID()
	text, _ := id.MarshalText()
	var back RPCID
	if err := back.UnmarshalText(text); err != nil || back != id {
		t.Errorf("round trip: %v, %v", back, err)
	}
	if err := back.UnmarshalText([]byte("abc")); err == nil {
		t.Error("short id accepted")
	}
	if newRPCID() == newRPCID() {
		t.Error("two random IDs are equal")
	}
}

func TestSameAddrUnmapsIPv4(t *testing.T) {
	plain := netip.MustParseAddrPort("10.0.0.1:4000")
	mapped := netip.MustParseAddrPort("[::ffff:10.0.0.1]:4000")
	if !sameAddr(plain, mapped) {
		t.Error("mapped and plain IPv4 differ")
	}
	if sameAddr(plain, netip.MustParseAddrPort("10.0.0.1:4001")) {
		t.Error("different ports are equal")
	}
}

func TestRemoteErrorMessage(t *testing.T) {
	err := &RemoteError{Method: "STORE", Msg: "hash mismatch"}
	if got := err.Error(); got != "rpc: remote STORE failed: hash mismatch" {
		t.Errorf("Error() = %q", got)
	}
}

func TestDefaultConfig(t *testing.T) {
	if c := DefaultConfig(); c.Timeout != 500*time.Millisecond || c.Retries != 2 {
		t.Errorf("DefaultConfig() = %+v", c)
	}
}
