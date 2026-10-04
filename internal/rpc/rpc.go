// Package rpc implements request/response calls over an unreliable
// network.PacketConn: request/response correlation by random RPC ID,
// timeouts, and retransmission. It knows nothing about Kademlia; methods
// are plain strings and bodies are JSON.
package rpc

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jonamarkin/lab-mobidist/internal/network"
)

var (
	ErrTimeout = errors.New("rpc: no response (timeout)")
	ErrClosed  = errors.New("rpc: endpoint closed")
)

// RemoteError is returned by Call when the remote handler reported an error.
type RemoteError struct {
	Method string
	Msg    string
}

func (e *RemoteError) Error() string {
	return fmt.Sprintf("rpc: remote %s failed: %s", e.Method, e.Msg)
}

// RPCID identifies one call. It is 160 random bits from crypto/rand (as in
// the Kademlia paper), so an attacker who cannot see the request cannot
// guess it to forge a response.
type RPCID [20]byte

func newRPCID() RPCID {
	var id RPCID
	rand.Read(id[:]) // never returns an error (Go 1.24+)
	return id
}

func (id RPCID) String() string { return hex.EncodeToString(id[:]) }

// MarshalText encodes the ID as hex in JSON (instead of an array of numbers).
func (id RPCID) MarshalText() ([]byte, error) {
	return []byte(id.String()), nil
}

func (id *RPCID) UnmarshalText(b []byte) error {
	if len(b) != hex.EncodedLen(len(id)) {
		return fmt.Errorf("rpc id must be %d hex digits", hex.EncodedLen(len(id)))
	}
	_, err := hex.Decode(id[:], b)
	return err
}

// envelope is the wire format: one JSON object per packet. Body is
// json.RawMessage so the caller's JSON is embedded as-is (a []byte field
// would be base64-encoded, about a third larger).
type envelope struct {
	ID       RPCID           `json:"id"`
	Response bool            `json:"response,omitempty"`
	Method   string          `json:"method"`
	Body     json.RawMessage `json:"body,omitempty"`
	Error    string          `json:"error,omitempty"`
}

// Handler serves incoming requests. Its reply is JSON-encoded and sent
// back; a non-nil error is sent back instead and surfaces as a RemoteError.
// Requests may be retransmitted, so a handler can run more than once for
// the same call and should be idempotent.
type Handler func(from netip.AddrPort, method string, body json.RawMessage) (reply any, err error)

// Config is the timeout/retry policy. A call makes at most 1+Retries
// attempts and waits Timeout after each one.
type Config struct {
	Timeout time.Duration
	Retries int
}

// DefaultConfig waits 500 ms per attempt and retries twice (at most 1.5 s).
func DefaultConfig() Config {
	return Config{Timeout: 500 * time.Millisecond, Retries: 2}
}

// Stats counts RPC events, for tests and experiments.
type Stats struct {
	Sent        int64 // request packets sent, including retransmissions
	Retransmits int64 // of which retransmissions
	Timeouts    int64 // calls that got no response after all attempts
	Unmatched   int64 // responses with an unknown ID or wrong source (late or forged)
	Malformed   int64 // packets that could not be decoded
}

// Endpoint makes calls and serves requests on one PacketConn. A single
// read-loop goroutine receives all packets: responses are handed to the
// waiting Call, requests are served in their own goroutine.
type Endpoint struct {
	conn    network.PacketConn
	handler Handler
	cfg     Config

	mu      sync.Mutex // guards pending
	pending map[RPCID]pendingCall

	done      chan struct{}
	closeOnce sync.Once
	wg        sync.WaitGroup // read loop and request handlers

	sent, retransmits, timeouts, unmatched, malformed atomic.Int64
}

type pendingCall struct {
	to    netip.AddrPort // a response must come from here
	reply chan envelope  // buffered (1): the read loop never blocks
}

// NewEndpoint starts serving on conn. The endpoint owns conn and closes
// it in Close.
func NewEndpoint(conn network.PacketConn, handler Handler, cfg Config) *Endpoint {
	e := &Endpoint{
		conn:    conn,
		handler: handler,
		cfg:     cfg,
		pending: make(map[RPCID]pendingCall),
		done:    make(chan struct{}),
	}
	e.wg.Go(e.readLoop)
	return e
}

func (e *Endpoint) LocalAddr() netip.AddrPort { return e.conn.LocalAddr() }

// Stats returns a snapshot of the counters.
func (e *Endpoint) Stats() Stats {
	return Stats{
		Sent:        e.sent.Load(),
		Retransmits: e.retransmits.Load(),
		Timeouts:    e.timeouts.Load(),
		Unmatched:   e.unmatched.Load(),
		Malformed:   e.malformed.Load(),
	}
}

// Call invokes method on the node at to, with args JSON-encoded, and
// decodes the response into reply (which may be nil). It returns
// ErrTimeout if no response arrives, a *RemoteError if the handler
// failed, ErrClosed if the endpoint is closed, or ctx.Err().
func (e *Endpoint) Call(ctx context.Context, to netip.AddrPort, method string, args, reply any) error {
	select {
	case <-e.done:
		return ErrClosed
	default:
	}
	body, err := json.Marshal(args)
	if err != nil {
		return fmt.Errorf("rpc: encode args: %w", err)
	}
	id := newRPCID()
	pkt, err := json.Marshal(envelope{ID: id, Method: method, Body: body})
	if err != nil {
		return fmt.Errorf("rpc: encode request: %w", err)
	}

	ch := make(chan envelope, 1)
	e.mu.Lock()
	e.pending[id] = pendingCall{to: to, reply: ch}
	e.mu.Unlock()
	defer func() {
		e.mu.Lock()
		delete(e.pending, id)
		e.mu.Unlock()
	}()

	for attempt := range e.cfg.Retries + 1 {
		if attempt > 0 {
			e.retransmits.Add(1)
		}
		e.sent.Add(1)
		// Same packet, same ID: a late response to an earlier attempt
		// still completes the call.
		if err := e.conn.Send(to, pkt); err != nil {
			return err
		}
		timer := time.NewTimer(e.cfg.Timeout)
		select {
		case resp := <-ch:
			timer.Stop()
			if resp.Error != "" {
				return &RemoteError{Method: method, Msg: resp.Error}
			}
			if reply == nil {
				return nil
			}
			if err := json.Unmarshal(resp.Body, reply); err != nil {
				return fmt.Errorf("rpc: decode reply: %w", err)
			}
			return nil
		case <-timer.C:
			// No response yet: retransmit (or give up below).
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-e.done:
			timer.Stop()
			return ErrClosed
		}
	}
	e.timeouts.Add(1)
	return ErrTimeout
}

// Close stops the endpoint, fails pending calls with ErrClosed, and waits
// for the read loop and running handlers to finish.
func (e *Endpoint) Close() error {
	e.closeOnce.Do(func() {
		close(e.done)
		e.conn.Close()
	})
	e.wg.Wait()
	return nil
}

func (e *Endpoint) readLoop() {
	for {
		pkt, err := e.conn.Recv()
		if err != nil {
			return // connection closed
		}
		var env envelope
		if err := json.Unmarshal(pkt.Data, &env); err != nil || env.Method == "" {
			e.malformed.Add(1)
			continue
		}
		if env.Response {
			e.handleResponse(pkt.From, env)
		} else {
			e.wg.Go(func() { e.handleRequest(pkt.From, env) })
		}
	}
}

// handleResponse completes the matching pending call. A response is only
// accepted if its ID is pending AND it comes from the address the request
// was sent to; anything else (late duplicate, forgery) is dropped.
func (e *Endpoint) handleResponse(from netip.AddrPort, env envelope) {
	e.mu.Lock()
	call, ok := e.pending[env.ID]
	ok = ok && sameAddr(call.to, from)
	if ok {
		delete(e.pending, env.ID) // so a duplicate response is unmatched
	}
	e.mu.Unlock()

	if !ok {
		e.unmatched.Add(1)
		return
	}
	call.reply <- env
}

func (e *Endpoint) handleRequest(from netip.AddrPort, env envelope) {
	resp := envelope{ID: env.ID, Response: true, Method: env.Method}
	if body, err := e.serve(from, env); err != nil {
		resp.Error = err.Error()
	} else {
		resp.Body = body
	}
	data, err := json.Marshal(resp)
	if err != nil {
		return
	}
	// Errors are ignored: if the response is lost, the caller times out
	// and retransmits, exactly as if the network had dropped it.
	e.conn.Send(from, data)
}

// serve runs the handler and JSON-encodes its reply.
func (e *Endpoint) serve(from netip.AddrPort, env envelope) (json.RawMessage, error) {
	if e.handler == nil {
		return nil, errors.New("no handler")
	}
	reply, err := e.handler(from, env.Method, env.Body)
	if err != nil {
		return nil, err
	}
	body, err := json.Marshal(reply)
	if err != nil {
		return nil, fmt.Errorf("encode reply: %w", err)
	}
	return body, nil
}

// sameAddr compares addresses, treating an IPv4-mapped IPv6 address
// (::ffff:a.b.c.d) as equal to the plain IPv4 address.
func sameAddr(a, b netip.AddrPort) bool {
	return network.Unmap(a) == network.Unmap(b)
}
