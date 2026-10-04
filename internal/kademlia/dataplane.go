package kademlia

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"time"
)

// MaxValueSize is the largest value a node accepts (64 MiB). Values are
// kept in memory, and the size is checked from the header before any data
// is read, so a peer cannot exhaust a node's memory by announcing a huge
// value.
const MaxValueSize = 64 << 20

// maxHeaderSize bounds the JSON header line of a stream request/response.
const maxHeaderSize = 4096

// Data-plane protocol: one stream (TCP connection) per transfer.
//
//	STORE: client sends {"op":"STORE","key":K,"size":N}\n + N value bytes
//	       server replies {"ok":true}\n, or {"ok":false,"error":...}\n
//	FETCH: client sends {"op":"FETCH","key":K}\n
//	       server replies {"ok":true,"size":N}\n + N value bytes, or an error
const (
	opStore = "STORE"
	opFetch = "FETCH"
)

type streamRequest struct {
	Op   string     `json:"op"`
	Key  KademliaID `json:"key"`
	Size int        `json:"size,omitempty"`
}

type streamResponse struct {
	OK    bool   `json:"ok"`
	Error string `json:"error,omitempty"`
	Size  int    `json:"size,omitempty"`
}

// readHeader reads one JSON line of at most maxHeaderSize bytes.
func readHeader(r *bufio.Reader, v any) error {
	line, err := r.ReadSlice('\n')
	if errors.Is(err, bufio.ErrBufferFull) {
		return errors.New("header too long")
	}
	if err != nil {
		return err
	}
	return json.Unmarshal(line, v)
}

// writeHeader writes v as one JSON line.
func writeHeader(w io.Writer, v any) error {
	return json.NewEncoder(w).Encode(v) // Encode appends '\n'
}

// readValue reads a value of the announced size, refusing oversize ones
// before reading any data.
func readValue(r io.Reader, size int) ([]byte, error) {
	if size < 0 || size > MaxValueSize {
		return nil, fmt.Errorf("value size %d outside [0, %d]", size, MaxValueSize)
	}
	value := make([]byte, size)
	if _, err := io.ReadFull(r, value); err != nil {
		return nil, err
	}
	return value, nil
}

// serveStreams accepts data-plane connections until the listener closes.
func (k *Kademlia) serveStreams() {
	for {
		conn, err := k.streams.Accept()
		if err != nil {
			return // listener closed
		}
		k.bg.Go(func() { k.handleStream(conn) })
	}
}

// handleStream serves one STORE or FETCH request.
func (k *Kademlia) handleStream(conn net.Conn) {
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(k.cfg.TransferTimeout)) // never hang forever
	r := bufio.NewReaderSize(conn, maxHeaderSize)

	var req streamRequest
	if err := readHeader(r, &req); err != nil {
		writeHeader(conn, streamResponse{Error: "bad request: " + err.Error()})
		return
	}
	switch req.Op {
	case opStore:
		value, err := readValue(r, req.Size)
		if err == nil {
			// DataStore.Put enforces key == hash(value) (spec requirement).
			err = k.store.Put(req.Key, value)
		}
		if err != nil {
			k.log.Warn("store_rejected", "key", req.Key.Short(), "err", err.Error())
			writeHeader(conn, streamResponse{Error: err.Error()})
			return
		}
		k.log.Info("stored", "key", req.Key.Short(), "size", len(value))
		writeHeader(conn, streamResponse{OK: true})
	case opFetch:
		value, ok := k.store.Get(req.Key)
		if !ok {
			writeHeader(conn, streamResponse{Error: "not found"})
			return
		}
		if writeHeader(conn, streamResponse{OK: true, Size: len(value)}) == nil {
			conn.Write(value)
		}
	default:
		writeHeader(conn, streamResponse{Error: fmt.Sprintf("unknown op %q", req.Op)})
	}
}

// dial opens a data-plane stream to c with the transfer deadline set.
func (k *Kademlia) dial(ctx context.Context, c Contact) (net.Conn, *bufio.Reader, error) {
	conn, err := k.net.DialStream(ctx, c.Address)
	if err != nil {
		return nil, nil, err
	}
	conn.SetDeadline(time.Now().Add(k.cfg.TransferTimeout))
	return conn, bufio.NewReaderSize(conn, maxHeaderSize), nil
}

// storeAt pushes key -> value to c over the data plane.
func (k *Kademlia) storeAt(ctx context.Context, c Contact, key KademliaID, value []byte) error {
	conn, r, err := k.dial(ctx, c)
	if err != nil {
		return err
	}
	defer conn.Close()
	if err := writeHeader(conn, streamRequest{Op: opStore, Key: key, Size: len(value)}); err != nil {
		return err
	}
	if _, err := conn.Write(value); err != nil {
		return err
	}
	var resp streamResponse
	if err := readHeader(r, &resp); err != nil {
		return err
	}
	if !resp.OK {
		return fmt.Errorf("store rejected by %v: %s", c, resp.Error)
	}
	return nil
}

// fetchFrom pulls the value for key from c and checks that key ==
// hash(value). A mismatching value is discarded and reported (spec).
func (k *Kademlia) fetchFrom(ctx context.Context, c Contact, key KademliaID) ([]byte, error) {
	conn, r, err := k.dial(ctx, c)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	if err := writeHeader(conn, streamRequest{Op: opFetch, Key: key}); err != nil {
		return nil, err
	}
	var resp streamResponse
	if err := readHeader(r, &resp); err != nil {
		return nil, err
	}
	if !resp.OK {
		return nil, fmt.Errorf("fetch from %v: %s", c, resp.Error)
	}
	value, err := readValue(r, resp.Size)
	if err != nil {
		return nil, err
	}
	if KeyFromValue(value) != key {
		k.log.Error("hash_mismatch", "key", key.Short(), "from", c.ID.Short(), "addr", c.Address.String())
		return nil, fmt.Errorf("value from %v: %w", c, ErrHashMismatch)
	}
	return value, nil
}
