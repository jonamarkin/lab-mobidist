package registry

import (
	"context"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/jonamarkin/lab-mobidist/internal/kademlia"
	"github.com/jonamarkin/lab-mobidist/internal/network"
	"github.com/jonamarkin/lab-mobidist/internal/rpc"
)

// The adapter wired into real nodes: a small simulated network whose
// holders validate latest pointers with the rules and a fake DNS.
func TestValidatorOnNodes(t *testing.T) {
	ctx := context.Background()
	pk, sk := testKey(31)
	dns := NewFakeDNS()
	dns.Set("rfin.ch", pk)
	cfg := kademlia.Config{K: 10, Alpha: 3, RPC: rpc.Config{Timeout: 200 * time.Millisecond, Retries: 1},
		Validator: Validator{Verifier: dns}}
	sim := network.NewSimNetwork(network.SimConfig{})
	var nodes []*kademlia.Kademlia
	for i := range 12 {
		addr := netip.AddrPortFrom(netip.AddrFrom4([4]byte{10, 0, 0, byte(i + 1)}), 4000)
		n, err := kademlia.NewKademlia(sim, addr, cfg)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { n.Close() })
		if i > 0 {
			if err := n.Join(ctx, nodes[0].Me().Address); err != nil {
				t.Fatal(err)
			}
		}
		nodes = append(nodes, n)
	}
	publisher, reader := nodes[1], nodes[7]

	// Publish 1.0.0: blob, record, pointer.
	blob := []byte("package v1")
	if _, err := publisher.Store(ctx, blob); err != nil {
		t.Fatal(err)
	}
	r1 := NewVersionRecord("rfin.ch", "java-pair", Version{1, 0, 0}, kademlia.KeyFromValue(blob), ZeroHash)
	r1.Sign(sk)
	if _, err := publisher.Store(ctx, r1.Encode()); err != nil {
		t.Fatal(err)
	}
	p1 := NewLatestPointer("rfin.ch", "java-pair", r1.Version, r1.Key())
	p1.Sign(sk)
	res, err := publisher.Update(ctx, p1.Key(), p1.Encode())
	if err != nil || len(res.Accepted) != 10 || len(res.Refused) != 0 {
		t.Fatalf("publish 1.0.0: %+v, %v", res, err)
	}

	// A rollback attempt (0.9.0 chained to 1.0.0) is refused everywhere,
	// with the rules' reason.
	r0 := NewVersionRecord("rfin.ch", "java-pair", Version{0, 9, 0}, kademlia.KeyFromValue(blob), r1.Key())
	r0.Sign(sk)
	publisher.Store(ctx, r0.Encode())
	p0 := NewLatestPointer("rfin.ch", "java-pair", r0.Version, r0.Key())
	p0.Sign(sk)
	res, err = publisher.Update(ctx, p0.Key(), p0.Encode())
	if err == nil || len(res.Accepted) != 0 || len(res.Refused) != 10 {
		t.Fatalf("rollback: %+v, %v", res, err)
	}
	for _, ref := range res.Refused {
		if !strings.Contains(ref.Reason, "not newer") {
			t.Errorf("refusal reason %q", ref.Reason)
		}
	}

	// Every holder still has 1.0.0, as seen from another node.
	copies, err := reader.LookupAll(ctx, p1.Key())
	if err != nil || len(copies) != 10 {
		t.Fatalf("LookupAll: %d copies, %v", len(copies), err)
	}
	for _, c := range copies {
		p, err := DecodeLatestPointer(c.Value)
		if err != nil || p.Version != r1.Version {
			t.Errorf("copy from %v: %v %v", c.From, p.Version, err)
		}
	}
}
