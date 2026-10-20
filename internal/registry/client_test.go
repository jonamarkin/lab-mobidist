package registry

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/jonamarkin/lab-mobidist/internal/kademlia"
	"github.com/jonamarkin/lab-mobidist/internal/network"
	"github.com/jonamarkin/lab-mobidist/internal/rpc"
)

// testNodes starts n simulated nodes whose holders validate pointers with
// the rules and the given fake DNS.
func testNodes(t *testing.T, n int, dns *FakeDNS) []*kademlia.Kademlia {
	t.Helper()
	cfg := kademlia.Config{K: 10, Alpha: 3, RPC: rpc.Config{Timeout: 200 * time.Millisecond, Retries: 1},
		Validator: Validator{Verifier: dns}}
	sim := network.NewSimNetwork(network.SimConfig{})
	var nodes []*kademlia.Kademlia
	for i := range n {
		addr := netip.AddrPortFrom(netip.AddrFrom4([4]byte{10, 0, byte(i >> 8), byte(i)}), 4000)
		node, err := kademlia.NewKademlia(sim, addr, cfg)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { node.Close() })
		if i > 0 {
			if err := node.Join(context.Background(), nodes[0].Me().Address); err != nil {
				t.Fatal(err)
			}
		}
		nodes = append(nodes, node)
	}
	return nodes
}

func mustRef(s string) Ref {
	ref, err := ParseRef(s)
	if err != nil {
		panic(err)
	}
	return ref
}

type clientFixture struct {
	nodes  []*kademlia.Kademlia
	dns    *FakeDNS
	pk     ed25519.PublicKey
	sk     ed25519.PrivateKey
	owner  *Client // publishes as rfin.ch
	reader *Client // another node, no key
}

func newClientFixture(t *testing.T, n int) *clientFixture {
	pk, sk := testKey(41)
	dns := NewFakeDNS()
	dns.Set("rfin.ch", pk)
	nodes := testNodes(t, n, dns)
	return &clientFixture{
		nodes:  nodes,
		dns:    dns,
		pk:     pk,
		sk:     sk,
		owner:  NewClient(nodes[1], dns, sk),
		reader: NewClient(nodes[n-1], dns, nil),
	}
}

func TestPublishInstallChain(t *testing.T) {
	ctx := context.Background()
	f := newClientFixture(t, 16)
	blobs := map[string][]byte{"1.0.0": []byte("one"), "1.1.0": []byte("one point one"), "2.0.0": []byte("two")}
	for _, v := range []string{"1.0.0", "1.1.0", "2.0.0"} {
		res, err := f.owner.Publish(ctx, mustRef("rfin.ch:java-pair:"+v), blobs[v], PublishOptions{})
		if err != nil {
			t.Fatalf("publish %s: %v", v, err)
		}
		if len(res.Pointer.Accepted) != 10 || len(res.Pointer.Refused) != 0 || len(res.Record.StoredAt) != 10 || len(res.Blob.StoredAt) != 10 {
			t.Errorf("publish %s: %+v", v, res)
		}
	}

	// latest, a specific version, and the oldest one.
	got, err := f.reader.Install(ctx, mustRef("rfin.ch:java-pair:latest"))
	if err != nil || !bytes.Equal(got.Blob, blobs["2.0.0"]) || got.Ref.Version != (Version{2, 0, 0}) || got.Head != (Version{2, 0, 0}) {
		t.Fatalf("install latest: %+v, %v", got.Ref, err)
	}
	if got.From == (kademlia.Contact{}) {
		t.Error("install did not say where the blob came from")
	}
	got, err = f.reader.Install(ctx, mustRef("rfin.ch:java-pair:1.1.0"))
	if err != nil || !bytes.Equal(got.Blob, blobs["1.1.0"]) || got.Head != (Version{2, 0, 0}) {
		t.Fatalf("install 1.1.0: %+v, %v", got.Ref, err)
	}
	got, err = f.reader.Install(ctx, mustRef("rfin.ch:java-pair:1.0.0"))
	if err != nil || !bytes.Equal(got.Blob, blobs["1.0.0"]) {
		t.Fatalf("install 1.0.0: %+v, %v", got.Ref, err)
	}
	for _, missing := range []string{"rfin.ch:java-pair:1.0.5", "rfin.ch:java-pair:3.0.0", "rfin.ch:java-pair:0.1.0"} {
		if _, err := f.reader.Install(ctx, mustRef(missing)); !errors.Is(err, ErrVersionNotFound) {
			t.Errorf("install %s: %v", missing, err)
		}
	}
	if _, err := f.reader.Install(ctx, mustRef("rfin.ch:nothing:latest")); !errors.Is(err, ErrNoPackage) {
		t.Errorf("install of an unknown package: %v", err)
	}

	// The chain, newest first, every record verified.
	chain, err := f.reader.Chain(ctx, "rfin.ch", "java-pair")
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"2.0.0", "1.1.0", "1.0.0"}
	if len(chain) != 3 {
		t.Fatalf("chain has %d entries: %+v", len(chain), chain)
	}
	for i, e := range chain {
		if e.Version.String() != want[i] || e.Err != nil || e.Blob != kademlia.KeyFromValue(blobs[want[i]]) {
			t.Errorf("entry %d: %+v", i, e)
		}
	}
	if chain[2].Prev != ZeroHash || chain[1].Prev != chain[2].RecordKey || chain[0].Prev != chain[1].RecordKey {
		t.Error("prev links do not connect the entries")
	}
	if _, err := f.reader.Chain(ctx, "rfin.ch", "nothing"); !errors.Is(err, ErrNoPackage) {
		t.Errorf("chain of an unknown package: %v", err)
	}

	pk, err := f.reader.Owner(ctx, "rfin.ch")
	if err != nil || !pk.Equal(f.pk) {
		t.Errorf("Owner = %x, %v", pk, err)
	}
	if _, err := f.reader.Owner(ctx, "other.ch"); !errors.Is(err, ErrNoKey) {
		t.Errorf("Owner of an unknown domain: %v", err)
	}
}

func TestPublishClientSideChecks(t *testing.T) {
	ctx := context.Background()
	f := newClientFixture(t, 14)
	if _, err := f.owner.Publish(ctx, mustRef("rfin.ch:java-pair:1.0.0"), []byte("one"), PublishOptions{}); err != nil {
		t.Fatal(err)
	}
	if _, err := f.owner.Publish(ctx, mustRef("rfin.ch:java-pair:1.1.0"), []byte("one.one"), PublishOptions{}); err != nil {
		t.Fatal(err)
	}
	pointerBefore, _ := f.nodes[5].LookupAll(ctx, LatestKey("rfin.ch", "java-pair"))

	v100, v110 := Version{1, 0, 0}, Version{1, 1, 0}
	_, otherSK := testKey(42)
	impostor := NewClient(f.nodes[3], f.dns, otherSK)
	noKey := NewClient(f.nodes[4], f.dns, nil)
	cases := []struct {
		name   string
		client *Client
		ref    string
		opts   PublishOptions
		want   error
	}{
		{"not newer", f.owner, "rfin.ch:java-pair:1.0.5", PublishOptions{}, ErrNotNewer},
		{"same version", f.owner, "rfin.ch:java-pair:1.1.0", PublishOptions{}, ErrNotNewer},
		{"prev is not the head", f.owner, "rfin.ch:java-pair:1.2.0", PublishOptions{Prev: &v100}, ErrFork},
		{"prev newer than the version", f.owner, "rfin.ch:java-pair:1.0.9", PublishOptions{Prev: &v110}, ErrNotNewer},
		{"prev does not exist", f.owner, "rfin.ch:java-pair:1.2.0", PublishOptions{Prev: &Version{0, 5, 0}}, ErrVersionNotFound},
		{"prev on a new package", f.owner, "rfin.ch:new-pkg:1.0.0", PublishOptions{Prev: &v100}, ErrVersionNotFound},
		{"not the owner", impostor, "rfin.ch:java-pair:1.2.0", PublishOptions{}, ErrNotOwner},
		{"unknown domain", f.owner, "other.ch:java-pair:1.0.0", PublishOptions{}, ErrNotOwner},
		{"no signing key", noKey, "rfin.ch:java-pair:1.2.0", PublishOptions{}, ErrNoSigningKey},
	}
	for _, c := range cases {
		_, err := c.client.Publish(ctx, mustRef(c.ref), []byte("x"), c.opts)
		if !errors.Is(err, c.want) {
			t.Errorf("%s: err = %v, want %v", c.name, err, c.want)
		}
	}
	if _, err := f.owner.Publish(ctx, mustRef("rfin.ch:java-pair:latest"), []byte("x"), PublishOptions{}); err == nil {
		t.Error("publishing \"latest\" succeeded")
	}
	if _, err := f.owner.Publish(ctx, mustRef("rfin.ch:java-pair:1.2.0"), make([]byte, kademlia.MaxValueSize+1), PublishOptions{}); err == nil {
		t.Error("an oversize package was accepted")
	}
	// None of that touched the network: the pointer is unchanged.
	pointerAfter, _ := f.nodes[5].LookupAll(ctx, LatestKey("rfin.ch", "java-pair"))
	if fmt.Sprint(pointerBefore) != fmt.Sprint(pointerAfter) {
		t.Error("a refused publish changed the holders")
	}
	// An explicit prev that is the head works like the default.
	if _, err := f.owner.Publish(ctx, mustRef("rfin.ch:java-pair:1.2.0"), []byte("x"), PublishOptions{Prev: &v110}); err != nil {
		t.Errorf("prev = head: %v", err)
	}
}

func TestPublishForceIsRefusedByHolders(t *testing.T) {
	ctx := context.Background()
	f := newClientFixture(t, 14)
	for _, v := range []string{"1.0.0", "1.1.0"} {
		if _, err := f.owner.Publish(ctx, mustRef("rfin.ch:java-pair:"+v), []byte(v), PublishOptions{}); err != nil {
			t.Fatal(err)
		}
	}
	v100 := Version{1, 0, 0}
	_, otherSK := testKey(43)
	impostor := NewClient(f.nodes[3], f.dns, otherSK)
	cases := []struct {
		name   string
		client *Client
		ref    string
		opts   PublishOptions
		reason string
	}{
		{"rollback", f.owner, "rfin.ch:java-pair:0.9.0", PublishOptions{Force: true}, "not newer"},
		{"fork", f.owner, "rfin.ch:java-pair:1.2.0", PublishOptions{Force: true, Prev: &v100}, "fork"},
		{"impostor", impostor, "rfin.ch:java-pair:1.2.0", PublishOptions{Force: true}, "not signed by the domain owner"},
	}
	for _, c := range cases {
		res, err := c.client.Publish(ctx, mustRef(c.ref), []byte(c.name), c.opts)
		if err == nil {
			t.Errorf("%s: forced publish succeeded", c.name)
			continue
		}
		if len(res.Pointer.Accepted) != 0 || len(res.Pointer.Refused) != 10 {
			t.Errorf("%s: accepted %d, refused %d", c.name, len(res.Pointer.Accepted), len(res.Pointer.Refused))
		}
		for _, r := range res.Pointer.Refused {
			if !strings.Contains(r.Reason, c.reason) {
				t.Errorf("%s: holder %v said %q", c.name, r.Node, r.Reason)
			}
		}
		// The blob and the record were uploaded (they are harmless, just
		// unreachable from any valid pointer); the pointer did not move.
		if len(res.Record.StoredAt) == 0 {
			t.Errorf("%s: record not stored", c.name)
		}
	}
	got, err := f.reader.Install(ctx, mustRef("rfin.ch:java-pair:latest"))
	if err != nil || got.Ref.Version != (Version{1, 1, 0}) {
		t.Fatalf("latest after forced publishes: %v, %v", got.Ref, err)
	}
	chain, _ := f.reader.Chain(ctx, "rfin.ch", "java-pair")
	if len(chain) != 2 {
		t.Errorf("chain has %d entries after forced publishes", len(chain))
	}
}

func TestReadersIgnoreStaleAndBadCopies(t *testing.T) {
	ctx := context.Background()
	f := newClientFixture(t, 16)
	res1, err := f.owner.Publish(ctx, mustRef("rfin.ch:java-pair:1.0.0"), []byte("one"), PublishOptions{})
	if err != nil {
		t.Fatal(err)
	}
	oldPointer := NewLatestPointer("rfin.ch", "java-pair", Version{1, 0, 0}, res1.RecordKey)
	oldPointer.Sign(f.sk)
	res2, err := f.owner.Publish(ctx, mustRef("rfin.ch:java-pair:1.1.0"), []byte("one.one"), PublishOptions{})
	if err != nil {
		t.Fatal(err)
	}
	key := LatestKey("rfin.ch", "java-pair")
	// Plant an old pointer on one holder and garbage on another, as if
	// one missed the update and one is broken.
	holders := res2.Pointer.Accepted
	stale := byContact(f.nodes, holders[0])
	cur, _ := stale.DataStore().Get(key)
	if err := stale.DataStore().PutMutable(key, oldPointer.Encode(), cur); err != nil {
		t.Fatal(err)
	}
	broken := byContact(f.nodes, holders[1])
	cur, _ = broken.DataStore().Get(key)
	if err := broken.DataStore().PutMutable(key, []byte("garbage"), cur); err != nil {
		t.Fatal(err)
	}
	got, err := f.reader.Install(ctx, mustRef("rfin.ch:java-pair:latest"))
	if err != nil || got.Ref.Version != (Version{1, 1, 0}) {
		t.Fatalf("install latest with stale and broken holders: %v, %v", got.Ref, err)
	}
	h, found, err := f.reader.head(ctx, "rfin.ch", "java-pair")
	if err != nil || !found || h.Invalid != 1 || h.Copies != 10 || h.Pointer.Version != (Version{1, 1, 0}) {
		t.Errorf("head = %+v, %v, %v", h, found, err)
	}
	// A publisher sees the same head, so the next version chains to 1.1.0.
	res3, err := f.owner.Publish(ctx, mustRef("rfin.ch:java-pair:1.2.0"), []byte("one.two"), PublishOptions{})
	if err != nil {
		t.Fatal(err)
	}
	rec, _ := DecodeVersionRecord(mustFetch(t, f.nodes[2], res3.RecordKey))
	if rec.Prev != res2.RecordKey {
		t.Error("1.2.0 does not chain to 1.1.0")
	}
}

func byContact(nodes []*kademlia.Kademlia, c kademlia.Contact) *kademlia.Kademlia {
	for _, n := range nodes {
		if n.Me() == c {
			return n
		}
	}
	panic("no such node")
}

func mustFetch(t *testing.T, n *kademlia.Kademlia, key kademlia.KademliaID) []byte {
	t.Helper()
	res, err := n.LookupData(context.Background(), key)
	if err != nil {
		t.Fatal(err)
	}
	return res.Value
}

func TestInstallSurvivesHolderChurn(t *testing.T) {
	ctx := context.Background()
	f := newClientFixture(t, 30)
	res, err := f.owner.Publish(ctx, mustRef("rfin.ch:java-pair:1.0.0"), []byte("one"), PublishOptions{})
	if err != nil {
		t.Fatal(err)
	}
	// Half of the pointer's holders leave; the rest still answer.
	for _, c := range res.Pointer.Accepted[:5] {
		byContact(f.nodes, c).Close()
	}
	got, err := f.reader.Install(ctx, mustRef("rfin.ch:java-pair:latest"))
	if err != nil || string(got.Blob) != "one" {
		t.Fatalf("install after churn: %v, %v", got.Ref, err)
	}
}

// Error paths that need broken data: a node alone is the only holder, so
// pointers and records can be planted directly.
func TestClientErrorPaths(t *testing.T) {
	ctx := context.Background()
	pk, sk := testKey(44)
	dns := NewFakeDNS()
	dns.Set("rfin.ch", pk)
	node := testNodes(t, 1, dns)[0]
	client := NewClient(node, dns, sk)

	// A chain whose first record was never stored: 1.0.0 exists only in
	// memory, 1.1.0 links to it and is published with its blob.
	blob1, blob2 := []byte("one"), []byte("one.one")
	r1 := NewVersionRecord("rfin.ch", "java-pair", Version{1, 0, 0}, kademlia.KeyFromValue(blob1), ZeroHash)
	r1.Sign(sk)
	r2 := NewVersionRecord("rfin.ch", "java-pair", Version{1, 1, 0}, kademlia.KeyFromValue(blob2), r1.Key())
	r2.Sign(sk)
	node.Store(ctx, blob2)
	node.Store(ctx, r2.Encode())
	p2 := NewLatestPointer("rfin.ch", "java-pair", r2.Version, r2.Key())
	p2.Sign(sk)
	if err := node.DataStore().PutMutable(p2.Key(), p2.Encode(), nil); err != nil {
		t.Fatal(err)
	}
	// latest is fine; the history ends where the record is missing.
	if got, err := client.Install(ctx, mustRef("rfin.ch:java-pair:latest")); err != nil || string(got.Blob) != "one.one" {
		t.Fatalf("install latest: %v, %v", got.Ref, err)
	}
	chain, err := client.Chain(ctx, "rfin.ch", "java-pair")
	if err != nil || len(chain) != 2 || chain[0].Err != nil || chain[1].Err == nil || chain[1].RecordKey != r1.Key() {
		t.Fatalf("chain with a missing record: %+v, %v", chain, err)
	}
	if _, err := client.Install(ctx, mustRef("rfin.ch:java-pair:1.0.0")); !errors.Is(err, ErrUnavailable) {
		t.Errorf("install of a version whose record is missing: %v", err)
	}
	if _, err := client.Publish(ctx, mustRef("rfin.ch:java-pair:1.2.0"), []byte("x"), PublishOptions{Prev: &Version{1, 0, 0}}); !errors.Is(err, ErrUnavailable) {
		t.Errorf("publish with a prev whose record is missing: %v", err)
	}

	// A record whose blob was never stored.
	r3 := NewVersionRecord("rfin.ch", "other", Version{1, 0, 0}, kademlia.KeyFromValue([]byte("never stored")), ZeroHash)
	r3.Sign(sk)
	node.Store(ctx, r3.Encode())
	p3 := NewLatestPointer("rfin.ch", "other", r3.Version, r3.Key())
	p3.Sign(sk)
	node.DataStore().PutMutable(p3.Key(), p3.Encode(), nil)
	if _, err := client.Install(ctx, mustRef("rfin.ch:other:latest")); err == nil || !strings.Contains(err.Error(), "fetch package") {
		t.Errorf("install with a missing blob: %v", err)
	}

	// A tiny chain budget truncates the history and stops a version walk.
	client.rules.MaxChain = 1
	if chain, err := client.Chain(ctx, "rfin.ch", "java-pair"); err != nil || len(chain) != 1 {
		t.Errorf("chain with MaxChain 1: %d entries, %v", len(chain), err)
	}
	if _, err := client.Install(ctx, mustRef("rfin.ch:java-pair:0.5.0")); !errors.Is(err, ErrChainTooLong) {
		t.Errorf("install past the chain budget: %v", err)
	}
	client.rules.MaxChain = 0
}
