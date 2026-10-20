package testnet

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"fmt"
	"testing"
	"time"

	"github.com/jonamarkin/lab-mobidist/internal/kademlia"
	"github.com/jonamarkin/lab-mobidist/internal/registry"
)

// The part 2 large-scale requirement: the registry on 1000 nodes. Random
// nodes publish packages under three domains, other random nodes install
// them, and forced invalid updates are refused by every holder.
func TestThousandNodeRegistry(t *testing.T) {
	if testing.Short() {
		t.Skip("1000-node registry test skipped with -short")
	}
	ctx := context.Background()
	domains := []string{"alpha.test", "beta.test", "gamma.test"}
	dns := registry.NewFakeDNS()
	keys := make(map[string]ed25519.PrivateKey)
	for i, d := range domains {
		seed := bytes.Repeat([]byte{byte(50 + i)}, ed25519.SeedSize)
		sk := ed25519.NewKeyFromSeed(seed)
		keys[d] = sk
		dns.Set(d, sk.Public().(ed25519.PublicKey))
	}
	cfg := config()
	cfg.Validator = registry.Validator{Verifier: dns}

	start := time.Now()
	nw, err := Build(ctx, Options{N: 1000, Seed: 7, Node: cfg})
	if err != nil {
		t.Fatal(err)
	}
	defer nw.Close()
	t.Logf("built 1000 nodes in %v", time.Since(start).Round(time.Millisecond))

	client := func(n *kademlia.Kademlia, domain string) *registry.Client {
		return registry.NewClient(n, dns, keys[domain])
	}
	type pkg struct {
		domain, name string
		versions     []string
		blobs        map[string][]byte
	}
	var pkgs []pkg
	for i := range 20 {
		p := pkg{domain: domains[i%3], name: fmt.Sprintf("pkg%02d", i), blobs: map[string][]byte{}}
		for v := range 1 + i%3 {
			p.versions = append(p.versions, fmt.Sprintf("1.%d.0", v))
		}
		pkgs = append(pkgs, p)
	}

	// Publish every version of every package from a random node.
	start = time.Now()
	published := 0
	for i := range pkgs {
		p := &pkgs[i]
		for _, v := range p.versions {
			blob := fmt.Appendf(nil, "%s:%s %s %x", p.domain, p.name, v, nw.Rand.Uint64())
			p.blobs[v] = blob
			ref := registry.Ref{Domain: p.domain, Package: p.name}
			ref.Version, _ = registry.ParseVersion(v)
			from := nw.Nodes[nw.Rand.IntN(len(nw.Nodes))]
			res, err := client(from, p.domain).Publish(ctx, ref, blob, registry.PublishOptions{})
			if err != nil {
				t.Fatalf("publish %s:%s %s: %v", p.domain, p.name, v, err)
			}
			if len(res.Pointer.Accepted) != 10 || len(res.Pointer.Refused) != 0 {
				t.Errorf("publish %s:%s %s: accepted %d, refused %d", p.domain, p.name, v,
					len(res.Pointer.Accepted), len(res.Pointer.Refused))
			}
			published++
		}
	}
	t.Logf("%d versions published in %v", published, time.Since(start).Round(time.Millisecond))

	// Install latest and the first version of every package from other
	// random nodes, and check the chains.
	start = time.Now()
	for _, p := range pkgs {
		from := nw.Nodes[nw.Rand.IntN(len(nw.Nodes))]
		c := client(from, "")
		latest := p.versions[len(p.versions)-1]
		got, err := c.Install(ctx, registry.Ref{Domain: p.domain, Package: p.name, Latest: true})
		if err != nil || !bytes.Equal(got.Blob, p.blobs[latest]) || got.Ref.Version.String() != latest {
			t.Fatalf("install %s:%s latest: %v %v", p.domain, p.name, got.Ref, err)
		}
		first := registry.Ref{Domain: p.domain, Package: p.name}
		first.Version, _ = registry.ParseVersion(p.versions[0])
		got, err = c.Install(ctx, first)
		if err != nil || !bytes.Equal(got.Blob, p.blobs[p.versions[0]]) {
			t.Fatalf("install %s:%s %s: %v", p.domain, p.name, p.versions[0], err)
		}
		chain, err := c.Chain(ctx, p.domain, p.name)
		if err != nil || len(chain) != len(p.versions) {
			t.Fatalf("chain %s:%s: %d entries, %v", p.domain, p.name, len(chain), err)
		}
		for _, e := range chain {
			if e.Err != nil {
				t.Errorf("chain %s:%s %v: %v", p.domain, p.name, e.Version, e.Err)
			}
		}
	}
	t.Logf("%d packages installed and checked in %v", len(pkgs), time.Since(start).Round(time.Millisecond))

	// Forced invalid updates on a package with three versions: a fork
	// from the first version and a rollback, both refused by all holders.
	p := pkgs[2] // 1.0.0, 1.1.0, 1.2.0
	owner := client(nw.Nodes[nw.Rand.IntN(len(nw.Nodes))], p.domain)
	v100, _ := registry.ParseVersion("1.0.0")
	fork := registry.Ref{Domain: p.domain, Package: p.name, Version: registry.Version{Major: 2}}
	res, err := owner.Publish(ctx, fork, []byte("fork"), registry.PublishOptions{Force: true, Prev: &v100})
	if err == nil || len(res.Pointer.Accepted) != 0 || len(res.Pointer.Refused) != 10 {
		t.Errorf("forced fork: accepted %d, refused %d, %v", len(res.Pointer.Accepted), len(res.Pointer.Refused), err)
	}
	rollback := registry.Ref{Domain: p.domain, Package: p.name, Version: registry.Version{Minor: 1}}
	res, err = owner.Publish(ctx, rollback, []byte("old"), registry.PublishOptions{Force: true})
	if err == nil || len(res.Pointer.Accepted) != 0 || len(res.Pointer.Refused) != 10 {
		t.Errorf("forced rollback: accepted %d, refused %d, %v", len(res.Pointer.Accepted), len(res.Pointer.Refused), err)
	}
	// An impostor: beta's key publishing under alpha.
	impostor := registry.NewClient(nw.Nodes[3], dns, keys["beta.test"])
	res, err = impostor.Publish(ctx, registry.Ref{Domain: "alpha.test", Package: p.name, Version: registry.Version{Major: 9}},
		[]byte("evil"), registry.PublishOptions{Force: true})
	if err == nil || len(res.Pointer.Accepted) != 0 {
		t.Errorf("impostor: accepted %d, %v", len(res.Pointer.Accepted), err)
	}
	// Latest is unchanged.
	got, err := client(nw.Nodes[500], "").Install(ctx, registry.Ref{Domain: p.domain, Package: p.name, Latest: true})
	if err != nil || got.Ref.Version.String() != "1.2.0" {
		t.Errorf("latest after forced updates: %v, %v", got.Ref, err)
	}
}
