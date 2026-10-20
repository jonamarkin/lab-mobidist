package cli

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jonamarkin/lab-mobidist/internal/kademlia"
	"github.com/jonamarkin/lab-mobidist/internal/network"
	"github.com/jonamarkin/lab-mobidist/internal/registry"
	"github.com/jonamarkin/lab-mobidist/internal/rpc"
)

var testCfg = kademlia.Config{K: 10, Alpha: 3, RPC: rpc.Config{Timeout: 100 * time.Millisecond, Retries: 1}}

func addr(i int) netip.AddrPort {
	return netip.AddrPortFrom(netip.AddrFrom4([4]byte{10, 0, byte(i >> 8), byte(i)}), 4000)
}

// network of n nodes; node 0 is the bootstrap node.
func testNetwork(t *testing.T, n int) []*kademlia.Kademlia {
	t.Helper()
	sim := network.NewSimNetwork(network.SimConfig{})
	var nodes []*kademlia.Kademlia
	for i := range n {
		k, err := kademlia.NewKademlia(sim, addr(i), testCfg)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { k.Close() })
		if i > 0 {
			if err := k.Join(context.Background(), addr(0)); err != nil {
				t.Fatal(err)
			}
		}
		nodes = append(nodes, k)
	}
	return nodes
}

// run executes one command on node and returns its output.
func run(node *kademlia.Kademlia, line string) string {
	var out bytes.Buffer
	NewShell(node, &out).Execute(line)
	return out.String()
}

func expect(t *testing.T, got string, wants ...string) {
	t.Helper()
	for _, w := range wants {
		if !strings.Contains(got, w) {
			t.Errorf("output does not contain %q:\n%s", w, got)
		}
	}
}

func TestRunStopsAtExit(t *testing.T) {
	nodes := testNetwork(t, 1)
	var out bytes.Buffer
	err := NewShell(nodes[0], &out).Run(strings.NewReader("help\n\nid\nexit\nid\n"))
	if err != nil {
		t.Fatal(err)
	}
	expect(t, out.String(), "commands:", "full ID "+nodes[0].Me().ID.String())
	if strings.Count(out.String(), "full ID") != 1 {
		t.Error("commands after exit were run")
	}
}

func TestRunStopsAtEOF(t *testing.T) {
	nodes := testNetwork(t, 1)
	var out bytes.Buffer
	if err := NewShell(nodes[0], &out).Run(strings.NewReader("id")); err != nil {
		t.Fatal(err)
	}
	expect(t, out.String(), "full ID")
}

// A line longer than bufio's default 64 KiB limit is still one command.
func TestRunLongLine(t *testing.T) {
	nodes := testNetwork(t, 1)
	var out bytes.Buffer
	text := strings.Repeat("x", 100<<10)
	if err := NewShell(nodes[0], &out).Run(strings.NewReader("puttext " + text + "\nid\n")); err != nil {
		t.Fatal(err)
	}
	expect(t, out.String(), fmt.Sprintf("stored %d bytes", len(text)), "full ID")
}

func TestPingByAddress(t *testing.T) {
	nodes := testNetwork(t, 3)
	expect(t, run(nodes[1], "ping "+addr(2).String()), "reply from "+nodes[2].Me().String(), "rtt=")
	expect(t, run(nodes[1], "ping 10.0.9.9:4000"), "error:", "timeout")
	expect(t, run(nodes[1], "ping"), "usage: ping")
	expect(t, run(nodes[1], "ping nosuchhost.invalid:4000"), "error:")
}

func TestPingByIDPrefix(t *testing.T) {
	nodes := testNetwork(t, 10)
	n := nodes[0] // the bootstrap node knows everyone here
	target := nodes[5].Me()
	expect(t, run(n, "ping "+strings.ToUpper(target.ID.String()[:12])), "reply from "+target.String())
	expect(t, run(n, "ping zz"), "not an address or a hex ID prefix")
	expect(t, run(n, "ping "+strings.Repeat("0", 63)), "no contact with ID prefix")

	// Find a one-digit prefix shared by at least two contacts.
	counts := map[byte]int{}
	for _, c := range nodes[1:] {
		counts[c.Me().ID.String()[0]]++
	}
	for digit, count := range counts {
		if count >= 2 {
			expect(t, run(n, "ping "+string(digit)), "ambiguous")
			break
		}
	}
}

func TestLookupCommand(t *testing.T) {
	nodes := testNetwork(t, 5)
	expect(t, run(nodes[0], "lookup ff"), "4 closest to ff00…0000", "probes", "1. ")
	expect(t, run(nodes[0], "lookup zz"), "error:")
	expect(t, run(nodes[0], "lookup"), "usage: lookup")
	expect(t, run(nodes[0], "lookup "+strings.Repeat("a", 65)), "usage: lookup")

	alone := testNetwork(t, 1)[0]
	expect(t, run(alone, "lookup 12"), "error:", "no live contacts")
}

func TestShowRT(t *testing.T) {
	nodes := testNetwork(t, 5)
	out := run(nodes[0], "show rt")
	expect(t, out, "routing table of "+nodes[0].Me().String(), "4 contacts", "(k=10)", "bucket 255", nodes[1].Me().String())
	if strings.Contains(out, "(0/10)") {
		t.Error("empty bucket printed")
	}
	expect(t, run(nodes[0], "show"), "usage: show rt | show ds")
	expect(t, run(nodes[0], "show xyz"), "usage: show rt | show ds")
}

func TestShowRTFlat(t *testing.T) {
	sim := network.NewSimNetwork(network.SimConfig{})
	cfg := testCfg
	cfg.FlatRoutingTable = true
	a, _ := kademlia.NewKademlia(sim, addr(0), cfg)
	b, _ := kademlia.NewKademlia(sim, addr(1), cfg)
	defer a.Close()
	defer b.Close()
	b.Join(context.Background(), addr(0))
	expect(t, run(a, "show rt"), "flat routing table", "1 contacts", b.Me().String())
}

func TestUnknownCommand(t *testing.T) {
	nodes := testNetwork(t, 1)
	expect(t, run(nodes[0], "frobnicate"), `unknown command "frobnicate"`)
	if run(nodes[0], "   ") != "" {
		t.Error("blank line produced output")
	}
}

func TestResolveAddr(t *testing.T) {
	if a, err := ResolveAddr("10.1.2.3:4000"); err != nil || a != netip.MustParseAddrPort("10.1.2.3:4000") {
		t.Errorf("IP: %v, %v", a, err)
	}
	if a, err := ResolveAddr("[::ffff:10.1.2.3]:4000"); err != nil || a != netip.MustParseAddrPort("10.1.2.3:4000") {
		t.Errorf("mapped IP: %v, %v", a, err)
	}
	if a, err := ResolveAddr("localhost:4000"); err != nil || !a.Addr().IsLoopback() || a.Port() != 4000 {
		t.Errorf("hostname: %v, %v", a, err)
	}
	if _, err := ResolveAddr("no-port"); err == nil {
		t.Error("address without port accepted")
	}
}

func TestListenAddr(t *testing.T) {
	if a, err := ListenAddr("127.0.0.1:4000"); err != nil || a != netip.MustParseAddrPort("127.0.0.1:4000") {
		t.Errorf("explicit IP: %v, %v", a, err)
	}
	a, err := ListenAddr(":4000")
	if err != nil {
		t.Skipf("no usable host IP in this environment: %v", err)
	}
	if a.Port() != 4000 || a.Addr().IsUnspecified() || !a.Addr().Is4() {
		t.Errorf("own IP: %v", a)
	}
	for _, bad := range []string{"4000", ":notaport", ":99999"} {
		if _, err := ListenAddr(bad); err == nil {
			t.Errorf("ListenAddr(%q) accepted", bad)
		}
	}
}

// The bootstrap node comes up after the first attempts have failed.
func TestJoinWithRetry(t *testing.T) {
	sim := network.NewSimNetwork(network.SimConfig{})
	node, _ := kademlia.NewKademlia(sim, addr(1), testCfg)
	defer node.Close()

	go func() {
		time.Sleep(300 * time.Millisecond)
		if b, err := kademlia.NewKademlia(sim, addr(0), testCfg); err == nil {
			t.Cleanup(func() { b.Close() })
		}
	}()
	var out bytes.Buffer
	if err := JoinWithRetry(context.Background(), node, addr(0).String(), 20, 50*time.Millisecond, &out); err != nil {
		t.Fatal(err)
	}
	expect(t, out.String(), "join attempt 1/20 failed")
}

func TestJoinWithRetryGivesUp(t *testing.T) {
	sim := network.NewSimNetwork(network.SimConfig{})
	node, _ := kademlia.NewKademlia(sim, addr(1), testCfg)
	defer node.Close()
	var out bytes.Buffer
	if err := JoinWithRetry(context.Background(), node, addr(0).String(), 2, time.Millisecond, &out); err == nil {
		t.Error("join without a bootstrap node succeeded")
	}
	if err := JoinWithRetry(context.Background(), node, "nosuchhost.invalid:4000", 2, time.Millisecond, &out); err == nil {
		t.Error("join via an unresolvable name succeeded")
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := JoinWithRetry(ctx, node, addr(0).String(), 5, time.Second, &out); err == nil {
		t.Error("cancelled join succeeded")
	}
}

func TestPutGetFile(t *testing.T) {
	nodes := testNetwork(t, 15)
	dir := t.TempDir()
	src, dst := filepath.Join(dir, "lib.jar"), filepath.Join(dir, "copy.jar")
	content := []byte("PK\x03\x04 pretend jar contents")
	os.WriteFile(src, content, 0o644)

	out := run(nodes[2], "put "+src)
	expect(t, out, fmt.Sprintf("stored %d bytes on 10 nodes (0 failed)", len(content)))
	key := kademlia.KeyFromValue(content).String()
	expect(t, out, "key "+key)

	out = run(nodes[11], "get "+key+" "+dst)
	expect(t, out, fmt.Sprintf("saved %d bytes to %s", len(content), dst), "received from ")
	if got, _ := os.ReadFile(dst); !bytes.Equal(got, content) {
		t.Errorf("saved file = %q", got)
	}
	expect(t, run(nodes[11], "get "+strings.ToUpper(key)), "pretend jar contents", "received from ")
}

func TestPutTextAndShowDS(t *testing.T) {
	nodes := testNetwork(t, 1)
	n := nodes[0]
	expect(t, run(n, "puttext hello   world"), "stored 11 bytes on 1 nodes")
	n.DataStore().Put(kademlia.KeyFromValue([]byte{0, 1, 2}), []byte{0, 1, 2})
	long := strings.Repeat("abcdefgh", 10)
	run(n, "puttext "+long)

	out := run(n, "show ds")
	key := kademlia.KeyFromValue([]byte("hello world"))
	expect(t, out, "3 values", key.Short(), "11 bytes", `"hello world"`, "(binary)", `"abcdefghabcdefghabcdefghabcdefgh…"`)
}

func TestPutGetErrors(t *testing.T) {
	nodes := testNetwork(t, 3)
	n := nodes[1]
	expect(t, run(n, "put"), "usage: put FILENAME")
	expect(t, run(n, "put /no/such/file"), "error:")
	expect(t, run(n, "get"), "usage: get KEY")
	expect(t, run(n, "get a b c"), "usage: get KEY")
	expect(t, run(n, "get xyz"), "error:")
	expect(t, run(n, "get "+kademlia.KeyFromValue([]byte("missing")).String()), "value not found")

	run(n, "puttext x")
	key := kademlia.KeyFromValue([]byte("x")).String()
	expect(t, run(n, "get "+key+" /no/such/dir/file"), "error:")
}

// registryNetwork starts n nodes whose holders validate package records,
// and returns the fake DNS and the key that owns demo.test.
func registryNetwork(t *testing.T, n int) ([]*kademlia.Kademlia, *registry.FakeDNS, ed25519.PrivateKey) {
	t.Helper()
	pk, sk, err := registry.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	dns := registry.NewFakeDNS()
	dns.Set("demo.test", pk)
	cfg := testCfg
	cfg.Validator = registry.Validator{Verifier: dns}
	sim := network.NewSimNetwork(network.SimConfig{})
	var nodes []*kademlia.Kademlia
	for i := range n {
		k, err := kademlia.NewKademlia(sim, addr(i), cfg)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { k.Close() })
		if i > 0 {
			if err := k.Join(context.Background(), addr(0)); err != nil {
				t.Fatal(err)
			}
		}
		nodes = append(nodes, k)
	}
	return nodes, dns, sk
}

// registryShell returns a shell on node with a registry client; key may be nil.
func registryShell(node *kademlia.Kademlia, dns *registry.FakeDNS, key ed25519.PrivateKey) (*Shell, *bytes.Buffer) {
	var out bytes.Buffer
	s := NewShell(node, &out)
	s.Registry = registry.NewClient(node, dns, key)
	return s, &out
}

func TestPublishInstallShow(t *testing.T) {
	nodes, dns, sk := registryNetwork(t, 12)
	dir := t.TempDir()
	v1, v2 := filepath.Join(dir, "v1.txt"), filepath.Join(dir, "v2.txt")
	os.WriteFile(v1, []byte("hello, version 1"), 0o644)
	os.WriteFile(v2, []byte("hello, version 2"), 0o644)
	owner, out := registryShell(nodes[1], dns, sk)
	reader, rout := registryShell(nodes[9], dns, nil)

	owner.Execute("publish demo.test:hello:1.0.0 " + v1)
	expect(t, out.String(), "published demo.test:hello 1.0.0", "pointer accepted by 10, refused by 0")
	out.Reset()
	owner.Execute("publish demo.test:hello:1.1.0 " + v2)
	expect(t, out.String(), "published demo.test:hello 1.1.0")

	reader.Execute("install demo.test:hello:latest")
	expect(t, rout.String(), "hello, version 2", "installed demo.test:hello 1.1.0 (latest is 1.1.0)", "received from")
	rout.Reset()
	saved := filepath.Join(dir, "got.txt")
	reader.Execute("install demo.test:hello:1.0.0 " + saved)
	expect(t, rout.String(), "saved 16 bytes", "installed demo.test:hello 1.0.0 (latest is 1.1.0)")
	if data, _ := os.ReadFile(saved); string(data) != "hello, version 1" {
		t.Errorf("saved file = %q", data)
	}
	rout.Reset()
	reader.Execute("show demo.test:hello")
	expect(t, rout.String(), "demo.test:hello: 2 versions", "-> 1.1.0", "   1.0.0", "signature ok")
	rout.Reset()
	reader.Execute("show dns demo.test")
	expect(t, rout.String(), "demo.test is owned by", "kademlia-pk=ed25519:")
	rout.Reset()
	reader.Execute("show dns nobody.test")
	expect(t, rout.String(), "error:", "no owner key")

	// show ds decodes pointers and records on the nodes that hold them
	// (the pointer and a record live under different keys, so usually on
	// different nodes).
	chain, err := reader.Registry.Chain(context.Background(), "demo.test", "hello")
	if err != nil {
		t.Fatal(err)
	}
	var sawPointer, sawRecord bool
	for _, n := range nodes {
		if n.DataStore().IsMutable(registry.LatestKey("demo.test", "hello")) && !sawPointer {
			expect(t, run(n, "show ds"), "latest  demo.test:hello -> 1.1.0 (record")
			sawPointer = true
		}
		if _, ok := n.DataStore().Get(chain[0].RecordKey); ok && !sawRecord {
			expect(t, run(n, "show ds"), "record  demo.test:hello 1.1.0 -> blob")
			sawRecord = true
		}
	}
	if !sawPointer || !sawRecord {
		t.Errorf("no node holds the pointer (%v) or the record (%v)", sawPointer, sawRecord)
	}
}

func TestPublishFlagsAndErrors(t *testing.T) {
	nodes, dns, sk := registryNetwork(t, 12)
	dir := t.TempDir()
	v1 := filepath.Join(dir, "v1.txt")
	os.WriteFile(v1, []byte("one"), 0o644)
	owner, out := registryShell(nodes[1], dns, sk)
	owner.Execute("publish demo.test:hello:1.0.0 " + v1)
	owner.Execute("publish demo.test:hello:1.1.0 " + v1)
	out.Reset()

	cases := map[string][]string{
		"publish":                       {"usage: publish"},
		"publish demo.test:hello:1.2.0": {"usage: publish"},
		"publish --bogus demo.test:hello:1.2.0 " + v1:              {"unknown flag"},
		"publish --prev=x demo.test:hello:1.2.0 " + v1:             {"want MAJOR.MINOR.PATCH"},
		"publish demo.test:hello " + v1:                            {"want DOMAIN:PACKAGE:VERSION"},
		"publish demo.test:hello:1.2.0 /no/such/file":              {"no such file"},
		"publish demo.test:hello:1.0.5 " + v1:                      {"not newer"},
		"publish --prev=1.0.0 demo.test:hello:1.2.0 " + v1:         {"forks", "1.0.0 is not the latest"},
		"publish --force --prev=1.0.0 demo.test:hello:1.2.0 " + v1: {"refused by 10", "fork"},
		"publish --force demo.test:hello:0.9.0 " + v1:              {"refused by 10", "not newer", "error:"},
		"install":                                       {"usage: install"},
		"install demo.test:hello":                       {"want DOMAIN:PACKAGE:VERSION"},
		"install demo.test:nothing:latest":              {"no such package"},
		"install demo.test:hello:9.9.9":                 {"no such version"},
		"install demo.test:hello:latest /no/such/dir/x": {"no such file or directory"},
		"show":                   {"usage: show"},
		"show dns":               {"usage: show"},
		"show demo.test":         {"usage: show"},
		"show de:mo:x":           {"want DOMAIN:PACKAGE"},
		"show demo.test:nothing": {"no such package"},
	}
	for line, wants := range cases {
		out.Reset()
		owner.Execute(line)
		expect(t, out.String(), wants...)
	}
	// After all that, latest is still 1.1.0.
	out.Reset()
	owner.Execute("install demo.test:hello:latest")
	expect(t, out.String(), "installed demo.test:hello 1.1.0")

	// A node without a signing key cannot publish; one without a registry
	// has none of the commands.
	noKey, nout := registryShell(nodes[2], dns, nil)
	noKey.Execute("publish demo.test:hello:1.2.0 " + v1)
	expect(t, nout.String(), "no signing key")
	expect(t, run(nodes[3], "publish demo.test:hello:1.2.0 "+v1), "no registry")
	expect(t, run(nodes[3], "install demo.test:hello:latest"), "no registry")
	expect(t, run(nodes[3], "show demo.test:hello"), "no registry")
	expect(t, run(nodes[3], "show dns demo.test"), "no registry")
	expect(t, run(nodes[3], "help"), "publish [--force]", "show dns DOMAIN")
}

func TestNewVerifierAndKeygen(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "owner.pem")
	var out bytes.Buffer
	if err := Keygen(keyPath, &out); err != nil {
		t.Fatal(err)
	}
	expect(t, out.String(), "private key saved to "+keyPath, "kademlia-pk=ed25519:")
	sk, err := registry.LoadKey(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	txt := registry.EncodePublicKey(sk.Public().(ed25519.PublicKey))
	if !strings.Contains(out.String(), txt) {
		t.Error("keygen did not print the key's TXT record")
	}
	if err := Keygen(filepath.Join(dir, "missing", "x.pem"), &out); err == nil {
		t.Error("keygen into a missing directory succeeded")
	}

	dnsPath := filepath.Join(dir, "dns.txt")
	os.WriteFile(dnsPath, []byte("demo.test "+txt+"\n"), 0o644)
	v, err := NewVerifier(dnsPath)
	if err != nil {
		t.Fatal(err)
	}
	if pk, err := v.OwnerKey(context.Background(), "demo.test"); err != nil || !pk.Equal(sk.Public().(ed25519.PublicKey)) {
		t.Errorf("fake DNS from file: %x, %v", pk, err)
	}
	if _, err := NewVerifier(filepath.Join(dir, "nope.txt")); err == nil {
		t.Error("a missing dns file was accepted")
	}
	if _, ok := must(NewVerifier("")).(*registry.DNSVerifier); !ok {
		t.Error("an empty -dns does not use real DNS")
	}
}

func must[T any](v T, err error) T {
	if err != nil {
		panic(err)
	}
	return v
}
