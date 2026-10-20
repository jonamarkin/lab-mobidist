package registry

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
)

func TestFakeDNS(t *testing.T) {
	ctx := context.Background()
	pk1, sk1 := testKey(11)
	pk2, _ := testKey(12)
	f := NewFakeDNS()
	if _, err := f.OwnerKey(ctx, "rfin.ch"); !errors.Is(err, ErrNoKey) {
		t.Fatalf("empty table: err = %v, want ErrNoKey", err)
	}
	f.Set("rfin.ch", pk1)
	f.Set("other.se", pk2)
	got, err := f.OwnerKey(ctx, "rfin.ch")
	if err != nil || !got.Equal(pk1) {
		t.Fatalf("OwnerKey = %x, %v", got, err)
	}
	// The table hands out copies: a caller cannot corrupt it.
	got[0] ^= 1
	if again, _ := f.OwnerKey(ctx, "rfin.ch"); !again.Equal(pk1) {
		t.Error("the stored key was modified through the returned slice")
	}
	if d := f.Domains(); !slices.Equal(d, []string{"other.se", "rfin.ch"}) {
		t.Errorf("Domains = %v", d)
	}
	// The key it returns verifies what the matching private key signed.
	r := sampleRecord()
	r.Sign(sk1)
	if fresh, _ := f.OwnerKey(ctx, "rfin.ch"); !r.Verify(fresh) {
		t.Error("record signed by the owner did not verify with the looked-up key")
	}

	// Concurrent readers and writers: checked by -race.
	var wg sync.WaitGroup
	for i := range 8 {
		wg.Go(func() {
			if i%2 == 0 {
				f.Set("rfin.ch", pk1)
			} else {
				f.OwnerKey(ctx, "rfin.ch")
			}
		})
	}
	wg.Wait()
}

func TestFakeDNSLoad(t *testing.T) {
	pk1, _ := testKey(13)
	pk2, _ := testKey(14)
	text := "# demo domains\n\n" +
		"demo.test   " + EncodePublicKey(pk1) + "\n" +
		"  other.test " + EncodePublicKey(pk2) + "   \n"
	f := NewFakeDNS()
	if err := f.Load(strings.NewReader(text)); err != nil {
		t.Fatal(err)
	}
	if got, _ := f.OwnerKey(context.Background(), "other.test"); !got.Equal(pk2) {
		t.Error("other.test has the wrong key")
	}
	if len(f.Domains()) != 2 {
		t.Errorf("Domains = %v", f.Domains())
	}

	bad := map[string]string{
		"one field":     "demo.test\n",
		"three fields":  "demo.test " + EncodePublicKey(pk1) + " extra\n",
		"bad name":      "de:mo " + EncodePublicKey(pk1) + "\n",
		"not our txt":   "demo.test v=spf1\n",
		"broken key":    "demo.test kademlia-pk=ed25519:AAAA\n",
		"bad on line 3": "# c\ndemo.test " + EncodePublicKey(pk1) + "\nx\n",
	}
	for name, in := range bad {
		err := NewFakeDNS().Load(strings.NewReader(in))
		if err == nil {
			t.Errorf("%s: loaded without error", name)
		} else if name == "bad on line 3" && !strings.Contains(err.Error(), "line 3") {
			t.Errorf("%s: error does not name the line: %v", name, err)
		}
	}

	dir := t.TempDir()
	path := filepath.Join(dir, "dns.txt")
	os.WriteFile(path, []byte(text), 0o644)
	g := NewFakeDNS()
	if err := g.LoadFile(path); err != nil || len(g.Domains()) != 2 {
		t.Errorf("LoadFile: %v, %v", err, g.Domains())
	}
	if err := g.LoadFile(filepath.Join(dir, "missing.txt")); err == nil {
		t.Error("LoadFile of a missing file succeeded")
	}
	os.WriteFile(path, []byte("broken\n"), 0o644)
	if err := g.LoadFile(path); err == nil || !strings.Contains(err.Error(), "dns.txt") {
		t.Errorf("LoadFile of a broken file: %v", err)
	}
}

// fakeLookup returns a LookupTXT function that serves fixed records.
func fakeLookup(records map[string][]string, failure error) func(context.Context, string) ([]string, error) {
	return func(_ context.Context, name string) ([]string, error) {
		if failure != nil {
			return nil, failure
		}
		return records[name], nil
	}
}

func TestDNSVerifier(t *testing.T) {
	ctx := context.Background()
	pk, _ := testKey(15)
	records := map[string][]string{
		"rfin.ch":   {"v=spf1 -all", "google-site-verification=abc", EncodePublicKey(pk)},
		"nokey.ch":  {"v=spf1 -all"},
		"broken.ch": {"kademlia-pk=ed25519:AAAA", EncodePublicKey(pk)},
		"empty.ch":  {},
	}
	d := &DNSVerifier{LookupTXT: fakeLookup(records, nil)}

	got, err := d.OwnerKey(ctx, "rfin.ch")
	if err != nil || !got.Equal(pk) {
		t.Fatalf("rfin.ch: %x, %v", got, err)
	}
	for _, domain := range []string{"nokey.ch", "empty.ch", "unknown.ch", "broken.ch"} {
		if _, err := d.OwnerKey(ctx, domain); !errors.Is(err, ErrNoKey) || errors.Is(err, ErrLookup) {
			t.Errorf("%s: err = %v, want ErrNoKey", domain, err)
		}
	}

	// NXDOMAIN is "no key"; any other resolver failure is a lookup error.
	notFound := &net.DNSError{Err: "no such host", Name: "gone.ch", IsNotFound: true}
	d.LookupTXT = fakeLookup(nil, notFound)
	if _, err := d.OwnerKey(ctx, "gone.ch"); !errors.Is(err, ErrNoKey) {
		t.Errorf("NXDOMAIN: err = %v, want ErrNoKey", err)
	}
	timeout := &net.DNSError{Err: "i/o timeout", Name: "rfin.ch", IsTimeout: true}
	d.LookupTXT = fakeLookup(nil, timeout)
	_, err = d.OwnerKey(ctx, "rfin.ch")
	if !errors.Is(err, ErrLookup) || errors.Is(err, ErrNoKey) || !errors.Is(err, timeout) {
		t.Errorf("timeout: err = %v, want ErrLookup wrapping the cause", err)
	}
	d.LookupTXT = fakeLookup(nil, errors.New("no resolver"))
	if _, err := d.OwnerKey(ctx, "rfin.ch"); !errors.Is(err, ErrLookup) {
		t.Errorf("generic failure: err = %v, want ErrLookup", err)
	}
}

func TestNewDNSVerifierUsesResolver(t *testing.T) {
	if NewDNSVerifier().LookupTXT == nil {
		t.Fatal("no lookup function")
	}
	// Both implementations satisfy the interface (compile-time check).
	var _ Verifier = NewFakeDNS()
	var _ Verifier = NewDNSVerifier()
}
