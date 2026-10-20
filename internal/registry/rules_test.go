package registry

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"sync"
	"testing"

	"github.com/jonamarkin/lab-mobidist/internal/kademlia"
)

// memStore stands in for the DHT: a map of key -> bytes, and a log of
// what was fetched, so tests can see which records a validation needed.
type memStore struct {
	mu      sync.Mutex
	values  map[kademlia.KademliaID][]byte
	fetched []kademlia.KademliaID
}

func newMemStore() *memStore { return &memStore{values: make(map[kademlia.KademliaID][]byte)} }

func (m *memStore) put(b []byte) kademlia.KademliaID {
	m.mu.Lock()
	defer m.mu.Unlock()
	k := kademlia.KeyFromValue(b)
	m.values[k] = b
	return k
}

func (m *memStore) fetch(_ context.Context, key kademlia.KademliaID) ([]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.fetched = append(m.fetched, key)
	b, ok := m.values[key]
	if !ok {
		return nil, errors.New("not found")
	}
	return b, nil
}

// fixture is a domain owner, a fake DNS that knows them, and a store.
type fixture struct {
	pk    ed25519.PublicKey
	sk    ed25519.PrivateKey
	dns   *FakeDNS
	store *memStore
	rules *Rules
}

func newFixture(seed byte) *fixture {
	pk, sk := testKey(seed)
	dns := NewFakeDNS()
	dns.Set("rfin.ch", pk)
	store := newMemStore()
	return &fixture{pk: pk, sk: sk, dns: dns, store: store, rules: NewRules(dns, store.fetch)}
}

// chain publishes records for the given versions of rfin.ch:java-pair,
// each linked to the previous, signed with sk, and stored. It returns
// the records and their keys, oldest first.
func (f *fixture) chain(sk ed25519.PrivateKey, versions ...string) ([]VersionRecord, []kademlia.KademliaID) {
	var recs []VersionRecord
	var keys []kademlia.KademliaID
	prev := ZeroHash
	for i, s := range versions {
		v, err := ParseVersion(s)
		if err != nil {
			panic(err)
		}
		blob := kademlia.KeyFromValue(fmt.Appendf(nil, "blob %d", i))
		rec := NewVersionRecord("rfin.ch", "java-pair", v, blob, prev)
		rec.Sign(sk)
		key := f.store.put(rec.Encode())
		recs = append(recs, rec)
		keys = append(keys, key)
		prev = key
	}
	return recs, keys
}

// pointer returns the signed, encoded latest pointer for rec.
func (f *fixture) pointer(sk ed25519.PrivateKey, rec VersionRecord, key kademlia.KademliaID) []byte {
	p := NewLatestPointer(rec.Domain, rec.Package, rec.Version, key)
	p.Sign(sk)
	return p.Encode()
}

var latest = LatestKey("rfin.ch", "java-pair")

func TestValidateUpdateAccepts(t *testing.T) {
	ctx := context.Background()
	f := newFixture(21)
	recs, keys := f.chain(f.sk, "1.0.0", "1.1.0", "1.2.0", "2.0.0")

	// A first version, with no current pointer.
	p, err := f.rules.ValidateUpdate(ctx, latest, f.pointer(f.sk, recs[0], keys[0]), nil)
	if err != nil || p.Version != recs[0].Version {
		t.Fatalf("first version: %v", err)
	}
	// The next version, with the previous one current: only the new
	// record is fetched, since its prev is the trusted record.
	f.store.fetched = nil
	cur := f.pointer(f.sk, recs[0], keys[0])
	if _, err := f.rules.ValidateUpdate(ctx, latest, f.pointer(f.sk, recs[1], keys[1]), cur); err != nil {
		t.Fatalf("second version: %v", err)
	}
	if len(f.store.fetched) != 1 || f.store.fetched[0] != keys[1] {
		t.Errorf("fetched %v, want only the new record", f.store.fetched)
	}
	// Catching up: current is 1.0.0, the new pointer is 2.0.0. The two
	// versions in between are fetched and checked on the way down.
	f.store.fetched = nil
	if _, err := f.rules.ValidateUpdate(ctx, latest, f.pointer(f.sk, recs[3], keys[3]), cur); err != nil {
		t.Fatalf("catch-up: %v", err)
	}
	want := []kademlia.KademliaID{keys[3], keys[2], keys[1]}
	if fmt.Sprint(f.store.fetched) != fmt.Sprint(want) {
		t.Errorf("catch-up fetched %v, want %v", f.store.fetched, want)
	}
	// A new holder (no current) walks the whole chain to the first version.
	f.store.fetched = nil
	if _, err := f.rules.ValidateUpdate(ctx, latest, f.pointer(f.sk, recs[3], keys[3]), nil); err != nil {
		t.Fatalf("new holder: %v", err)
	}
	if len(f.store.fetched) != 4 {
		t.Errorf("new holder fetched %d records, want 4", len(f.store.fetched))
	}
}

func TestValidateUpdateRefuses(t *testing.T) {
	ctx := context.Background()
	f := newFixture(22)
	_, otherSK := testKey(23)
	recs, keys := f.chain(f.sk, "1.0.0", "1.1.0", "1.2.0")
	current := f.pointer(f.sk, recs[1], keys[1]) // the holder is at 1.1.0

	// A fork: 1.3.0 whose prev is 1.0.0, bypassing the current 1.1.0.
	forkRec := NewVersionRecord("rfin.ch", "java-pair", Version{1, 3, 0}, kademlia.KeyFromValue([]byte("fork")), keys[0])
	forkRec.Sign(f.sk)
	forkKey := f.store.put(forkRec.Encode())
	// A fork at the same version: a second, different 1.1.0 record.
	twinRec := NewVersionRecord("rfin.ch", "java-pair", Version{1, 1, 0}, kademlia.KeyFromValue([]byte("twin")), keys[0])
	twinRec.Sign(f.sk)
	twinKey := f.store.put(twinRec.Encode())
	onTwin := NewVersionRecord("rfin.ch", "java-pair", Version{1, 2, 0}, kademlia.KeyFromValue([]byte("on twin")), twinKey)
	onTwin.Sign(f.sk)
	onTwinKey := f.store.put(onTwin.Encode())
	// A fresh start: a 3.0.0 with prev = 0, ignoring the history.
	freshRec := NewVersionRecord("rfin.ch", "java-pair", Version{3, 0, 0}, kademlia.KeyFromValue([]byte("fresh")), ZeroHash)
	freshRec.Sign(f.sk)
	freshKey := f.store.put(freshRec.Encode())
	// A record signed by someone else, properly chained.
	impostor := NewVersionRecord("rfin.ch", "java-pair", Version{1, 3, 0}, kademlia.KeyFromValue([]byte("imp")), keys[2])
	impostor.Sign(otherSK)
	impostorKey := f.store.put(impostor.Encode())
	// A record whose prev has a higher version, and one of another package.
	backwards := NewVersionRecord("rfin.ch", "java-pair", Version{1, 3, 0}, kademlia.KeyFromValue([]byte("b")), keys[2])
	backwards.Version = Version{1, 0, 5} // lower than its prev 1.2.0
	backwards.Sign(f.sk)
	backwardsKey := f.store.put(backwards.Encode())
	otherPkg := NewVersionRecord("rfin.ch", "java-pear", Version{0, 1, 0}, kademlia.KeyFromValue([]byte("o")), ZeroHash)
	otherPkg.Sign(f.sk)
	otherPkgKey := f.store.put(otherPkg.Encode())
	crossPkg := NewVersionRecord("rfin.ch", "java-pair", Version{1, 3, 0}, kademlia.KeyFromValue([]byte("c")), otherPkgKey)
	crossPkg.Sign(f.sk)
	crossPkgKey := f.store.put(crossPkg.Encode())
	// A pointer whose record is not stored anywhere.
	missing := NewVersionRecord("rfin.ch", "java-pair", Version{1, 3, 0}, kademlia.KeyFromValue([]byte("m")), keys[2])
	missing.Sign(f.sk)

	// Mismatching pointers: the version, or the package, differs from the record.
	wrongVersion := NewLatestPointer("rfin.ch", "java-pair", Version{9, 9, 9}, keys[2])
	wrongVersion.Sign(f.sk)
	wrongPkg := NewLatestPointer("rfin.ch", "java-pear", Version{1, 2, 0}, keys[2])
	wrongPkg.Sign(f.sk)
	// A valid pointer, but signed by someone else.
	impostorPtr := NewLatestPointer("rfin.ch", "java-pair", Version{1, 2, 0}, keys[2])
	impostorPtr.Sign(otherSK)
	// A pointer with no signature: not well formed.
	unsigned := NewLatestPointer("rfin.ch", "java-pair", Version{1, 2, 0}, keys[2])

	cases := []struct {
		name    string
		key     kademlia.KademliaID
		value   []byte
		current []byte
		want    error
	}{
		{"rollback", latest, f.pointer(f.sk, recs[0], keys[0]), current, ErrNotNewer},
		{"same version", latest, f.pointer(f.sk, recs[1], keys[1]), current, ErrNotNewer},
		{"same version, different record", latest, f.pointer(f.sk, twinRec, twinKey), current, ErrNotNewer},
		{"fork past the current version", latest, f.pointer(f.sk, forkRec, forkKey), current, ErrFork},
		{"fork through a twin", latest, f.pointer(f.sk, onTwin, onTwinKey), current, ErrFork},
		{"fresh start ignoring history", latest, f.pointer(f.sk, freshRec, freshKey), current, ErrFork},
		{"record by an impostor", latest, f.pointer(f.sk, impostor, impostorKey), current, ErrNotOwner},
		{"pointer by an impostor", latest, impostorPtr.Encode(), current, ErrNotOwner},
		{"unsigned pointer", latest, unsigned.Encode(), current, ErrBadRecord},
		{"garbage", latest, []byte("hello"), current, ErrBadRecord},
		{"wrong key", LatestKey("rfin.ch", "java-pear"), f.pointer(f.sk, recs[2], keys[2]), nil, ErrWrongKey},
		{"version mismatch", latest, wrongVersion.Encode(), nil, ErrMismatch},
		{"package mismatch", wrongPkg.Key(), wrongPkg.Encode(), nil, ErrMismatch},
		{"missing record", latest, f.pointer(f.sk, missing, missing.Key()), current, ErrUnavailable},
		{"prev with a higher version", latest, f.pointer(f.sk, backwards, backwardsKey), nil, ErrBadChain},
		{"prev of another package", latest, f.pointer(f.sk, crossPkg, crossPkgKey), nil, ErrBadChain},
	}
	for _, c := range cases {
		_, err := f.rules.ValidateUpdate(ctx, c.key, c.value, c.current)
		if !errors.Is(err, c.want) {
			t.Errorf("%s: err = %v, want %v", c.name, err, c.want)
		}
	}
	// The sane update still passes after all that noise.
	if _, err := f.rules.ValidateUpdate(ctx, latest, f.pointer(f.sk, recs[2], keys[2]), current); err != nil {
		t.Errorf("a valid update was refused: %v", err)
	}
}

func TestValidateUpdateOwnerLookup(t *testing.T) {
	ctx := context.Background()
	f := newFixture(24)
	recs, keys := f.chain(f.sk, "1.0.0")
	value := f.pointer(f.sk, recs[0], keys[0])

	// No key for the domain: not the owner (whoever signed it).
	noKey := NewFakeDNS()
	_, err := NewRules(noKey, f.store.fetch).ValidateUpdate(ctx, latest, value, nil)
	if !errors.Is(err, ErrNotOwner) || !errors.Is(err, ErrNoKey) {
		t.Errorf("no key: err = %v", err)
	}
	// DNS down: also refused, but the cause says so.
	down := &DNSVerifier{LookupTXT: fakeLookup(nil, errors.New("resolver down"))}
	_, err = NewRules(down, f.store.fetch).ValidateUpdate(ctx, latest, value, nil)
	if !errors.Is(err, ErrNotOwner) || !errors.Is(err, ErrLookup) {
		t.Errorf("DNS down: err = %v", err)
	}
	// One lookup per domain per validation, however long the chain.
	count := 0
	counting := &DNSVerifier{LookupTXT: func(ctx context.Context, name string) ([]string, error) {
		count++
		return []string{EncodePublicKey(f.pk)}, nil
	}}
	recs, keys = f.chain(f.sk, "1.0.0", "1.1.0", "1.2.0", "1.3.0", "1.4.0")
	if _, err := NewRules(counting, f.store.fetch).ValidateUpdate(ctx, latest, f.pointer(f.sk, recs[4], keys[4]), nil); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Errorf("%d owner-key lookups for one validation, want 1", count)
	}
}

func TestValidateUpdateChainLimit(t *testing.T) {
	ctx := context.Background()
	f := newFixture(25)
	recs, keys := f.chain(f.sk, "1.0.0", "1.1.0", "1.2.0", "1.3.0")
	f.rules.MaxChain = 2
	_, err := f.rules.ValidateUpdate(ctx, latest, f.pointer(f.sk, recs[3], keys[3]), nil)
	if !errors.Is(err, ErrChainTooLong) {
		t.Errorf("err = %v, want ErrChainTooLong", err)
	}
	// With a trusted anchor two steps down, the same chain fits the limit.
	cur := f.pointer(f.sk, recs[1], keys[1])
	if _, err := f.rules.ValidateUpdate(ctx, latest, f.pointer(f.sk, recs[3], keys[3]), cur); err != nil {
		t.Errorf("anchored update: %v", err)
	}
}

func TestValidateUpdateCorruptCurrent(t *testing.T) {
	// A current value that does not decode cannot constrain the update:
	// it is treated as absent rather than blocking the key forever.
	ctx := context.Background()
	f := newFixture(26)
	recs, keys := f.chain(f.sk, "1.0.0")
	if _, err := f.rules.ValidateUpdate(ctx, latest, f.pointer(f.sk, recs[0], keys[0]), []byte("corrupt")); err != nil {
		t.Errorf("err = %v", err)
	}
}

func TestValidateRecordAndPointer(t *testing.T) {
	ctx := context.Background()
	f := newFixture(27)
	_, otherSK := testKey(28)
	recs, keys := f.chain(f.sk, "1.0.0", "1.1.0")

	if err := f.rules.ValidateRecord(ctx, recs[1]); err != nil {
		t.Errorf("ValidateRecord: %v", err)
	}
	bad := recs[1]
	bad.Sign(otherSK)
	if err := f.rules.ValidateRecord(ctx, bad); !errors.Is(err, ErrNotOwner) {
		t.Errorf("ValidateRecord of an impostor's record: %v", err)
	}
	unsigned := recs[1]
	unsigned.Sig = nil
	if err := f.rules.ValidateRecord(ctx, unsigned); !errors.Is(err, ErrBadRecord) {
		t.Errorf("ValidateRecord of an unsigned record: %v", err)
	}
	// A fetched value whose hash is not the requested key is unusable.
	orphan := recs[1]
	orphan.Prev = kademlia.KeyFromValue([]byte("nowhere"))
	orphan.Sign(f.sk)
	f.store.mu.Lock()
	f.store.values[orphan.Prev] = recs[0].Encode() // right record, wrong key
	f.store.mu.Unlock()
	if err := f.rules.ValidateRecord(ctx, orphan); !errors.Is(err, ErrUnavailable) {
		t.Errorf("ValidateRecord with a mismatching fetch: %v", err)
	}
	// A prev that is stored, but is not a version record at all.
	garbage := recs[1]
	garbage.Prev = f.store.put([]byte("not a record"))
	garbage.Sign(f.sk)
	if err := f.rules.ValidateRecord(ctx, garbage); !errors.Is(err, ErrBadRecord) {
		t.Errorf("ValidateRecord with a non-record prev: %v", err)
	}

	p := NewLatestPointer("rfin.ch", "java-pair", recs[1].Version, keys[1])
	p.Sign(f.sk)
	rec, err := f.rules.ValidatePointer(ctx, latest, p)
	if err != nil || rec.Version != recs[1].Version {
		t.Errorf("ValidatePointer = %v, %v", rec.Version, err)
	}
	if _, err := f.rules.ValidatePointer(ctx, LatestKey("x.ch", "y"), p); !errors.Is(err, ErrWrongKey) {
		t.Errorf("ValidatePointer under another key: %v", err)
	}
}
