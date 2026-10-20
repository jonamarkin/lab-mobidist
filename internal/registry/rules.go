package registry

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"

	"github.com/jonamarkin/lab-mobidist/internal/kademlia"
)

// The validation rules of the registry (PART2-DESIGN). They decide whether
// a version record is valid and whether a new latest pointer may replace
// a holder's current one: only the domain owner may publish, history is
// never forked, and "latest" never moves backwards. A node that holds a
// pointer enforces them before storing an update; a publisher checks them
// before uploading; a reader checks what it fetched.

// Why an update is refused. Every error returned by the rules wraps one
// of these, so callers can use errors.Is and holders can report a reason.
var (
	ErrBadRecord    = errors.New("registry: malformed record")
	ErrWrongKey     = errors.New("registry: pointer stored under the wrong key")
	ErrNotOwner     = errors.New("registry: not signed by the domain owner")
	ErrUnavailable  = errors.New("registry: record could not be fetched")
	ErrMismatch     = errors.New("registry: pointer and record disagree")
	ErrBadChain     = errors.New("registry: broken version chain")
	ErrNotNewer     = errors.New("registry: version is not newer than the current one")
	ErrFork         = errors.New("registry: update forks the version history")
	ErrChainTooLong = errors.New("registry: version chain too long")
)

// FetchFunc returns the value stored under key: from the local store, the
// DHT, or a test's map. It is how the rules read records they do not have.
type FetchFunc func(ctx context.Context, key kademlia.KademliaID) ([]byte, error)

// DefaultMaxChain bounds how many records one validation walks through.
// A chain cannot loop (versions strictly decrease along it), so this only
// limits the work a very long history can cause.
const DefaultMaxChain = 10000

// Rules validates records and pointer updates.
type Rules struct {
	Verifier Verifier
	Fetch    FetchFunc
	MaxChain int // 0 means DefaultMaxChain
}

// NewRules returns rules that find owner keys with v and records with fetch.
func NewRules(v Verifier, fetch FetchFunc) *Rules {
	return &Rules{Verifier: v, Fetch: fetch}
}

// walk is the state of one validation: an owner-key cache, so a chain of
// records from one domain costs one DNS lookup, and a step budget.
type walk struct {
	rules *Rules
	keys  map[string]ed25519.PublicKey
	steps int
}

func (r *Rules) newWalk() *walk {
	return &walk{rules: r, keys: make(map[string]ed25519.PublicKey)}
}

// ownerKey returns the owner key of domain, cached for this walk.
func (w *walk) ownerKey(ctx context.Context, domain string) (ed25519.PublicKey, error) {
	if pk, ok := w.keys[domain]; ok {
		return pk, nil
	}
	pk, err := w.rules.Verifier.OwnerKey(ctx, domain)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrNotOwner, err)
	}
	w.keys[domain] = pk
	return pk, nil
}

// checkRecord verifies that rec is well formed and signed by its domain's
// owner (rules 1 and 2 for records).
func (w *walk) checkRecord(ctx context.Context, rec VersionRecord) error {
	if err := wellFormed(rec.Tag, TagVersionRecord, rec.Domain, rec.Package, rec.Sig); err != nil {
		return fmt.Errorf("%w: %w", ErrBadRecord, err)
	}
	pk, err := w.ownerKey(ctx, rec.Domain)
	if err != nil {
		return err
	}
	if !rec.Verify(pk) {
		return fmt.Errorf("%w: record %s %s %v", ErrNotOwner, rec.Domain, rec.Package, rec.Version)
	}
	return nil
}

// fetchRecord fetches and decodes the record stored under key, checking
// that the bytes really hash to key (a fetch function need not).
func (w *walk) fetchRecord(ctx context.Context, key kademlia.KademliaID) (VersionRecord, error) {
	b, err := w.rules.Fetch(ctx, key)
	if err != nil {
		return VersionRecord{}, fmt.Errorf("%w: %s: %w", ErrUnavailable, key.Short(), err)
	}
	if kademlia.KeyFromValue(b) != key {
		return VersionRecord{}, fmt.Errorf("%w: value for %s has a different hash", ErrUnavailable, key.Short())
	}
	rec, err := DecodeVersionRecord(b)
	if err != nil {
		return VersionRecord{}, fmt.Errorf("%w: %w", ErrBadRecord, err)
	}
	return rec, nil
}

// anchor is the record a holder already trusts: its current pointer's.
type anchor struct {
	key     kademlia.KademliaID
	version Version
}

// validateChain checks rec and the records before it. With no anchor it
// walks back to the first version. With an anchor it walks until a prev
// link reaches the anchor (the update extends the trusted history) and
// reports a fork if the chain ends or passes the anchor's version first.
func (w *walk) validateChain(ctx context.Context, rec VersionRecord, a *anchor) error {
	max := w.rules.MaxChain
	if max <= 0 {
		max = DefaultMaxChain
	}
	cur := rec
	for {
		if w.steps++; w.steps > max {
			return fmt.Errorf("%w: more than %d records", ErrChainTooLong, max)
		}
		if err := w.checkRecord(ctx, cur); err != nil {
			return err
		}
		if a != nil {
			if cur.Version.Compare(a.version) <= 0 {
				// We are at or below the trusted version without having
				// passed through the trusted record: a parallel history.
				return fmt.Errorf("%w: %v is not an ancestor of %v", ErrFork, a.version, rec.Version)
			}
			if cur.Prev == a.key {
				return nil // the chain continues from the trusted record
			}
		}
		if cur.Prev == ZeroHash {
			if a != nil {
				return fmt.Errorf("%w: chain of %v starts over", ErrFork, rec.Version)
			}
			return nil // the first version: the whole chain checked out
		}
		prev, err := w.fetchRecord(ctx, cur.Prev)
		if err != nil {
			return err
		}
		if prev.Domain != cur.Domain || prev.Package != cur.Package {
			return fmt.Errorf("%w: %v links to a record of %s:%s", ErrBadChain, cur.Version, prev.Domain, prev.Package)
		}
		if !prev.Version.Less(cur.Version) {
			return fmt.Errorf("%w: %v links to %v, which is not lower", ErrBadChain, cur.Version, prev.Version)
		}
		cur = prev
	}
}

// ValidateRecord reports whether rec is a valid version record: well
// formed, signed by its domain's owner, and chained through valid records
// of the same package with strictly lower versions down to a first
// version. Records not at hand are fetched.
func (r *Rules) ValidateRecord(ctx context.Context, rec VersionRecord) error {
	return r.newWalk().validateChain(ctx, rec, nil)
}

// ValidatePointer checks a pointer stored under key against rules 1 to 3:
// the key is the package's latest key, the owner signed it, and its record
// exists, is signed by the owner, and names the same package and version.
// It returns that record. The record's chain is not checked here.
func (r *Rules) ValidatePointer(ctx context.Context, key kademlia.KademliaID, p LatestPointer) (VersionRecord, error) {
	return r.newWalk().checkPointer(ctx, key, p)
}

func (w *walk) checkPointer(ctx context.Context, key kademlia.KademliaID, p LatestPointer) (VersionRecord, error) {
	if err := wellFormed(p.Tag, TagLatestPointer, p.Domain, p.Package, p.Sig); err != nil {
		return VersionRecord{}, fmt.Errorf("%w: %w", ErrBadRecord, err)
	}
	if key != LatestKey(p.Domain, p.Package) {
		return VersionRecord{}, fmt.Errorf("%w: pointer for %s:%s", ErrWrongKey, p.Domain, p.Package)
	}
	pk, err := w.ownerKey(ctx, p.Domain)
	if err != nil {
		return VersionRecord{}, err
	}
	if !p.Verify(pk) {
		return VersionRecord{}, fmt.Errorf("%w: pointer %s:%s %v", ErrNotOwner, p.Domain, p.Package, p.Version)
	}
	rec, err := w.fetchRecord(ctx, p.Record)
	if err != nil {
		return VersionRecord{}, err
	}
	if rec.Domain != p.Domain || rec.Package != p.Package || rec.Version != p.Version {
		return VersionRecord{}, fmt.Errorf("%w: pointer says %s:%s %v, record says %s:%s %v",
			ErrMismatch, p.Domain, p.Package, p.Version, rec.Domain, rec.Package, rec.Version)
	}
	if err := w.checkRecord(ctx, rec); err != nil {
		return VersionRecord{}, err
	}
	return rec, nil
}

// ValidateUpdate decides whether newValue may be stored under key as the
// latest pointer, given the holder's current value (nil if none). It
// returns the decoded new pointer. Beyond ValidatePointer, the new
// version must be higher than the current one, and the current record
// must be an ancestor of the new one; records on the way that the holder
// has not seen are fetched (catching up).
func (r *Rules) ValidateUpdate(ctx context.Context, key kademlia.KademliaID, newValue, current []byte) (LatestPointer, error) {
	p, err := DecodeLatestPointer(newValue)
	if err != nil {
		return LatestPointer{}, fmt.Errorf("%w: %w", ErrBadRecord, err)
	}
	w := r.newWalk()
	rec, err := w.checkPointer(ctx, key, p)
	if err != nil {
		return p, err
	}
	var a *anchor
	if current != nil {
		// Our own stored value passed these rules when it was stored, so
		// it decodes; if it somehow does not, it cannot constrain anything.
		if cur, err := DecodeLatestPointer(current); err == nil {
			if p.Version.Compare(cur.Version) <= 0 {
				return p, fmt.Errorf("%w: %v, current is %v", ErrNotNewer, p.Version, cur.Version)
			}
			a = &anchor{key: cur.Record, version: cur.Version}
		}
	}
	return p, w.validateChain(ctx, rec, a)
}
