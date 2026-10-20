package registry

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"log/slog"

	"github.com/jonamarkin/lab-mobidist/internal/kademlia"
)

// Client is the registry seen from one node: it publishes packages,
// installs them, and shows a package's history. Every value it uses is
// verified (signatures, hashes) before it is trusted, so the DHT nodes
// it talks to need not be.
type Client struct {
	node     *kademlia.Kademlia
	verifier Verifier
	key      ed25519.PrivateKey // nil: this node cannot publish
	rules    *Rules
	log      *slog.Logger
}

var (
	ErrNoSigningKey    = errors.New("registry: this node has no signing key")
	ErrNoPackage       = errors.New("registry: no such package")
	ErrVersionNotFound = errors.New("registry: no such version")
)

// NewClient returns a client for node. key may be nil for a node that
// only installs.
func NewClient(node *kademlia.Kademlia, verifier Verifier, key ed25519.PrivateKey) *Client {
	c := &Client{node: node, verifier: verifier, key: key}
	c.rules = NewRules(verifier, c.fetch)
	logger := node.Config().Logger
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}
	c.log = logger.With("node", node.Me().ID.Short())
	return c
}

// fetch reads a content-addressed value from the DHT (local store first).
func (c *Client) fetch(ctx context.Context, key kademlia.KademliaID) ([]byte, error) {
	res, err := c.node.LookupData(ctx, key)
	if err != nil {
		return nil, err
	}
	return res.Value, nil
}

// Owner returns the public key that owns domain, as the verifier sees it.
func (c *Client) Owner(ctx context.Context, domain string) (ed25519.PublicKey, error) {
	return c.verifier.OwnerKey(ctx, domain)
}

// head is a package's latest pointer as the network currently agrees on
// it: the highest valid version among all holders' copies.
type head struct {
	Pointer   LatestPointer
	Record    VersionRecord
	RecordKey kademlia.KademliaID
	Copies    int // holders asked that returned a copy
	Invalid   int // copies that failed validation
}

// head reads the latest pointer of a package. found is false if no holder
// has a valid pointer.
func (c *Client) head(ctx context.Context, domain, pkg string) (h head, found bool, err error) {
	key := LatestKey(domain, pkg)
	copies, err := c.node.LookupAll(ctx, key)
	if err != nil {
		return head{}, false, err
	}
	h.Copies = len(copies)
	for _, cp := range copies {
		p, err := DecodeLatestPointer(cp.Value)
		if err != nil {
			h.Invalid++
			c.log.Warn("bad_pointer", "key", key.Short(), "from", cp.From.ID.Short(), "err", err.Error())
			continue
		}
		rec, err := c.rules.ValidatePointer(ctx, key, p)
		if err != nil {
			h.Invalid++
			c.log.Warn("bad_pointer", "key", key.Short(), "from", cp.From.ID.Short(), "err", err.Error())
			continue
		}
		if !found || h.Pointer.Version.Less(p.Version) {
			h.Pointer, h.Record, h.RecordKey, found = p, rec, p.Record, true
		}
	}
	return h, found, nil
}

// findVersion walks the chain back from the head to the record of version
// v, verifying each record on the way.
func (c *Client) findVersion(ctx context.Context, w *walk, h head, v Version) (VersionRecord, kademlia.KademliaID, error) {
	rec, key := h.Record, h.RecordKey
	for steps := 1; ; steps++ { // records examined so far
		switch rec.Version.Compare(v) {
		case 0:
			return rec, key, nil
		case -1:
			// Versions decrease along the chain, so v is not in it.
			return VersionRecord{}, kademlia.KademliaID{}, fmt.Errorf("%w: %s:%s %v", ErrVersionNotFound, h.Pointer.Domain, h.Pointer.Package, v)
		}
		if rec.Prev == ZeroHash {
			return VersionRecord{}, kademlia.KademliaID{}, fmt.Errorf("%w: %s:%s %v", ErrVersionNotFound, h.Pointer.Domain, h.Pointer.Package, v)
		}
		if steps >= c.rules.maxChain() {
			return VersionRecord{}, kademlia.KademliaID{}, ErrChainTooLong
		}
		prev, err := w.fetchRecord(ctx, rec.Prev)
		if err != nil {
			return VersionRecord{}, kademlia.KademliaID{}, err
		}
		if err := w.checkRecord(ctx, prev); err != nil {
			return VersionRecord{}, kademlia.KademliaID{}, err
		}
		rec, key = prev, rec.Prev
	}
}

// PublishOptions are the publish command's flags.
type PublishOptions struct {
	Force bool     // skip the client-side checks: let the holders refuse
	Prev  *Version // the previous version (nil: the current head)
}

// PublishResult reports what a publish stored and where.
type PublishResult struct {
	Ref       Ref
	BlobKey   kademlia.KademliaID
	RecordKey kademlia.KademliaID
	Blob      kademlia.StoreResult
	Record    kademlia.StoreResult
	Pointer   kademlia.UpdateResult
}

// Publish stores blob as version ref of a package and moves the package's
// latest pointer to it. Without Force it first checks what the holders
// will check (the key owns the domain, the version is newer than the
// head, the previous record is the head), so an honest mistake fails
// before anything is uploaded. With Force it uploads whatever was asked.
func (c *Client) Publish(ctx context.Context, ref Ref, blob []byte, opts PublishOptions) (PublishResult, error) {
	res := PublishResult{Ref: ref}
	if c.key == nil {
		return res, ErrNoSigningKey
	}
	if ref.Latest {
		return res, errors.New("registry: publish needs a version, not \"latest\"")
	}
	if len(blob) > kademlia.MaxValueSize {
		return res, fmt.Errorf("registry: package of %d bytes exceeds the %d byte limit", len(blob), kademlia.MaxValueSize)
	}
	if !opts.Force {
		pk, err := c.verifier.OwnerKey(ctx, ref.Domain)
		if err != nil {
			return res, fmt.Errorf("%w: %w", ErrNotOwner, err)
		}
		if !pk.Equal(c.key.Public()) {
			return res, fmt.Errorf("%w: this node's key does not own %s", ErrNotOwner, ref.Domain)
		}
	}

	h, found, err := c.head(ctx, ref.Domain, ref.Package)
	if err != nil {
		return res, err
	}
	prev := ZeroHash
	if opts.Prev != nil {
		if !found {
			return res, fmt.Errorf("%w: %s:%s has no versions", ErrVersionNotFound, ref.Domain, ref.Package)
		}
		rec, key, err := c.findVersion(ctx, c.rules.newWalk(), h, *opts.Prev)
		if err != nil {
			return res, err
		}
		if !opts.Force {
			if key != h.RecordKey {
				return res, fmt.Errorf("%w: %v is not the latest version (%v is)", ErrFork, *opts.Prev, h.Pointer.Version)
			}
			if ref.Version.Compare(rec.Version) <= 0 {
				return res, fmt.Errorf("%w: %v after %v", ErrNotNewer, ref.Version, rec.Version)
			}
		}
		prev = key
	} else if found {
		if !opts.Force && ref.Version.Compare(h.Pointer.Version) <= 0 {
			return res, fmt.Errorf("%w: %v, latest is %v", ErrNotNewer, ref.Version, h.Pointer.Version)
		}
		prev = h.RecordKey
	}

	rec := NewVersionRecord(ref.Domain, ref.Package, ref.Version, kademlia.KeyFromValue(blob), prev)
	rec.Sign(c.key)
	ptr := NewLatestPointer(ref.Domain, ref.Package, ref.Version, rec.Key())
	ptr.Sign(c.key)
	res.BlobKey, res.RecordKey = rec.Blob, rec.Key()

	// Blob and record first: holders validate the pointer by fetching
	// its record, and readers fetch the blob by the record's hash.
	if res.Blob, err = c.node.Store(ctx, blob); err != nil {
		return res, fmt.Errorf("registry: store package: %w", err)
	}
	if res.Record, err = c.node.Store(ctx, rec.Encode()); err != nil {
		return res, fmt.Errorf("registry: store version record: %w", err)
	}
	res.Pointer, err = c.node.Update(ctx, ptr.Key(), ptr.Encode())
	c.log.Info("publish", "package", ref.Domain+":"+ref.Package, "version", ref.Version.String(),
		"force", opts.Force, "accepted", len(res.Pointer.Accepted), "refused", len(res.Pointer.Refused), "ok", err == nil)
	if err != nil {
		return res, fmt.Errorf("registry: update latest pointer: %w", err)
	}
	return res, nil
}

// Package is an installed package version.
type Package struct {
	Ref       Ref // with the version resolved (never "latest")
	Record    VersionRecord
	RecordKey kademlia.KademliaID
	Blob      []byte
	From      kademlia.Contact // the node the blob came from
	Head      Version          // the package's latest version
}

// Install fetches version ref of a package ("latest" allowed). The
// pointer's and the record's signatures and the blob's hash are checked;
// nothing is returned that the domain owner did not publish.
func (c *Client) Install(ctx context.Context, ref Ref) (Package, error) {
	h, found, err := c.head(ctx, ref.Domain, ref.Package)
	if err != nil {
		return Package{}, err
	}
	if !found {
		return Package{}, fmt.Errorf("%w: %s:%s", ErrNoPackage, ref.Domain, ref.Package)
	}
	rec, key := h.Record, h.RecordKey
	if !ref.Latest {
		rec, key, err = c.findVersion(ctx, c.rules.newWalk(), h, ref.Version)
		if err != nil {
			return Package{}, err
		}
	}
	blob, err := c.node.LookupData(ctx, rec.Blob) // verified: hash(blob) == rec.Blob
	if err != nil {
		return Package{}, fmt.Errorf("registry: fetch package %s:%s %v: %w", ref.Domain, ref.Package, rec.Version, err)
	}
	c.log.Info("install", "package", ref.Domain+":"+ref.Package, "version", rec.Version.String(), "from", blob.From.ID.Short())
	return Package{
		Ref:       Ref{Domain: ref.Domain, Package: ref.Package, Version: rec.Version},
		Record:    rec,
		RecordKey: key,
		Blob:      blob.Value,
		From:      blob.From,
		Head:      h.Pointer.Version,
	}, nil
}

// ChainEntry is one version in a package's history.
type ChainEntry struct {
	Version   Version
	RecordKey kademlia.KademliaID
	Blob      kademlia.KademliaID
	Prev      kademlia.KademliaID
	Err       error // nil if the record verified; otherwise why it did not
}

// Chain returns a package's history, newest first, as far as it can be
// followed. A record that cannot be fetched ends the chain with an entry
// whose Err says so; a record with a bad signature is listed with Err set.
func (c *Client) Chain(ctx context.Context, domain, pkg string) ([]ChainEntry, error) {
	h, found, err := c.head(ctx, domain, pkg)
	if err != nil {
		return nil, err
	}
	if !found {
		return nil, fmt.Errorf("%w: %s:%s", ErrNoPackage, domain, pkg)
	}
	w := c.rules.newWalk()
	var entries []ChainEntry
	rec, key := h.Record, h.RecordKey
	for {
		entries = append(entries, ChainEntry{Version: rec.Version, RecordKey: key, Blob: rec.Blob, Prev: rec.Prev, Err: w.checkRecord(ctx, rec)})
		if rec.Prev == ZeroHash || len(entries) >= c.rules.maxChain() {
			return entries, nil
		}
		prev, err := w.fetchRecord(ctx, rec.Prev)
		if err != nil {
			entries = append(entries, ChainEntry{RecordKey: rec.Prev, Err: err})
			return entries, nil
		}
		rec, key = prev, rec.Prev
	}
}

// maxChain is the effective chain budget.
func (r *Rules) maxChain() int {
	if r.MaxChain <= 0 {
		return DefaultMaxChain
	}
	return r.MaxChain
}
