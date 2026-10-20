package registry

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"unicode"

	"github.com/jonamarkin/lab-mobidist/internal/kademlia"
)

// Record tags: the first field of every record says what it is.
const (
	TagVersionRecord = "version-record"
	TagLatestPointer = "latest-pointer"
)

// ZeroHash is the "previous record" of a package's first version.
var ZeroHash kademlia.KademliaID

// VersionRecord describes one version of a package (PART2-DESIGN). It is
// stored content-addressed, under the hash of its encoding, and is
// immutable. Prev links it to the previous version's record, so all
// versions of a package form a chain.
//
// The JSON field order is the record's canonical form: Sig signs the
// SHA-256 hash of the JSON of the other fields (see SigningHash).
type VersionRecord struct {
	Tag     string              `json:"tag"`
	Domain  string              `json:"domain"`
	Package string              `json:"package"`
	Version Version             `json:"version"`
	Blob    kademlia.KademliaID `json:"blobHash"`
	Prev    kademlia.KademliaID `json:"prevRecordHash"`
	Sig     []byte              `json:"sig,omitempty"`
}

// LatestPointer is the entry point to a package's chain: it names the
// newest version record. It is stored under LatestKey(domain, package),
// the only key whose value changes over time.
type LatestPointer struct {
	Tag     string              `json:"tag"`
	Domain  string              `json:"domain"`
	Package string              `json:"package"`
	Version Version             `json:"version"`
	Record  kademlia.KademliaID `json:"versionRecordHash"`
	Sig     []byte              `json:"sig,omitempty"`
}

// NewVersionRecord returns an unsigned record for version v of a package,
// whose blob and previous record have the given hashes (ZeroHash for a
// first version).
func NewVersionRecord(domain, pkg string, v Version, blob, prev kademlia.KademliaID) VersionRecord {
	return VersionRecord{Tag: TagVersionRecord, Domain: domain, Package: pkg, Version: v, Blob: blob, Prev: prev}
}

// NewLatestPointer returns an unsigned pointer to the record of version v.
func NewLatestPointer(domain, pkg string, v Version, record kademlia.KademliaID) LatestPointer {
	return LatestPointer{Tag: TagLatestPointer, Domain: domain, Package: pkg, Version: v, Record: record}
}

// LatestKey is the DHT key of a package's latest pointer:
// hash("domain:package:latest").
func LatestKey(domain, pkg string) kademlia.KademliaID {
	return kademlia.KeyFromValue([]byte(domain + ":" + pkg + ":latest"))
}

// encode returns v's JSON. Marshalling these structs cannot fail (only
// strings, integers, fixed arrays and bytes), so the error is a bug.
func encode(v any) []byte {
	b, err := json.Marshal(v)
	if err != nil {
		panic("registry: encode record: " + err.Error())
	}
	return b
}

// sign returns the signature of hash with sk.
func sign(sk ed25519.PrivateKey, hash kademlia.KademliaID) []byte {
	return ed25519.Sign(sk, hash[:])
}

// verify reports whether sig is pk's signature of hash. Bad lengths are
// rejected rather than passed to ed25519, which would panic.
func verify(pk ed25519.PublicKey, hash kademlia.KademliaID, sig []byte) bool {
	return len(pk) == ed25519.PublicKeySize && len(sig) == ed25519.SignatureSize &&
		ed25519.Verify(pk, hash[:], sig)
}

// SigningHash is what the owner signs: the hash of the record's JSON
// without the signature. (r is a copy, so clearing Sig is local.)
func (r VersionRecord) SigningHash() kademlia.KademliaID {
	r.Sig = nil
	return kademlia.KeyFromValue(encode(r))
}

// Sign signs r with the domain owner's private key.
func (r *VersionRecord) Sign(sk ed25519.PrivateKey) { r.Sig = sign(sk, r.SigningHash()) }

// Verify reports whether r's signature was made with the private key
// matching pk.
func (r VersionRecord) Verify(pk ed25519.PublicKey) bool { return verify(pk, r.SigningHash(), r.Sig) }

// Encode returns the bytes stored in the DHT: the full JSON record.
func (r VersionRecord) Encode() []byte { return encode(r) }

// Key is the record's DHT key: the hash of its encoding.
func (r VersionRecord) Key() kademlia.KademliaID { return kademlia.KeyFromValue(r.Encode()) }

func (p LatestPointer) SigningHash() kademlia.KademliaID {
	p.Sig = nil
	return kademlia.KeyFromValue(encode(p))
}

func (p *LatestPointer) Sign(sk ed25519.PrivateKey)      { p.Sig = sign(sk, p.SigningHash()) }
func (p LatestPointer) Verify(pk ed25519.PublicKey) bool { return verify(pk, p.SigningHash(), p.Sig) }
func (p LatestPointer) Encode() []byte                   { return encode(p) }

// Key is the pointer's DHT key, which depends only on the package name.
func (p LatestPointer) Key() kademlia.KademliaID { return LatestKey(p.Domain, p.Package) }

// DecodeVersionRecord parses a stored value as a version record and
// checks that it is well formed: the right tag, valid names, a signature
// of the right size, and the canonical encoding (so a record has exactly
// one key). Whether it is valid (signed by the owner, a proper chain) is
// a separate question, answered by the validation rules.
func DecodeVersionRecord(b []byte) (VersionRecord, error) {
	var r VersionRecord
	if err := json.Unmarshal(b, &r); err != nil {
		return VersionRecord{}, fmt.Errorf("version record: %w", err)
	}
	if err := wellFormed(r.Tag, TagVersionRecord, r.Domain, r.Package, r.Sig); err != nil {
		return VersionRecord{}, fmt.Errorf("version record: %w", err)
	}
	if !bytes.Equal(r.Encode(), b) {
		return VersionRecord{}, errors.New("version record: not in canonical form")
	}
	return r, nil
}

// DecodeLatestPointer parses a stored value as a latest pointer; see
// DecodeVersionRecord.
func DecodeLatestPointer(b []byte) (LatestPointer, error) {
	var p LatestPointer
	if err := json.Unmarshal(b, &p); err != nil {
		return LatestPointer{}, fmt.Errorf("latest pointer: %w", err)
	}
	if err := wellFormed(p.Tag, TagLatestPointer, p.Domain, p.Package, p.Sig); err != nil {
		return LatestPointer{}, fmt.Errorf("latest pointer: %w", err)
	}
	if !bytes.Equal(p.Encode(), b) {
		return LatestPointer{}, errors.New("latest pointer: not in canonical form")
	}
	return p, nil
}

// TagOf returns the tag of a stored value, or "" if it is not a record.
// It lets "show ds" tell records from plain blobs.
func TagOf(b []byte) string {
	var v struct {
		Tag string `json:"tag"`
	}
	if len(b) == 0 || b[0] != '{' || json.Unmarshal(b, &v) != nil {
		return ""
	}
	return v.Tag
}

func wellFormed(tag, want, domain, pkg string, sig []byte) error {
	if tag != want {
		return fmt.Errorf("tag %q, want %q", tag, want)
	}
	if err := CheckName(domain); err != nil {
		return fmt.Errorf("domain: %w", err)
	}
	if err := CheckName(pkg); err != nil {
		return fmt.Errorf("package: %w", err)
	}
	if len(sig) != ed25519.SignatureSize {
		return fmt.Errorf("signature of %d bytes, want %d", len(sig), ed25519.SignatureSize)
	}
	return nil
}

// CheckName checks a domain or package name: non-empty, printable, and
// without ':' (the separator in "domain:package:version") or spaces.
func CheckName(s string) error {
	if s == "" {
		return errors.New("empty name")
	}
	bad := func(r rune) bool { return r == ':' || unicode.IsSpace(r) || !unicode.IsPrint(r) }
	if strings.ContainsFunc(s, bad) {
		return fmt.Errorf("invalid name %q", s)
	}
	return nil
}

// Ref names a package version as the user writes it:
// "DOMAIN:PACKAGE:VERSION", where VERSION may be "latest".
type Ref struct {
	Domain, Package string
	Version         Version
	Latest          bool // the version is "latest"
}

// ParseRef parses "DOMAIN:PACKAGE:VERSION".
func ParseRef(s string) (Ref, error) {
	parts := strings.Split(s, ":")
	if len(parts) != 3 {
		return Ref{}, fmt.Errorf("%q: want DOMAIN:PACKAGE:VERSION", s)
	}
	ref := Ref{Domain: parts[0], Package: parts[1]}
	if err := CheckName(ref.Domain); err != nil {
		return Ref{}, err
	}
	if err := CheckName(ref.Package); err != nil {
		return Ref{}, err
	}
	if parts[2] == "latest" {
		ref.Latest = true
		return ref, nil
	}
	v, err := ParseVersion(parts[2])
	if err != nil {
		return Ref{}, err
	}
	ref.Version = v
	return ref, nil
}

// ParseName parses "DOMAIN:PACKAGE".
func ParseName(s string) (domain, pkg string, err error) {
	domain, pkg, ok := strings.Cut(s, ":")
	if !ok || strings.Contains(pkg, ":") {
		return "", "", fmt.Errorf("%q: want DOMAIN:PACKAGE", s)
	}
	if err := CheckName(domain); err != nil {
		return "", "", err
	}
	if err := CheckName(pkg); err != nil {
		return "", "", err
	}
	return domain, pkg, nil
}
