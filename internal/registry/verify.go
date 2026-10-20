package registry

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"io"
	"maps"
	"net"
	"os"
	"slices"
	"strings"
	"sync"
)

// Ownership verification: who owns a domain? The answer is the public key
// in the domain's DNS TXT record (see keys.go for the format). It sits
// behind an interface so that tests and demos can fake it.

// Verifier answers which public key owns a domain.
type Verifier interface {
	// OwnerKey returns the owner's public key, ErrNoKey if the domain has
	// no usable key, or ErrLookup if the question could not be answered.
	OwnerKey(ctx context.Context, domain string) (ed25519.PublicKey, error)
}

var (
	// ErrNoKey means the domain exists without a registry key, does not
	// exist, or has a broken key record: nothing signed for it can verify.
	ErrNoKey = errors.New("registry: no owner key for domain")
	// ErrLookup means the key could not be looked up (e.g. DNS failed).
	ErrLookup = errors.New("registry: owner key lookup failed")
)

// FakeDNS is an in-memory Verifier: a table of domain -> key, filled by
// tests or loaded from a file for demos. Safe for concurrent use.
type FakeDNS struct {
	mu   sync.RWMutex
	keys map[string]ed25519.PublicKey
}

// NewFakeDNS returns an empty table.
func NewFakeDNS() *FakeDNS {
	return &FakeDNS{keys: make(map[string]ed25519.PublicKey)}
}

// Set makes pk the owner key of domain.
func (f *FakeDNS) Set(domain string, pk ed25519.PublicKey) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.keys[domain] = slices.Clone(pk)
}

// OwnerKey implements Verifier.
func (f *FakeDNS) OwnerKey(_ context.Context, domain string) (ed25519.PublicKey, error) {
	f.mu.RLock()
	defer f.mu.RUnlock()
	pk, ok := f.keys[domain]
	if !ok {
		return nil, fmt.Errorf("%w: %s", ErrNoKey, domain)
	}
	return slices.Clone(pk), nil
}

// Domains lists the known domains, sorted.
func (f *FakeDNS) Domains() []string {
	f.mu.RLock()
	defer f.mu.RUnlock()
	return slices.Sorted(maps.Keys(f.keys))
}

// Load reads lines of the form "domain kademlia-pk=ed25519:<base64>".
// Blank lines and lines starting with # are skipped.
func (f *FakeDNS) Load(r io.Reader) error {
	scanner := bufio.NewScanner(r)
	for n := 1; scanner.Scan(); n++ {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) != 2 {
			return fmt.Errorf("line %d: want \"domain kademlia-pk=ed25519:...\"", n)
		}
		if err := CheckName(fields[0]); err != nil {
			return fmt.Errorf("line %d: %w", n, err)
		}
		pk, ok, err := ParsePublicKey(fields[1])
		if !ok {
			return fmt.Errorf("line %d: not a kademlia-pk record", n)
		}
		if err != nil {
			return fmt.Errorf("line %d: %w", n, err)
		}
		f.Set(fields[0], pk)
	}
	return scanner.Err()
}

// LoadFile is Load on the named file.
func (f *FakeDNS) LoadFile(path string) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()
	if err := f.Load(file); err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	return nil
}

// DNSVerifier finds owner keys in real DNS TXT records.
type DNSVerifier struct {
	// LookupTXT returns the TXT records of a name. It is a field so that
	// tests can supply records without a network.
	LookupTXT func(ctx context.Context, name string) ([]string, error)
}

// NewDNSVerifier returns a verifier that uses the system resolver.
func NewDNSVerifier() *DNSVerifier {
	return &DNSVerifier{LookupTXT: net.DefaultResolver.LookupTXT}
}

// OwnerKey implements Verifier: the first TXT record in our format wins.
func (d *DNSVerifier) OwnerKey(ctx context.Context, domain string) (ed25519.PublicKey, error) {
	records, err := d.LookupTXT(ctx, domain)
	if err != nil {
		// A domain that does not exist has no key; any other failure
		// (timeout, no resolver) is a lookup error.
		var dnsErr *net.DNSError
		if errors.As(err, &dnsErr) && dnsErr.IsNotFound {
			return nil, fmt.Errorf("%w: %s does not exist", ErrNoKey, domain)
		}
		return nil, fmt.Errorf("%w: %s: %w", ErrLookup, domain, err)
	}
	for _, txt := range records {
		pk, ok, err := ParsePublicKey(txt)
		if !ok {
			continue // some other TXT record, e.g. SPF
		}
		if err != nil {
			return nil, fmt.Errorf("%w: %s has a broken record: %w", ErrNoKey, domain, err)
		}
		return pk, nil
	}
	return nil, fmt.Errorf("%w: %s", ErrNoKey, domain)
}
