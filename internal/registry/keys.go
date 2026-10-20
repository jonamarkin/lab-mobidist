package registry

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"strings"
)

// Signature scheme: Ed25519 (crypto/ed25519). Keys are 32 bytes, signatures
// 64 bytes, signing is deterministic, and it is in Go's standard library.
//
// Private keys are stored as PKCS#8 PEM ("-----BEGIN PRIVATE KEY-----"),
// the same format as `openssl genpkey -algorithm ed25519`.
//
// A domain publishes its owner's public key in a DNS TXT record of the
// form "kademlia-pk=ed25519:<base64 of the 32 key bytes>".

// pkPrefix starts the TXT record that carries a domain's public key.
const pkPrefix = "kademlia-pk=ed25519:"

// GenerateKey makes a new random key pair.
func GenerateKey() (ed25519.PublicKey, ed25519.PrivateKey, error) {
	return ed25519.GenerateKey(nil) // nil: crypto/rand
}

// SaveKey writes sk to path as PKCS#8 PEM, readable only by the owner.
func SaveKey(path string, sk ed25519.PrivateKey) error {
	der, err := x509.MarshalPKCS8PrivateKey(sk)
	if err != nil {
		return err
	}
	return os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0o600)
}

// LoadKey reads a PKCS#8 PEM Ed25519 private key from path.
func LoadKey(path string) (ed25519.PrivateKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(data)
	if block == nil || block.Type != "PRIVATE KEY" {
		return nil, fmt.Errorf("%s: not a PEM private key", path)
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	sk, ok := key.(ed25519.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("%s: not an Ed25519 key", path)
	}
	return sk, nil
}

// EncodePublicKey returns the TXT record text for pk.
func EncodePublicKey(pk ed25519.PublicKey) string {
	return pkPrefix + base64.StdEncoding.EncodeToString(pk)
}

// ParsePublicKey parses a TXT record written by EncodePublicKey. ok is
// false for any other TXT record, so a domain's unrelated records are
// skipped; err reports a record that starts like ours but is broken.
func ParsePublicKey(txt string) (pk ed25519.PublicKey, ok bool, err error) {
	rest, found := strings.CutPrefix(strings.TrimSpace(txt), pkPrefix)
	if !found {
		return nil, false, nil
	}
	raw, err := base64.StdEncoding.DecodeString(rest)
	if err != nil {
		return nil, true, fmt.Errorf("public key: %w", err)
	}
	if len(raw) != ed25519.PublicKeySize {
		return nil, true, errors.New("public key: wrong size")
	}
	return ed25519.PublicKey(raw), true, nil
}
