package registry

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestKeyFileRoundTrip(t *testing.T) {
	pk, sk, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "owner.pem")
	if err := SaveKey(path, sk); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Errorf("key file mode = %o, want 600", info.Mode().Perm())
	}
	data, _ := os.ReadFile(path)
	if !bytes.HasPrefix(data, []byte("-----BEGIN PRIVATE KEY-----")) {
		t.Errorf("not PKCS#8 PEM: %s", data)
	}
	loaded, err := LoadKey(path)
	if err != nil {
		t.Fatal(err)
	}
	if !loaded.Equal(sk) || !loaded.Public().(ed25519.PublicKey).Equal(pk) {
		t.Error("loaded key differs from the saved one")
	}
}

func TestLoadKeyErrors(t *testing.T) {
	dir := t.TempDir()
	write := func(name string, data []byte) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, data, 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	// A PKCS#8 key of another algorithm: well-formed, but not Ed25519.
	ec, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der, _ := x509.MarshalPKCS8PrivateKey(ec)
	ecPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})

	cases := map[string]string{
		"missing":     filepath.Join(dir, "nope.pem"),
		"not PEM":     write("a.pem", []byte("hello")),
		"wrong block": write("b.pem", []byte("-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n")),
		"bad DER":     write("c.pem", []byte("-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n")),
		"not ed25519": write("d.pem", ecPEM),
	}
	for name, path := range cases {
		if _, err := LoadKey(path); err == nil {
			t.Errorf("%s: LoadKey succeeded", name)
		}
	}
}

func TestPublicKeyText(t *testing.T) {
	pk, _ := testKey(9)
	txt := EncodePublicKey(pk)
	if !strings.HasPrefix(txt, "kademlia-pk=ed25519:") {
		t.Errorf("TXT = %q", txt)
	}
	got, ok, err := ParsePublicKey(txt)
	if err != nil || !ok || !got.Equal(pk) {
		t.Fatalf("ParsePublicKey = %x, %v, %v", got, ok, err)
	}
	// Surrounding whitespace, as DNS tools sometimes add, is tolerated.
	if got, ok, err := ParsePublicKey("  " + txt + "\n"); err != nil || !ok || !got.Equal(pk) {
		t.Error("whitespace around the record was not tolerated")
	}
	// Unrelated TXT records are skipped, not errors.
	for _, other := range []string{"v=spf1 -all", "", "kademlia-pk=rsa:AAAA", "KADEMLIA-PK=ed25519:AAAA"} {
		if _, ok, err := ParsePublicKey(other); ok || err != nil {
			t.Errorf("ParsePublicKey(%q) = ok %v, err %v; want skipped", other, ok, err)
		}
	}
	// Records that claim to be ours but are broken are errors.
	for _, broken := range []string{"kademlia-pk=ed25519:", "kademlia-pk=ed25519:not base64!", "kademlia-pk=ed25519:AAAA"} {
		if _, ok, err := ParsePublicKey(broken); !ok || err == nil {
			t.Errorf("ParsePublicKey(%q) = ok %v, err %v; want an error", broken, ok, err)
		}
	}
}
