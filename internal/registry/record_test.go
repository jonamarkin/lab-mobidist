package registry

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/jonamarkin/lab-mobidist/internal/kademlia"
)

// testKey returns a repeatable key pair: Ed25519 keys are derived from a
// 32-byte seed, so a fixed seed gives the same key on every run.
func testKey(seed byte) (ed25519.PublicKey, ed25519.PrivateKey) {
	s := bytes.Repeat([]byte{seed}, ed25519.SeedSize)
	sk := ed25519.NewKeyFromSeed(s)
	return sk.Public().(ed25519.PublicKey), sk
}

func sampleRecord() VersionRecord {
	blob := kademlia.KeyFromValue([]byte("the package"))
	prev := kademlia.KeyFromValue([]byte("the previous record"))
	return NewVersionRecord("rfin.ch", "java-pair", Version{1, 2, 0}, blob, prev)
}

func TestCanonicalEncoding(t *testing.T) {
	// The signing bytes are the JSON of every field but sig, in this order.
	r := sampleRecord()
	want := `{"tag":"version-record","domain":"rfin.ch","package":"java-pair","version":"1.2.0",` +
		`"blobHash":"` + r.Blob.String() + `","prevRecordHash":"` + r.Prev.String() + `"}`
	if got := string(r.Encode()); got != want {
		t.Errorf("unsigned encoding:\n got  %s\n want %s", got, want)
	}
	if r.SigningHash() != kademlia.KeyFromValue([]byte(want)) {
		t.Error("SigningHash is not the hash of the unsigned encoding")
	}
	p := NewLatestPointer("rfin.ch", "java-pair", Version{1, 2, 0}, r.Key())
	wantP := `{"tag":"latest-pointer","domain":"rfin.ch","package":"java-pair","version":"1.2.0",` +
		`"versionRecordHash":"` + r.Key().String() + `"}`
	if got := string(p.Encode()); got != wantP {
		t.Errorf("pointer encoding:\n got  %s\n want %s", got, wantP)
	}
}

func TestSignVerifyRecord(t *testing.T) {
	pk, sk := testKey(1)
	other, _ := testKey(2)
	r := sampleRecord()
	if r.Verify(pk) {
		t.Fatal("an unsigned record verified")
	}
	r.Sign(sk)
	if len(r.Sig) != ed25519.SignatureSize {
		t.Fatalf("signature of %d bytes", len(r.Sig))
	}
	if !r.Verify(pk) {
		t.Fatal("a signed record did not verify")
	}
	if r.Verify(other) {
		t.Error("verified with the wrong key")
	}
	// Signing is deterministic: the same record always gets the same
	// signature, so re-signing never changes its key.
	again := sampleRecord()
	again.Sign(sk)
	if !bytes.Equal(again.Sig, r.Sig) || again.Key() != r.Key() {
		t.Error("signing is not deterministic")
	}
	// Any change to a signed field breaks the signature.
	tampers := map[string]func(*VersionRecord){
		"tag":     func(r *VersionRecord) { r.Tag = TagLatestPointer },
		"domain":  func(r *VersionRecord) { r.Domain = "evil.ch" },
		"package": func(r *VersionRecord) { r.Package = "java-pear" },
		"version": func(r *VersionRecord) { r.Version.Patch++ },
		"blob":    func(r *VersionRecord) { r.Blob[0] ^= 1 },
		"prev":    func(r *VersionRecord) { r.Prev[31] ^= 1 },
		"sig":     func(r *VersionRecord) { r.Sig[5] ^= 1 },
	}
	for field, tamper := range tampers {
		x := r
		x.Sig = bytes.Clone(r.Sig)
		tamper(&x)
		if x.Verify(pk) {
			t.Errorf("changed %s but the record still verified", field)
		}
	}
}

func TestSignVerifyPointer(t *testing.T) {
	pk, sk := testKey(3)
	r := sampleRecord()
	r.Sign(sk)
	p := NewLatestPointer(r.Domain, r.Package, r.Version, r.Key())
	p.Sign(sk)
	if !p.Verify(pk) {
		t.Fatal("a signed pointer did not verify")
	}
	x := p
	x.Version.Major++
	if x.Verify(pk) {
		t.Error("a changed pointer still verified")
	}
	if p.Key() != LatestKey("rfin.ch", "java-pair") {
		t.Error("pointer key is not the latest key of its package")
	}
}

func TestVerifyRejectsBadLengths(t *testing.T) {
	// Wrong-sized keys and signatures must return false, not panic.
	pk, sk := testKey(4)
	r := sampleRecord()
	r.Sign(sk)
	if r.Verify(pk[:16]) || r.Verify(nil) {
		t.Error("verified with a short key")
	}
	r.Sig = r.Sig[:32]
	if r.Verify(pk) {
		t.Error("verified with a short signature")
	}
	r.Sig = nil
	if r.Verify(pk) {
		t.Error("verified with no signature")
	}
}

func TestEncodeDecodeRoundTrip(t *testing.T) {
	_, sk := testKey(5)
	r := sampleRecord()
	r.Sign(sk)
	b := r.Encode()
	got, err := DecodeVersionRecord(b)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got.Encode(), b) {
		t.Error("decode(encode(r)) re-encodes differently")
	}
	if got.Key() != r.Key() || got.Key() != kademlia.KeyFromValue(b) {
		t.Error("key is not the hash of the stored bytes")
	}
	p := NewLatestPointer(r.Domain, r.Package, r.Version, r.Key())
	p.Sign(sk)
	gotP, err := DecodeLatestPointer(p.Encode())
	if err != nil || !bytes.Equal(gotP.Encode(), p.Encode()) {
		t.Fatalf("pointer round trip: %v", err)
	}
}

func TestDecodeRejectsMalformed(t *testing.T) {
	_, sk := testKey(6)
	r := sampleRecord()
	r.Sign(sk)
	good := string(r.Encode())
	cases := map[string]string{
		"not json":      "hello",
		"empty":         "",
		"wrong tag":     strings.Replace(good, TagVersionRecord, TagLatestPointer, 1),
		"empty domain":  strings.Replace(good, `"rfin.ch"`, `""`, 1),
		"colon in name": strings.Replace(good, `"java-pair"`, `"java:pair"`, 1),
		"space in name": strings.Replace(good, `"java-pair"`, `"java pair"`, 1),
		"bad version":   strings.Replace(good, `"1.2.0"`, `"1.2"`, 1),
		"short sig":     strings.Replace(good, `"sig":"`, `"sig":"AAAA`, 1),
		"no sig":        strings.Replace(good, `,"sig":"`+r.sigBase64()+`"`, ``, 1),
		"extra field":   strings.Replace(good, `{"tag"`, `{"x":1,"tag"`, 1),
		"reordered":     strings.Replace(strings.Replace(good, `"tag":"version-record",`, ``, 1), `{`, `{"tag":"version-record",`, 1),
		"with space":    strings.Replace(good, `"tag":`, `"tag": `, 1),
		"bad hash hex":  strings.Replace(good, r.Blob.String(), strings.Repeat("zz", 32), 1),
		"short hash":    strings.Replace(good, r.Blob.String(), "abcd", 1),
	}
	cases["reordered"] = `{"domain":"rfin.ch","tag":"version-record"` + good[len(`{"tag":"version-record","domain":"rfin.ch"`):]
	for name, in := range cases {
		if name == "reordered" && in == good {
			t.Fatalf("test case %q did not change the input", name)
		}
		if _, err := DecodeVersionRecord([]byte(in)); err == nil {
			t.Errorf("%s: decoded without error:\n%s", name, in)
		}
	}
	if _, err := DecodeLatestPointer(r.Encode()); err == nil {
		t.Error("a version record decoded as a pointer")
	}
	p := NewLatestPointer(r.Domain, r.Package, r.Version, r.Key())
	p.Sign(sk)
	for name, in := range map[string]string{
		"not json":      "nope",
		"not canonical": strings.Replace(string(p.Encode()), `"tag":`, `"tag": `, 1),
	} {
		if _, err := DecodeLatestPointer([]byte(in)); err == nil {
			t.Errorf("pointer %s: decoded without error", name)
		}
	}
}

// sigBase64 is the record's signature as it appears in JSON.
func (r VersionRecord) sigBase64() string {
	s := string(r.Encode())
	i := strings.Index(s, `"sig":"`) + len(`"sig":"`)
	return s[i : len(s)-2]
}

func TestLatestKey(t *testing.T) {
	k := LatestKey("rfin.ch", "java-pair")
	if k != kademlia.KeyFromValue([]byte("rfin.ch:java-pair:latest")) {
		t.Error("LatestKey is not hash(domain:package:latest)")
	}
	if k == LatestKey("rfin.ch", "java-pear") || k == LatestKey("rfin.se", "java-pair") {
		t.Error("different packages share a latest key")
	}
	if k == ZeroHash {
		t.Error("latest key is zero")
	}
}

func TestTagOf(t *testing.T) {
	_, sk := testKey(7)
	r := sampleRecord()
	r.Sign(sk)
	p := NewLatestPointer(r.Domain, r.Package, r.Version, r.Key())
	cases := map[string]string{
		string(r.Encode()): TagVersionRecord,
		string(p.Encode()): TagLatestPointer,
		"just a blob":      "",
		"":                 "",
		"{broken":          "",
		`{"tag":"other"}`:  "other",
		`{"notag":1}`:      "",
	}
	for in, want := range cases {
		if got := TagOf([]byte(in)); got != want {
			t.Errorf("TagOf(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestCheckName(t *testing.T) {
	for _, ok := range []string{"rfin.ch", "java-pair", "a", "x_y.z", "héllo", "pkg2"} {
		if err := CheckName(ok); err != nil {
			t.Errorf("CheckName(%q) = %v", ok, err)
		}
	}
	for _, bad := range []string{"", "a:b", "a b", "a\tb", "a\nb", "\x00", "a​b"} {
		if err := CheckName(bad); err == nil {
			t.Errorf("CheckName(%q) accepted", bad)
		}
	}
}

func TestParseRef(t *testing.T) {
	ref, err := ParseRef("rfin.ch:java-pair:1.4.2")
	if err != nil || ref != (Ref{Domain: "rfin.ch", Package: "java-pair", Version: Version{1, 4, 2}}) {
		t.Errorf("ParseRef = %+v, %v", ref, err)
	}
	ref, err = ParseRef("rfin.ch:java-pair:latest")
	if err != nil || !ref.Latest || ref.Domain != "rfin.ch" || ref.Package != "java-pair" {
		t.Errorf("ParseRef latest = %+v, %v", ref, err)
	}
	for _, bad := range []string{"", "rfin.ch", "rfin.ch:java-pair", "rfin.ch:java-pair:1.4",
		"rfin.ch:java-pair:1.4.2:x", ":java-pair:1.0.0", "rfin.ch::1.0.0", "rfin.ch:java-pair:Latest",
		"rfin ch:java-pair:1.0.0"} {
		if ref, err := ParseRef(bad); err == nil {
			t.Errorf("ParseRef(%q) = %+v, want an error", bad, ref)
		}
	}
}

func TestParseName(t *testing.T) {
	d, p, err := ParseName("rfin.ch:java-pair")
	if err != nil || d != "rfin.ch" || p != "java-pair" {
		t.Errorf("ParseName = %q, %q, %v", d, p, err)
	}
	for _, bad := range []string{"", "rfin.ch", "rfin.ch:", ":java-pair", "a:b:c", "a b:c"} {
		if _, _, err := ParseName(bad); err == nil {
			t.Errorf("ParseName(%q) accepted", bad)
		}
	}
}

func TestZeroHashIsAllZeros(t *testing.T) {
	if ZeroHash.String() != strings.Repeat("0", 64) {
		t.Errorf("ZeroHash = %s", ZeroHash)
	}
	if _, err := hex.DecodeString(ZeroHash.String()); err != nil {
		t.Error(err)
	}
}
