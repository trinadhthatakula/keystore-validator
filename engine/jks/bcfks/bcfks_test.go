package bcfks

import (
	"bytes"
	"crypto/sha256"
	"encoding/asn1"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestBouncyCastleFixtures(t *testing.T) {
	dir := os.Getenv("BC_FIXTURE_DIR")
	if dir == "" {
		t.Skip("set BC_FIXTURE_DIR to generated Bouncy Castle fixtures")
	}
	read := func(name string) []byte {
		b, e := os.ReadFile(filepath.Join(dir, name))
		if e != nil {
			t.Fatal(e)
		}
		return b
	}
	data := read("store.bcfks")
	if !LooksLike(data) {
		t.Fatal("BCFKS not recognized")
	}
	entries, err := Inspect(data, "café🔑pass")
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 3 {
		t.Fatalf("expected three aliases, got %d", len(entries))
	}
	expected := map[string][]byte{"fips": read("fips.der"), "café-😀": read("fips-unicode.der"), "trusted": read("fips.der")}
	for _, entry := range entries {
		want, ok := expected[entry.Alias]
		if !ok || !bytes.Equal(entry.Certificate.Raw, want) {
			t.Errorf("incorrect certificate for %q", entry.Alias)
		}
		if entry.Alias == "trusted" && entry.EntryType != "trusted-certificate" {
			t.Error("trusted entry misclassified")
		}
		if entry.Alias != "trusted" && entry.EntryType != "private-key" {
			t.Error("key entry misclassified")
		}
		delete(expected, entry.Alias)
	}
	if len(expected) > 0 {
		t.Errorf("missing aliases: %v", expected)
	}
	for _, variant := range []string{"scrypt.bcfks", "sha3.bcfks"} {
		items, err := Inspect(read(variant), "café🔑pass")
		if err != nil || len(items) != 3 {
			t.Fatalf("%s: %+v, %v", variant, items, err)
		}
	}
	empty, err := Inspect(read("empty.bcfks"), "")
	if err != nil || len(empty) != 1 || !bytes.Equal(empty[0].Certificate.Raw, read("fips.der")) {
		t.Fatalf("empty password: %+v, %v", empty, err)
	}
	if _, err = Inspect(read("empty.bcfks"), "wrong"); !errors.Is(err, ErrIntegrity) {
		t.Fatalf("empty-store wrong password: %v", err)
	}
	if _, err = Inspect(data, "wrong"); !errors.Is(err, ErrIntegrity) {
		t.Fatalf("wrong password: %v", err)
	}
	altered := append([]byte(nil), data...)
	altered[len(altered)/2] ^= 1
	if _, err = Inspect(altered, "café🔑pass"); !errors.Is(err, ErrIntegrity) {
		t.Fatalf("tampering: %v", err)
	}
	// Manipulate the untrusted MAC PBKDF iteration count; it must be bounded
	// before derivation rather than consuming unbounded CPU.
	excessive := append([]byte(nil), data...)
	marker := []byte{2, 3, 0, 0xc8, 0}
	pos := bytes.LastIndex(excessive, marker)
	if pos < 0 {
		t.Fatal("fixture iteration marker not found")
	}
	copy(excessive[pos+2:pos+5], []byte{0x7f, 0xff, 0xff})
	if _, err = Inspect(excessive, "café🔑pass"); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("iteration bound: %v", err)
	}
	sum := sha256.Sum256(read("fips.der"))
	if sum != sha256.Sum256(entries[0].Certificate.Raw) && sum != sha256.Sum256(entries[1].Certificate.Raw) && sum != sha256.Sum256(entries[2].Certificate.Raw) {
		t.Fatal("certificate corrupted after container clear")
	}
}

func TestScryptResourceBounds(t *testing.T) {
	makeKDF := func(n, r, p int) asn1.RawValue {
		params, err := asn1.Marshal(struct {
			Salt            []byte
			N, R, P, KeyLen int
		}{[]byte("test-salt"), n, r, p, 32})
		if err != nil {
			t.Fatal(err)
		}
		encoded, err := asn1.Marshal(struct {
			OID    asn1.ObjectIdentifier
			Params asn1.RawValue
		}{oidScrypt, asn1.RawValue{FullBytes: params}})
		if err != nil {
			t.Fatal(err)
		}
		var value asn1.RawValue
		if _, err = asn1.Unmarshal(encoded, &value); err != nil {
			t.Fatal(err)
		}
		return value
	}
	if _, err := parseKDF(makeKDF(1024, 8, 1), 32); err != nil {
		t.Fatalf("reasonable scrypt rejected: %v", err)
	}
	if _, err := parseKDF(makeKDF(1<<20, 8, 1), 32); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("excessive scrypt accepted: %v", err)
	}
}

func FuzzInspect(f *testing.F) {
	f.Add([]byte{}, "")
	f.Add([]byte{0x30, 0x02, 0x30, 0x00}, "test")
	f.Fuzz(func(t *testing.T, data []byte, pass string) { _, _ = Inspect(data, pass) })
}
