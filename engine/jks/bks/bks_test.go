package bks

import (
	"bytes"
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestBouncyCastleFixture(t *testing.T) {
	dir := os.Getenv("BKS_FIXTURE_DIR")
	if dir == "" {
		t.Skip("set BKS_FIXTURE_DIR to a Bouncy Castle fixture directory")
	}
	read := func(name string) []byte {
		b, e := os.ReadFile(filepath.Join(dir, name))
		if e != nil {
			t.Fatal(e)
		}
		return b
	}
	data := read("store.bks")
	result, err := Inspect(data, "testpass123")
	if err != nil {
		t.Fatal(err)
	}
	if result.Version != 2 || result.WeakIntegrity || len(result.Entries) != 3 {
		t.Fatalf("bad BKS result: %+v", result)
	}
	wanted := map[string][]byte{"alpha": read("alpha.der"), "café-😀": read("unicode.der"), "trusted": read("alpha.der")}
	for _, entry := range result.Entries {
		want, ok := wanted[entry.Alias]
		if !ok || !bytes.Equal(entry.Certificate, want) {
			t.Errorf("incorrect certificate for %q", entry.Alias)
		}
		if entry.Alias == "trusted" && entry.EntryType != "trusted-certificate" {
			t.Errorf("wrong trusted entry type: %s", entry.EntryType)
		}
		if entry.Alias != "trusted" && entry.EntryType != "key-entry" {
			t.Errorf("sealed entry must not claim private key possession: %s", entry.EntryType)
		}
		delete(wanted, entry.Alias)
	}
	if len(wanted) != 0 {
		t.Errorf("missing aliases: %v", wanted)
	}
	unicodePass, err := Inspect(read("unicode-pass.bks"), "café🔑pass")
	if err != nil || len(unicodePass.Entries) != 1 || unicodePass.Entries[0].Alias != "unicode" || !bytes.Equal(unicodePass.Entries[0].Certificate, read("unicode-pass.der")) {
		t.Fatalf("unicode password failed: %+v, %v", unicodePass, err)
	}
	emptyPass, err := Inspect(read("empty.bks"), "")
	if err != nil || len(emptyPass.Entries) != 1 || emptyPass.Entries[0].Alias != "empty-pass" || !bytes.Equal(emptyPass.Entries[0].Certificate, read("alpha.der")) {
		t.Fatalf("empty password failed: %+v, %v", emptyPass, err)
	}
	if _, err = Inspect(read("empty.bks"), "wrong"); !errors.Is(err, ErrIntegrity) {
		t.Fatalf("empty-store wrong password accepted: %v", err)
	}
	if _, err = Inspect(data, "wrong-password"); !errors.Is(err, ErrIntegrity) {
		t.Fatalf("wrong password: %v", err)
	}
	corrupt := append([]byte(nil), data...)
	corrupt[len(corrupt)/2] ^= 1
	if _, err = Inspect(corrupt, "testpass123"); !errors.Is(err, ErrIntegrity) {
		t.Fatalf("tampering: %v", err)
	}
	legacy, err := Inspect(read("old.bks"), "testpass123")
	if err != nil || !legacy.WeakIntegrity || len(legacy.Entries) != 1 || !bytes.Equal(legacy.Entries[0].Certificate, read("old.der")) {
		t.Fatalf("legacy BKS: %+v, %v", legacy, err)
	}
	uber, err := InspectUber(read("store.uber"), "testpass123")
	if err != nil || uber.WeakIntegrity || len(uber.Entries) != 1 || !bytes.Equal(uber.Entries[0].Certificate, read("uber.der")) {
		t.Fatalf("UBER: %+v, %v", uber, err)
	}
	if _, err = InspectUber(read("store.uber"), "wrong"); !errors.Is(err, ErrIntegrity) {
		t.Fatalf("UBER wrong password accepted: %v", err)
	}
	unicodeUber, err := InspectUber(read("unicode.uber"), "café🔑pass")
	if err != nil || len(unicodeUber.Entries) != 1 || !bytes.Equal(unicodeUber.Entries[0].Certificate, read("uber-unicode.der")) {
		t.Fatalf("UBER unicode password: %+v, %v", unicodeUber, err)
	}
	emptyUber, err := InspectUber(read("empty.uber"), "")
	if err != nil || len(emptyUber.Entries) != 1 || !bytes.Equal(emptyUber.Entries[0].Certificate, read("alpha.der")) {
		t.Fatalf("UBER empty password: %+v, %v", emptyUber, err)
	}
	badUber := read("store.uber")
	badUber[len(badUber)/2] ^= 1
	if _, err = InspectUber(badUber, "testpass123"); err == nil {
		t.Fatal("tampered UBER accepted")
	}
	excessive := append([]byte(nil), data...)
	salt := binary.BigEndian.Uint32(excessive[4:8])
	binary.BigEndian.PutUint32(excessive[8+salt:12+salt], maxIterations+1)
	if _, err = Inspect(excessive, "testpass123"); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("iteration limit: %v", err)
	}
}

func TestModifiedUTF8(t *testing.T) {
	valid := []byte{0x63, 0x61, 0x66, 0xc3, 0xa9, 0x2d, 0xed, 0xa0, 0xbd, 0xed, 0xb8, 0x80}
	got, err := modifiedUTF8(valid)
	if err != nil || got != "café-😀" {
		t.Fatalf("got %q %v", got, err)
	}
	for _, bad := range [][]byte{{0x00}, {0xed, 0xa0, 0xbd}, {0xc0, 0x81}, {0xf0, 0x9f, 0x98, 0x80}} {
		if _, err := modifiedUTF8(bad); err == nil {
			t.Errorf("accepted invalid modified UTF-8: %x", bad)
		}
	}
}

func FuzzInspect(f *testing.F) {
	f.Add([]byte{}, "")
	f.Add([]byte{0, 0, 0, 2, 0, 0, 0, 1, 1, 0, 0, 0, 1}, "password")
	f.Fuzz(func(t *testing.T, data []byte, password string) { _, _ = Inspect(data, password) })
}
