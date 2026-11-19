package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/binary"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/agusibrahim/apksig-go/pkg/algo"
	"github.com/agusibrahim/apksig-go/pkg/datasource"
)

func lp(b []byte) []byte {
	out := make([]byte, 4+len(b))
	binary.LittleEndian.PutUint32(out, uint32(len(b)))
	copy(out[4:], b)
	return out
}

func TestRepeatedContentDigestTypeIsUnsupported(t *testing.T) {
	ids := []algo.SigID{algo.SigRSAPSSSHA256, algo.SigRSAPKCS1SHA256}
	if err := checkAlgorithms(ids, 24, false); err == nil {
		t.Fatal("cannot safely validate two digest records collapsed into one map entry")
	}
}
func v2Block(key []byte) []byte {
	signer := append(lp(nil), lp(nil)...)
	signer = append(signer, lp(key)...)
	return lp(lp(signer))
}

// The upstream verifier v1.1.0 accepted a signer public key which did not
// correspond to the certificate. This test must continue to reject it.
func TestV2PublicKeyMustMatchCertificate(t *testing.T) {
	a, e := rsa.GenerateKey(rand.Reader, 1024)
	if e != nil {
		t.Fatal(e)
	}
	b, e := rsa.GenerateKey(rand.Reader, 1024)
	if e != nil {
		t.Fatal(e)
	}
	cert := &x509.Certificate{PublicKey: &a.PublicKey}
	aKey, e := x509.MarshalPKIXPublicKey(&a.PublicKey)
	if e != nil {
		t.Fatal(e)
	}
	bKey, e := x509.MarshalPKIXPublicKey(&b.PublicKey)
	if e != nil {
		t.Fatal(e)
	}
	if err := checkV2PublicKey(v2Block(aKey), cert); err != nil {
		t.Fatalf("matching key rejected: %v", err)
	}
	if err := checkV2PublicKey(v2Block(bKey), cert); err == nil {
		t.Fatal("mismatched key accepted")
	}
	if err := checkV2PublicKey(append(v2Block(aKey), 1), cert); err == nil {
		t.Fatal("trailing data accepted")
	}
}
func TestMalformedAPKNotVerified(t *testing.T) {
	r := verifyAPK(datasource.NewBytes([]byte("not an APK")))
	if r.Verified || len(r.Errors) == 0 {
		t.Fatalf("unsafe malformed APK result: %+v", r)
	}
}
func TestGoldenFixtures(t *testing.T) {
	dir := os.Getenv("APK_FIXTURE_DIR")
	if dir == "" {
		t.Skip("set APK_FIXTURE_DIR to the public AOSP golden fixture directory")
	}
	cases := []struct {
		name     string
		verified bool
		contains string
	}{
		{"golden-aligned-v2-out.apk", true, ""},
		{"golden-aligned-v1v2v3-out.apk", true, ""},
		{"golden-aligned-v1v2v3-lineage-out.apk", false, "rotation"},
		{"golden-aligned-v1-out.apk", false, "v1-only"},
		{"tampered-v1v2v3.apk", false, "digest"},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			b, e := os.ReadFile(filepath.Join(dir, tt.name))
			if e != nil {
				t.Fatal(e)
			}
			r := verifyAPK(datasource.NewBytes(b))
			if r.Verified != tt.verified {
				t.Fatalf("got verified=%v, want %v: %+v", r.Verified, tt.verified, r)
			}
			if tt.contains != "" && !strings.Contains(strings.ToLower(strings.Join(r.Errors, " ")), tt.contains) {
				t.Fatalf("expected %q in errors: %+v", tt.contains, r.Errors)
			}
			if r.Verified && (len(r.Signers) != 1 || r.Signers[0].SHA256 != "fb5dbd3c669af9fc236c6991e6387b7f11ff0590997f22d0f5c74ff40e04fca8") {
				t.Fatalf("unexpected signer: %+v", r.Signers)
			}
			if tt.name == "golden-aligned-v1-out.apk" && (len(r.Signers) != 1 || r.Signers[0].SHA256 != "fb5dbd3c669af9fc236c6991e6387b7f11ff0590997f22d0f5c74ff40e04fca8") {
				t.Fatalf("missing v1 diagnostic certificate: %+v", r.Signers)
			}
		})
	}
}
