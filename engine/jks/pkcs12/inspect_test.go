package pkcs12

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"strings"
	"testing"
	"time"
)

func fixture(t *testing.T, encoder *Encoder) ([]byte, *x509.Certificate) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Fixture"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	data, err := encoder.Encode(key, cert, nil, "testpass")
	if err != nil {
		t.Fatal(err)
	}
	return data, cert
}
func TestInspectCertificatesAndMAC(t *testing.T) {
	for _, tc := range []struct {
		name    string
		encoder *Encoder
	}{{"modern", Modern}, {"legacy", LegacyRC2}} {
		t.Run(tc.name, func(t *testing.T) {
			data, cert := fixture(t, tc.encoder)
			items, err := InspectCertificates(data, "testpass")
			if err != nil {
				t.Fatal(err)
			}
			if len(items) != 1 || !items[0].Certificate.Equal(cert) || items[0].EntryType != "private-key" {
				t.Fatalf("unexpected certificate: %+v", items)
			}
			if _, err := InspectCertificates(data, "incorrect"); err != ErrIncorrectPassword {
				t.Fatalf("wrong password accepted: %v", err)
			}
			data[len(data)-1] ^= 1
			if _, err := InspectCertificates(data, "testpass"); err == nil {
				t.Fatal("corrupt MAC accepted")
			}
		})
	}
}
func TestMissingOrExpensiveMACFails(t *testing.T) {
	data, _ := fixture(t, Modern)
	var pfx pfxPdu
	if err := unmarshal(data, &pfx); err != nil {
		t.Fatal(err)
	}
	pfx.MacData.Iterations = maxInspectionIterations + 1
	altered, err := asn1.Marshal(pfx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := InspectCertificates(altered, "testpass"); err == nil || !strings.Contains(err.Error(), "iteration") {
		t.Fatalf("unbounded MAC accepted: %v", err)
	}
	pfx.MacData = macData{}
	altered, err = asn1.Marshal(pfx)
	if err == nil {
		if _, err = InspectCertificates(altered, ""); err == nil {
			t.Fatal("missing MAC accepted")
		}
	}
}
func TestPrivateKeyBagNotDecrypted(t *testing.T) {
	data, cert := fixture(t, Modern)
	var pfx pfxPdu
	if err := unmarshal(data, &pfx); err != nil {
		t.Fatal(err)
	}
	var authBytes []byte
	if err := unmarshal(pfx.AuthSafe.Content.Bytes, &authBytes); err != nil {
		t.Fatal(err)
	}
	var safe []contentInfo
	if err := unmarshal(authBytes, &safe); err != nil {
		t.Fatal(err)
	}
	changed := false
	for i := range safe {
		if !safe[i].ContentType.Equal(oidDataContentType) {
			continue
		}
		var bytes []byte
		if err := unmarshal(safe[i].Content.Bytes, &bytes); err != nil {
			t.Fatal(err)
		}
		var bags []safeBag
		if err := unmarshal(bytes, &bags); err != nil {
			t.Fatal(err)
		}
		for j := range bags {
			if bags[j].Id.Equal(oidPKCS8ShroundedKeyBag) {
				bags[j].Value = asn1.RawValue{Class: 2, Tag: 0, IsCompound: true, Bytes: []byte{0x05, 0x00}}
				changed = true
			}
		}
		if !changed {
			continue
		}
		bytes, err := asn1.Marshal(bags)
		if err != nil {
			t.Fatal(err)
		}
		encoded, err := asn1.Marshal(bytes)
		if err != nil {
			t.Fatal(err)
		}
		safe[i].Content = asn1.RawValue{Class: 2, Tag: 0, IsCompound: true, Bytes: encoded}
	}
	if !changed {
		t.Fatal("missing shrouded key fixture")
	}
	authBytes, err := asn1.Marshal(safe)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := asn1.Marshal(authBytes)
	if err != nil {
		t.Fatal(err)
	}
	pfx.AuthSafe.Content = asn1.RawValue{Class: 2, Tag: 0, IsCompound: true, Bytes: encoded}
	password, err := bmpStringZeroTerminated("testpass")
	if err != nil {
		t.Fatal(err)
	}
	if err := computeMac(&pfx.MacData, authBytes, password); err != nil {
		t.Fatal(err)
	}
	altered, err := asn1.Marshal(pfx)
	if err != nil {
		t.Fatal(err)
	}
	items, err := InspectCertificates(altered, "testpass")
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 1 || !items[0].Certificate.Equal(cert) {
		t.Fatalf("unexpected certificate: %+v", items)
	}
}
