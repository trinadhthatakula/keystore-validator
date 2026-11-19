// Package x509cert reads public X.509 certificates without opening private keys.
package x509cert

import (
	"bytes"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"errors"
)

const maxCertificates = 128

var ErrInvalid = errors.New("invalid or unsupported X.509 certificate")
var ErrPrivateKeyOnly = errors.New("select the X.509 certificate supplied with the private key; a private key alone has no signing certificate")

// Parse returns certificates, whether the data was recognizable as an X.509
// certificate or PEM, and an error. PEM private-key blocks are never decoded.
func Parse(data []byte) ([]*x509.Certificate, bool, error) {
	const begin = "-----BEGIN CERTIFICATE-----"
	const end = "-----END CERTIFICATE-----"
	if bytes.Contains(data, []byte("-----BEGIN ")) {
		var certs []*x509.Certificate
		remaining := data
		for {
			start := bytes.Index(remaining, []byte(begin))
			if start < 0 {
				break
			}
			remaining = remaining[start:]
			endAt := bytes.Index(remaining, []byte(end))
			if endAt < 0 {
				return nil, true, ErrInvalid
			}
			endAt += len(end)
			block, _ := pem.Decode(remaining[:endAt])
			if block == nil || block.Type != "CERTIFICATE" {
				return nil, true, ErrInvalid
			}
			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				return nil, true, ErrInvalid
			}
			certs = append(certs, cert)
			if len(certs) > maxCertificates {
				return nil, true, ErrInvalid
			}
			remaining = remaining[endAt:]
		}
		if len(certs) == 0 {
			if bytes.Contains(data, []byte("PRIVATE KEY-----")) {
				return nil, true, ErrPrivateKeyOnly
			}
			return nil, true, ErrInvalid
		}
		return certs, true, nil
	}
	certs, err := x509.ParseCertificates(data)
	if err != nil {
		if looksLikePKCS8(data) {
			return nil, true, ErrPrivateKeyOnly
		}
		return nil, false, nil
	}
	if len(certs) == 0 || len(certs) > maxCertificates {
		return nil, true, ErrInvalid
	}
	return certs, true, nil
}

// Recognize the outer structure only; do not decrypt or parse key material.
func looksLikePKCS8(data []byte) bool {
	var sequence asn1.RawValue
	rest, err := asn1.Unmarshal(data, &sequence)
	if err != nil || len(rest) != 0 || sequence.Class != 0 || sequence.Tag != 16 {
		return false
	}
	var first, second, third asn1.RawValue
	remain, err := asn1.Unmarshal(sequence.Bytes, &first)
	if err != nil {
		return false
	}
	remain, err = asn1.Unmarshal(remain, &second)
	if err != nil {
		return false
	}
	if first.Class == 0 && first.Tag == 16 && second.Class == 0 && second.Tag == 4 {
		return true
	}
	if first.Class != 0 || first.Tag != 2 || second.Class != 0 || second.Tag != 16 {
		return false
	}
	_, err = asn1.Unmarshal(remain, &third)
	return err == nil && third.Class == 0 && third.Tag == 4
}
