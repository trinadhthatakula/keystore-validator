package main

import (
	"bytes"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode/utf16"

	keystore "github.com/pavlo-v-chernykh/keystore-go/v4"
	"keystorevalidator/jks/bcfks"
	"keystorevalidator/jks/bks"
	"keystorevalidator/jks/jceks"
	"keystorevalidator/jks/x509cert"
	pkcs12 "software.sslmate.com/src/go-pkcs12"
)

const (
	maxStoreBytes    = 16 * 1024 * 1024
	maxEntries       = 4096
	maxCertChain     = 128
	maxPasswordBytes = 16 * 1024
)

type inspectError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

type certificateEntry struct {
	Alias     string `json:"alias"`
	EntryType string `json:"entryType"`
	Subject   string `json:"subject"`
	Issuer    string `json:"issuer"`
	NotBefore string `json:"notBefore"`
	NotAfter  string `json:"notAfter"`
	SHA256    string `json:"sha256"`
	SHA1      string `json:"sha1"`
}

type inspectResult struct {
	OK        bool               `json:"ok"`
	Format    string             `json:"format,omitempty"`
	Integrity string             `json:"integrity,omitempty"`
	Aliases   []certificateEntry `json:"aliases"`
	Error     *inspectError      `json:"error,omitempty"`
}

func failure(code, message string) inspectResult {
	return inspectResult{Error: &inspectError{Code: code, Message: message}}
}

// Inspect verifies the JKS store integrity before reading public certificates.
// It never asks for or decrypts a private key. JKS has no way to reliably
// distinguish an incorrect password from an altered integrity digest.
func Inspect(data []byte, password string) inspectResult {
	if len(data) > maxStoreBytes {
		return failure("FILE_TOO_LARGE", "Keystores larger than 16 MiB are not supported.")
	}
	if len(password) > maxPasswordBytes {
		return failure("PASSWORD_TOO_LONG", "The store password is too long.")
	}
	format := "JKS"
	if jceks.LooksLike(data) {
		converted, err := jceks.AsJKS(data, password)
		if errors.Is(err, jceks.ErrIntegrity) {
			return failure("INTEGRITY_ERROR", "The store password is incorrect or the keystore is damaged.")
		}
		if err != nil {
			return failure("INVALID_JCEKS", "This JCEKS is malformed or exceeds supported limits.")
		}
		defer clear(converted)
		data = converted
		format = "JCEKS"
	} else if bks.LooksLike(data) {
		return inspectBKS(data, password)
	} else if len(data) < 4 || binary.BigEndian.Uint32(data[:4]) != 0xfeedfeed {
		if looksLikePKCS12(data) {
			return inspectPKCS12(data, password)
		}
		if bcfks.LooksLike(data) {
			return inspectBCFKS(data, password)
		}
		certs, recognized, err := x509cert.Parse(data)
		if recognized {
			if err != nil {
				return failure("INVALID_CERTIFICATE", err.Error())
			}
			entries := make([]certificateEntry, 0, len(certs))
			for i, cert := range certs {
				entries = append(entries, certificateDetails(fmt.Sprintf("Certificate %d", i+1), "certificate", cert))
			}
			return inspectResult{OK: true, Format: "X.509", Aliases: entries}
		}
		return failure("UNSUPPORTED_FORMAT", "This format is not supported. Select a JKS, JCEKS, PKCS#12, BKS, UBER, BCFKS, or X.509 certificate file.")
	}

	aliases, err := preflight(data)
	if err != nil {
		if format == "JCEKS" {
			return failure("INVALID_JCEKS", "This JCEKS is damaged or contains unsupported secret-key entries.")
		}
		return failure("INVALID_JKS", "This JKS is malformed, damaged, or exceeds supported limits.")
	}
	// The pinned decoder allocates using file-provided lengths. preflight validates
	// every allocation and count against actual data before the decoder sees it.
	ks := keystore.New(keystore.WithCaseExactAliases())
	passwordBytes := []byte(password)
	defer clear(passwordBytes)
	if err := ks.Load(bytes.NewReader(data), passwordBytes); err != nil {
		return failure("INTEGRITY_ERROR", "The store password is incorrect or the keystore is damaged.")
	}
	entries := make([]certificateEntry, 0, len(aliases))
	for _, alias := range aliases {
		var cert keystore.Certificate
		entryType := ""
		if ks.IsPrivateKeyEntry(alias.raw) {
			entryType = "private-key"
			chain, err := ks.GetPrivateKeyEntryCertificateChain(alias.raw)
			if err != nil || len(chain) == 0 {
				return failure("NO_CERTIFICATE", "An entry does not contain a readable signing certificate.")
			}
			cert = chain[0]
		} else if ks.IsTrustedCertificateEntry(alias.raw) {
			entryType = "trusted-certificate"
			trusted, err := ks.GetTrustedCertificateEntry(alias.raw)
			if err != nil {
				return failure("INVALID_JKS", "An entry could not be read.")
			}
			cert = trusted.Certificate
		} else {
			return failure("INVALID_JKS", "An entry could not be read.")
		}
		x509Cert, err := x509.ParseCertificate(cert.Content)
		if err != nil {
			return failure("INVALID_CERTIFICATE", "An entry contains an invalid or unsupported X.509 certificate.")
		}
		sum256, sum1 := sha256.Sum256(cert.Content), sha1.Sum(cert.Content)
		entries = append(entries, certificateEntry{
			Alias: alias.display, EntryType: entryType,
			Subject: x509Cert.Subject.String(), Issuer: x509Cert.Issuer.String(),
			NotBefore: x509Cert.NotBefore.UTC().Format(time.RFC3339),
			NotAfter:  x509Cert.NotAfter.UTC().Format(time.RFC3339),
			SHA256:    fingerprint(sum256[:]), SHA1: fingerprint(sum1[:]),
		})
	}
	return inspectResult{OK: true, Format: format, Aliases: entries}
}

func inspectBCFKS(data []byte, password string) inspectResult {
	items, err := bcfks.Inspect(data, password)
	if errors.Is(err, bcfks.ErrIntegrity) {
		return failure("INTEGRITY_ERROR", "The store password is incorrect or the keystore is damaged.")
	}
	if err != nil {
		return failure("INVALID_BCFKS", "This BCFKS store is damaged or uses unsupported protection parameters.")
	}
	entries := make([]certificateEntry, 0, len(items))
	for _, item := range items {
		entries = append(entries, certificateDetails(item.Alias, item.EntryType, item.Certificate))
	}
	return inspectResult{OK: true, Format: "BCFKS", Aliases: entries}
}

func certificateDetails(alias, kind string, cert *x509.Certificate) certificateEntry {
	sha256sum, sha1sum := sha256.Sum256(cert.Raw), sha1.Sum(cert.Raw)
	return certificateEntry{Alias: alias, EntryType: kind, Subject: cert.Subject.String(), Issuer: cert.Issuer.String(), NotBefore: cert.NotBefore.UTC().Format(time.RFC3339), NotAfter: cert.NotAfter.UTC().Format(time.RFC3339), SHA256: fingerprint(sha256sum[:]), SHA1: fingerprint(sha1sum[:])}
}

func inspectBKS(data []byte, password string) inspectResult {
	store, err := bks.Inspect(data, password)
	format := "BKS"
	if err != nil {
		// UBER uses the same outer header as BKS, but encrypts the payload.
		if uber, uberErr := bks.InspectUber(data, password); uberErr == nil {
			store, err, format = uber, nil, "UBER"
		} else if errors.Is(uberErr, bks.ErrIntegrity) {
			err = bks.ErrIntegrity
		}
	}
	if errors.Is(err, bks.ErrIntegrity) {
		return failure("INTEGRITY_ERROR", "The store password is incorrect or the keystore is damaged.")
	}
	if err != nil {
		return failure("INVALID_BKS", "This BKS store is damaged or uses unsupported entries.")
	}
	entries := make([]certificateEntry, 0, len(store.Entries))
	for _, item := range store.Entries {
		cert, err := x509.ParseCertificate(item.Certificate)
		if err != nil {
			return failure("INVALID_CERTIFICATE", "An entry contains an invalid or unsupported X.509 certificate.")
		}
		entries = append(entries, certificateDetails(item.Alias, item.EntryType, cert))
	}
	integrity := ""
	if store.WeakIntegrity {
		integrity = "weak"
	}
	return inspectResult{OK: true, Format: format, Integrity: integrity, Aliases: entries}
}

func inspectPKCS12(data []byte, password string) inspectResult {
	items, err := pkcs12.InspectCertificates(data, password)
	if err != nil {
		if errors.Is(err, pkcs12.ErrIncorrectPassword) {
			return failure("INTEGRITY_ERROR", "The store password is incorrect or the keystore is damaged.")
		}
		return failure("INVALID_PKCS12", "This PKCS#12 store is damaged or uses unsupported encryption or certificate metadata.")
	}
	entries := make([]certificateEntry, 0, len(items))
	for _, item := range items {
		cert := item.Certificate
		entries = append(entries, certificateDetails(item.Alias, item.EntryType, cert))
	}
	return inspectResult{OK: true, Format: "PKCS#12", Aliases: entries}
}

func fingerprint(digest []byte) string {
	str := strings.ToUpper(hex.EncodeToString(digest))
	var b strings.Builder
	b.Grow(len(str) + len(digest) - 1)
	for i := 0; i < len(str); i += 2 {
		if i != 0 {
			b.WriteByte(':')
		}
		b.WriteString(str[i : i+2])
	}
	return b.String()
}

func looksLikePKCS12(data []byte) bool {
	var seq asn1.RawValue
	rest, err := asn1.Unmarshal(data, &seq)
	if err != nil || len(rest) != 0 || seq.Class != 0 || seq.Tag != 16 {
		return false
	}
	var version int
	inside, err := asn1.Unmarshal(seq.Bytes, &version)
	if err != nil || version != 3 {
		return false
	}
	var content asn1.RawValue
	_, err = asn1.Unmarshal(inside, &content)
	if err != nil || content.Class != 0 || content.Tag != 16 {
		return false
	}
	var oid asn1.ObjectIdentifier
	_, err = asn1.Unmarshal(content.Bytes, &oid)
	return err == nil && (oid.Equal(asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 1}) || oid.Equal(asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 6}))
}

type storeAlias struct{ raw, display string }
type inputReader struct {
	b   []byte
	pos int
}

func (r *inputReader) take(n uint64) ([]byte, error) {
	if n > uint64(len(r.b)-r.pos) {
		return nil, errors.New("truncated")
	}
	start := r.pos
	r.pos += int(n)
	return r.b[start:r.pos], nil
}
func (r *inputReader) u16() (uint16, error) {
	b, e := r.take(2)
	if e != nil {
		return 0, e
	}
	return binary.BigEndian.Uint16(b), nil
}
func (r *inputReader) u32() (uint32, error) {
	b, e := r.take(4)
	if e != nil {
		return 0, e
	}
	return binary.BigEndian.Uint32(b), nil
}
func (r *inputReader) javaString() ([]byte, error) {
	n, e := r.u16()
	if e != nil {
		return nil, e
	}
	return r.take(uint64(n))
}
func (r *inputReader) certificate(version uint32) error {
	if version == 2 {
		if _, e := r.javaString(); e != nil {
			return e
		}
	}
	n, e := r.u32()
	if e != nil {
		return e
	}
	if n == 0 {
		return errors.New("empty certificate")
	}
	_, e = r.take(uint64(n))
	return e
}

// Java's DataInput.readUTF uses modified UTF-8 (including UTF-16 surrogate
// pairs), not ordinary UTF-8. Decode it strictly for display while preserving
// the original bytes for lookups into the upstream parser.
func decodeModifiedUTF8(input []byte) (string, error) {
	units := make([]uint16, 0, len(input))
	for i := 0; i < len(input); {
		b := input[i]
		switch {
		case b >= 1 && b <= 0x7f:
			units = append(units, uint16(b))
			i++
		case b >= 0xc0 && b <= 0xdf:
			if i+1 >= len(input) || input[i+1]&0xc0 != 0x80 {
				return "", errors.New("invalid modified UTF-8")
			}
			v := uint16(b&0x1f)<<6 | uint16(input[i+1]&0x3f)
			if v < 0x80 && !(b == 0xc0 && input[i+1] == 0x80) {
				return "", errors.New("overlong modified UTF-8")
			}
			units = append(units, v)
			i += 2
		case b >= 0xe0 && b <= 0xef:
			if i+2 >= len(input) || input[i+1]&0xc0 != 0x80 || input[i+2]&0xc0 != 0x80 {
				return "", errors.New("invalid modified UTF-8")
			}
			v := uint16(b&0x0f)<<12 | uint16(input[i+1]&0x3f)<<6 | uint16(input[i+2]&0x3f)
			if v < 0x800 {
				return "", errors.New("overlong modified UTF-8")
			}
			units = append(units, v)
			i += 3
		default:
			return "", errors.New("invalid modified UTF-8")
		}
	}
	for i := 0; i < len(units); i++ {
		if units[i] >= 0xd800 && units[i] <= 0xdbff {
			if i+1 >= len(units) || units[i+1] < 0xdc00 || units[i+1] > 0xdfff {
				return "", errors.New("unpaired surrogate")
			}
			i++
		} else if units[i] >= 0xdc00 && units[i] <= 0xdfff {
			return "", errors.New("unpaired surrogate")
		}
	}
	return string(utf16.Decode(units)), nil
}

func preflight(data []byte) ([]storeAlias, error) {
	if len(data) < 32 {
		return nil, errors.New("truncated")
	}
	// The final 20 bytes are the SHA-1 store-integrity digest.
	r := inputReader{b: data[:len(data)-20]}
	magic, e := r.u32()
	if e != nil || magic != 0xfeedfeed {
		return nil, errors.New("invalid magic")
	}
	version, e := r.u32()
	if e != nil || (version != 1 && version != 2) {
		return nil, errors.New("unsupported version")
	}
	count, e := r.u32()
	if e != nil || count > maxEntries {
		return nil, errors.New("invalid entry count")
	}
	aliases := make([]storeAlias, 0, count)
	seen := make(map[string]bool)
	for i := uint32(0); i < count; i++ {
		tag, e := r.u32()
		if e != nil {
			return nil, e
		}
		raw, e := r.javaString()
		if e != nil {
			return nil, e
		}
		display, e := decodeModifiedUTF8(raw)
		if e != nil {
			return nil, e
		}
		if seen[display] {
			return nil, fmt.Errorf("duplicate alias")
		}
		seen[display] = true
		aliases = append(aliases, storeAlias{raw: string(raw), display: display})
		if _, e = r.take(8); e != nil {
			return nil, e
		}
		switch tag {
		case 1:
			n, e := r.u32()
			if e != nil {
				return nil, e
			}
			if _, e = r.take(uint64(n)); e != nil {
				return nil, e
			}
			certs, e := r.u32()
			if e != nil || certs > maxCertChain {
				return nil, errors.New("invalid certificate count")
			}
			for j := uint32(0); j < certs; j++ {
				if e = r.certificate(version); e != nil {
					return nil, e
				}
			}
		case 2:
			if e = r.certificate(version); e != nil {
				return nil, e
			}
		default:
			return nil, errors.New("invalid tag")
		}
	}
	if r.pos != len(r.b) {
		return nil, errors.New("trailing or missing data")
	}
	return aliases, nil
}
