package main

import (
	"bytes"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/agusibrahim/apksig-go/pkg/algo"
	"github.com/agusibrahim/apksig-go/pkg/apksigblock"
	"github.com/agusibrahim/apksig-go/pkg/buf"
	"github.com/agusibrahim/apksig-go/pkg/datasource"
	"github.com/agusibrahim/apksig-go/pkg/digest"
	"github.com/agusibrahim/apksig-go/pkg/pkcs7"
	v2 "github.com/agusibrahim/apksig-go/pkg/verifier/v2"
	v3 "github.com/agusibrahim/apksig-go/pkg/verifier/v3"
	apkzip "github.com/agusibrahim/apksig-go/pkg/zip"
)

// Verification is limited to this explicitly stated Android platform range.
// The result is deliberately stricter than the upstream library: unsupported or
// ambiguous signatures never produce verified=true.
const minSDK, maxSDK = 24, 35
const maxAPKSize = int64(1 << 30)
const maxCentralDir = int64(64 << 20)
const maxSigningBlock = int64(32 << 20)
const strippingProtectionID = uint32(0xbeeff00d)

type signer struct {
	SHA256  string `json:"sha256"`
	SHA1    string `json:"sha1"`
	Subject string `json:"subject"`
	Issuer  string `json:"issuer"`
	Scheme  string `json:"scheme"`
	MinSDK  int    `json:"minSdk,omitempty"`
	MaxSDK  int    `json:"maxSdk,omitempty"`
}
type result struct {
	Verified bool     `json:"verified"`
	Signers  []signer `json:"signers"`
	Schemes  []string `json:"schemes"`
	Warnings []string `json:"warnings"`
	Errors   []string `json:"errors"`
	Scope    string   `json:"scope"`
}

func emptyResult() result {
	return result{Signers: []signer{}, Schemes: []string{}, Warnings: []string{}, Errors: []string{}, Scope: "Android API 24–35; APK Signature Scheme v2/v3. v1-only, v3.1, rotation and multiple signers are not verified."}
}
func certificate(c *x509.Certificate, scheme string, low, high int) signer {
	sha256Digest := sha256.Sum256(c.Raw)
	sha1Digest := sha1.Sum(c.Raw)
	return signer{SHA256: hex.EncodeToString(sha256Digest[:]), SHA1: hex.EncodeToString(sha1Digest[:]), Subject: c.Subject.String(), Issuer: c.Issuer.String(), Scheme: scheme, MinSDK: low, MaxSDK: high}
}
func fail(r result, format string, args ...any) result {
	r.Errors = append(r.Errors, fmt.Sprintf(format, args...))
	return r
}

func verifyAPK(ds datasource.DataSource) result {
	r := emptyResult()
	if ds.Size() > maxAPKSize {
		return fail(r, "APK is larger than the 1 GiB safety limit.")
	}
	e, err := apkzip.FindEOCD(ds)
	if err != nil {
		return fail(r, "Invalid APK: %v", err)
	}
	if e.CDSize > maxCentralDir || e.CDStartOffset < 0 || e.CDStartOffset+e.CDSize != e.Offset {
		return fail(r, "Invalid or unsupported APK central directory.")
	}
	entries, err := apkzip.ParseCD(ds, e)
	if err != nil {
		return fail(r, "Invalid APK directory: %v", err)
	}
	names := make(map[string]bool, len(entries))
	for _, entry := range entries {
		if names[entry.Name] {
			return fail(r, "Duplicate ZIP entry is unsupported.")
		}
		names[entry.Name] = true
	}
	if e.CDStartOffset < 24 {
		r.Signers = v1Certificates(ds, entries)
		return fail(r, "No APK signing block: v1-only or unsigned APKs are not verified.")
	}
	footer := make([]byte, 24)
	if _, err = ds.ReadAt(footer, e.CDStartOffset-24); err != nil {
		return fail(r, "Cannot read APK signing footer.")
	}
	if string(footer[8:]) != "APK Sig Block 42" {
		r.Signers = v1Certificates(ds, entries)
		return fail(r, "No APK signing block: v1-only or unsigned APKs are not verified.")
	}
	sz := binary.LittleEndian.Uint64(footer[:8])
	if sz > uint64(maxSigningBlock-8) {
		return fail(r, "APK signing block exceeds safety limit.")
	}
	block, err := apksigblock.Find(ds, e)
	if err != nil {
		return fail(r, "Invalid APK signing block: %v", err)
	}
	seen := map[uint32]bool{}
	for _, p := range block.Pairs {
		if seen[p.ID] {
			return fail(r, "Duplicate APK signing block IDs are unsupported.")
		}
		seen[p.ID] = true
		switch p.ID {
		case apksigblock.IDV2Signature, apksigblock.IDV3Signature, apksigblock.IDV31Signature, apksigblock.IDSourceStampV1, apksigblock.IDSourceStampV2, apksigblock.IDPaddingPair, apksigblock.IDDependencyInfo:
		default:
			return fail(r, "Unknown APK signing block ID 0x%x is unsupported.", p.ID)
		}
	}
	patchedEOCD := append([]byte(nil), e.Bytes...)
	binary.LittleEndian.PutUint32(patchedEOCD[16:20], uint32(block.StartOffset))
	before := ds.Slice(0, block.StartOffset)
	central := ds.Slice(e.CDStartOffset, e.CDSize)
	got := map[algo.ContentDigest][]byte{}
	checkDigest := func(claimed map[algo.ContentDigest][]byte) error {
		if len(claimed) == 0 {
			return fmt.Errorf("no supported content digests")
		}
		for a, want := range claimed {
			if a != algo.ChunkedSHA256 && a != algo.ChunkedSHA512 {
				return fmt.Errorf("unsupported APK content digest")
			}
			actual, ok := got[a]
			if !ok {
				hashes, err := digest.Compute([]algo.ContentDigest{a}, before, central, patchedEOCD)
				if err != nil {
					return err
				}
				actual = hashes[a]
				got[a] = actual
			}
			if !bytes.Equal(actual, want) {
				return fmt.Errorf("APK content digest does not match; the file is modified or corrupted")
			}
		}
		return nil
	}
	var v2cert, v3cert *x509.Certificate
	v2ok, v3ok := false, false
	if p := block.FindPair(apksigblock.IDV2Signature); p != nil {
		r.Schemes = append(r.Schemes, "v2")
		parsed, err := v2.Verify(p.Value, minSDK, maxSDK)
		if err != nil {
			r.Errors = append(r.Errors, "v2 signature: "+err.Error())
		} else if parsed == nil || len(parsed.Signers) != 1 || len(parsed.Errors) > 0 {
			r.Errors = append(r.Errors, "v2: multiple signers or malformed signer data are unsupported.")
		} else {
			s := parsed.Signers[0]
			if len(s.Certs) > 0 {
				v2cert = s.Certs[0]
				r.Signers = append(r.Signers, certificate(v2cert, "v2", 24, 0))
			}
			if !parsed.Verified || !s.Verified || len(s.Errors) > 0 || len(s.Certs) == 0 {
				r.Errors = append(r.Errors, "v2 signature could not be verified.")
			} else if err := checkV2PublicKey(p.Value, v2cert); err != nil {
				r.Errors = append(r.Errors, "v2 public key: "+err.Error())
			} else if err := checkV2Attrs(s.AdditionalAttrs, seen); err != nil {
				r.Errors = append(r.Errors, "v2 attributes: "+err.Error())
			} else if err := checkAlgorithms(s.VerifiedAlgorithms, 24, false); err != nil {
				r.Errors = append(r.Errors, "v2 algorithms: "+err.Error())
			} else if err := checkDigest(s.ContentDigests); err != nil {
				r.Errors = append(r.Errors, "v2: "+err.Error())
			} else {
				v2ok = true
			}
		}
	}
	if p := block.FindPair(apksigblock.IDV3Signature); p != nil {
		r.Schemes = append(r.Schemes, "v3")
		parsed, err := v3.Verify(p.Value, minSDK, maxSDK)
		if err != nil {
			r.Errors = append(r.Errors, "v3 signature: "+err.Error())
		} else if parsed == nil || len(parsed.Signers) != 1 || len(parsed.Errors) > 0 {
			r.Errors = append(r.Errors, "v3: multiple signers or malformed signer data are unsupported.")
		} else {
			s := parsed.Signers[0]
			if len(s.Certs) > 0 {
				v3cert = s.Certs[0]
				r.Signers = append(r.Signers, certificate(v3cert, "v3", int(s.MinSDK), int(s.MaxSDK)))
			}
			if !parsed.Verified || !s.Verified || len(s.Errors) > 0 || len(s.Certs) == 0 {
				r.Errors = append(r.Errors, "v3 signature could not be verified.")
			} else if len(s.AdditionalAttrs) > 0 {
				r.Errors = append(r.Errors, "v3 attributes or key rotation are not supported.")
			} else if s.MinSDK > 28 || s.MaxSDK < maxSDK {
				r.Errors = append(r.Errors, "v3 signer does not cover the supported Android API 28–35 range.")
			} else if err := checkAlgorithms(s.VerifiedAlgorithms, 28, true); err != nil {
				r.Errors = append(r.Errors, "v3 algorithms: "+err.Error())
			} else if err := checkDigest(s.ContentDigests); err != nil {
				r.Errors = append(r.Errors, "v3: "+err.Error())
			} else {
				v3ok = true
			}
		}
	}
	if seen[apksigblock.IDV31Signature] {
		r.Schemes = append(r.Schemes, "v3.1")
		r.Errors = append(r.Errors, "v3.1 and rotated signing keys are not supported.")
	}
	if !v2ok {
		r.Errors = append(r.Errors, "A valid v2 signature is required for the Android API 24–27 portion of the stated range.")
	}
	if seen[apksigblock.IDV3Signature] && !v3ok {
		r.Errors = append(r.Errors, "APK v3 signature could not be verified.")
	}
	if v2cert != nil && v3cert != nil && !bytes.Equal(v2cert.Raw, v3cert.Raw) {
		r.Errors = append(r.Errors, "v2 and v3 certificates differ; rotated or API-dependent signers are unsupported.")
	}
	if len(r.Errors) == 0 && v2ok && (!seen[apksigblock.IDV3Signature] || v3ok) {
		r.Verified = true
		// A single identity is active throughout our supported API range.
		if v3cert != nil {
			r.Signers = []signer{certificate(v3cert, "v2 + v3", minSDK, maxSDK)}
		} else {
			r.Signers = []signer{certificate(v2cert, "v2", 24, maxSDK)}
		}
	}
	return r
}

// v1Certificates extracts only diagnostic certificates. It does not establish
// that an APK or even its JAR signature is valid; verified remains false.
func v1Certificates(ds datasource.DataSource, entries []apkzip.CDEntry) []signer {
	const maxSignatureBytes = 2 << 20
	var found []signer
	var candidates int
	seen := map[string]bool{}
	for i := range entries {
		e := &entries[i]
		name := strings.ToUpper(e.Name)
		if !strings.HasPrefix(name, "META-INF/") || strings.Contains(strings.TrimPrefix(name, "META-INF/"), "/") ||
			!(strings.HasSuffix(name, ".RSA") || strings.HasSuffix(name, ".DSA") || strings.HasSuffix(name, ".EC")) {
			continue
		}
		candidates++
		if candidates > 16 {
			break
		}
		// Avoid excessive allocation and ZIP-bomb expansion on untrusted input.
		if e.GeneralPurpose&1 != 0 || e.CompressedSize == 0 || e.UncompressedSize == 0 ||
			e.CompressedSize > maxSignatureBytes || e.UncompressedSize > maxSignatureBytes {
			continue
		}
		raw, err := apkzip.ReadEntry(ds, e)
		if err != nil {
			continue
		}
		parsed, err := pkcs7.Parse(raw)
		if err != nil {
			continue
		}
		for _, info := range parsed.SignerInfos {
			cert := parsed.FindSignerCert(info)
			if cert == nil {
				continue
			}
			s := certificate(cert, "v1 (unverified)", 0, 0)
			if !seen[s.SHA256] {
				seen[s.SHA256] = true
				found = append(found, s)
			}
			if len(found) >= 16 {
				return found
			}
		}
	}
	return found
}

// Upstream v1.1.0 incorrectly compares the certificate key to itself when a
// v2 signer's public-key bytes differ. Parse and validate that field ourselves.
func checkV2PublicKey(block []byte, cert *x509.Certificate) error {
	outer := buf.New(block)
	signers, err := outer.LengthPrefixedSlice()
	if err != nil || outer.Remaining() != 0 {
		return fmt.Errorf("malformed signer sequence")
	}
	one, err := signers.LengthPrefixedSlice()
	if err != nil || signers.Remaining() != 0 {
		return fmt.Errorf("expected exactly one signer")
	}
	if _, err = one.LengthPrefixedSlice(); err != nil {
		return err
	}
	if _, err = one.LengthPrefixedSlice(); err != nil {
		return err
	}
	encoded, err := one.LengthPrefixedBytes()
	if err != nil || one.Remaining() != 0 {
		return fmt.Errorf("malformed public key")
	}
	key, err := x509.ParsePKIXPublicKey(encoded)
	if err != nil {
		return err
	}
	normalized, err := x509.MarshalPKIXPublicKey(key)
	if err != nil {
		return err
	}
	certKey, err := x509.MarshalPKIXPublicKey(cert.PublicKey)
	if err != nil {
		return err
	}
	if !bytes.Equal(normalized, certKey) {
		return fmt.Errorf("signer public key does not match certificate")
	}
	return nil
}
func checkV2Attrs(attrs [][]byte, ids map[uint32]bool) error {
	seen := map[uint32]bool{}
	for _, a := range attrs {
		if len(a) != 8 {
			return fmt.Errorf("unknown or malformed attribute")
		}
		id := binary.LittleEndian.Uint32(a[:4])
		value := binary.LittleEndian.Uint32(a[4:])
		if seen[id] {
			return fmt.Errorf("duplicate attribute")
		}
		seen[id] = true
		if id != strippingProtectionID || value != 3 {
			return fmt.Errorf("unknown attribute")
		}
		if !ids[apksigblock.IDV3Signature] {
			return fmt.Errorf("v3 signature required by stripping-protection attribute")
		}
	}
	return nil
}
func checkAlgorithms(ids []algo.SigID, platform int, v3Scheme bool) error {
	if len(ids) == 0 {
		return fmt.Errorf("no verified signature algorithm")
	}
	seen := map[algo.SigID]bool{}
	digestSeen := map[algo.ContentDigest]bool{}
	compatible := false
	for _, id := range ids {
		if seen[id] {
			return fmt.Errorf("duplicate signature algorithm")
		}
		seen[id] = true
		a, ok := algo.ByID(id)
		if !ok {
			return fmt.Errorf("unknown signature algorithm")
		}
		if a.ContentDigest != algo.ChunkedSHA256 && a.ContentDigest != algo.ChunkedSHA512 {
			return fmt.Errorf("unsupported verity signature algorithm")
		}
		// The upstream result maps digests by content-hash type, so two
		// algorithms using the same type would overwrite one another. Do not
		// claim verification unless every signed digest was checked.
		if digestSeen[a.ContentDigest] {
			return fmt.Errorf("multiple signatures using the same content digest are unsupported")
		}
		digestSeen[a.ContentDigest] = true
		if (!v3Scheme && a.MinSdkV2 <= platform) || (v3Scheme && a.MinSdkV3 <= platform) {
			compatible = true
		}
	}
	if !compatible {
		return fmt.Errorf("no signature algorithm supports the full stated Android API range")
	}
	return nil
}
