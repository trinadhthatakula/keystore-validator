// Package bcfks inspects password-MAC protected Bouncy Castle BCFKS stores.
// It opens the outer container and reads certificate metadata without
// decrypting any individual private or secret-key entry.
package bcfks

import (
	"crypto/aes"
	"crypto/hmac"
	"crypto/pbkdf2"
	"crypto/sha3"
	"crypto/sha512"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"hash"
	"unicode/utf16"
	"unicode/utf8"

	"github.com/pion/dtls/v3/pkg/crypto/ccm"
	"golang.org/x/crypto/scrypt"
)

var (
	ErrFormat       = errors.New("malformed BCFKS store")
	ErrIntegrity    = errors.New("incorrect password or damaged BCFKS store")
	ErrUnsupported  = errors.New("unsupported BCFKS parameters")
	oidPBES2        = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5, 13}
	oidPBKDF2       = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5, 12}
	oidScrypt       = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 11591, 4, 11}
	oidHMACSHA512   = asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 11}
	oidHMACSHA3_512 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 16}
	oidAES256CCM    = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 47}
)

const maxElements = 4096
const maxIterations = 1_000_000
const maxSalt = 1024

type Entry struct {
	Alias       string
	EntryType   string
	Certificate *x509.Certificate
}
type algorithm struct {
	oid    asn1.ObjectIdentifier
	params asn1.RawValue
}

type kdfParams struct {
	salt       []byte
	iterations int
	keyLen     int
	hash       func() hash.Hash
	scryptN    int
	scryptR    int
}

func elements(raw asn1.RawValue, limit int) ([]asn1.RawValue, error) {
	if raw.Class != 0 || raw.Tag != asn1.TagSequence || !raw.IsCompound {
		return nil, ErrFormat
	}
	var out []asn1.RawValue
	rest := raw.Bytes
	for len(rest) > 0 {
		if len(out) >= limit {
			return nil, ErrUnsupported
		}
		var value asn1.RawValue
		tail, err := asn1.Unmarshal(rest, &value)
		if err != nil || len(tail) >= len(rest) {
			return nil, ErrFormat
		}
		out = append(out, value)
		rest = tail
	}
	return out, nil
}
func top(data []byte) (asn1.RawValue, error) {
	var r asn1.RawValue
	remain, err := asn1.Unmarshal(data, &r)
	if err != nil || len(remain) != 0 {
		return r, ErrFormat
	}
	return r, nil
}
func parseAlg(raw asn1.RawValue) (algorithm, error) {
	fields, err := elements(raw, 2)
	if err != nil || len(fields) < 1 {
		return algorithm{}, ErrFormat
	}
	var id asn1.ObjectIdentifier
	rest, err := asn1.Unmarshal(fields[0].FullBytes, &id)
	if err != nil || len(rest) != 0 {
		return algorithm{}, ErrFormat
	}
	a := algorithm{oid: id}
	if len(fields) == 2 {
		a.params = fields[1]
	}
	return a, nil
}
func integer(raw asn1.RawValue) (int, error) {
	var n int
	rest, err := asn1.Unmarshal(raw.FullBytes, &n)
	if err != nil || len(rest) != 0 || n < 0 {
		return 0, ErrFormat
	}
	return n, nil
}
func octets(raw asn1.RawValue) ([]byte, error) {
	if raw.Class != 0 || raw.Tag != asn1.TagOctetString || raw.IsCompound {
		return nil, ErrFormat
	}
	return raw.Bytes, nil
}
func digestFor(id asn1.ObjectIdentifier) (func() hash.Hash, error) {
	switch {
	case id.Equal(oidHMACSHA512):
		return sha512.New, nil
	case id.Equal(oidHMACSHA3_512):
		return func() hash.Hash { return sha3.New512() }, nil
	default:
		return nil, ErrUnsupported
	}
}
func parseKDF(raw asn1.RawValue, expectedKeyLen int) (kdfParams, error) {
	a, err := parseAlg(raw)
	if err != nil {
		return kdfParams{}, ErrUnsupported
	}
	if a.oid.Equal(oidScrypt) {
		fields, err := elements(a.params, 5)
		if err != nil || len(fields) < 4 {
			return kdfParams{}, ErrFormat
		}
		salt, err := octets(fields[0])
		if err != nil || len(salt) == 0 || len(salt) > maxSalt {
			return kdfParams{}, ErrUnsupported
		}
		n, err := integer(fields[1])
		if err != nil || n < 2 || n&(n-1) != 0 {
			return kdfParams{}, ErrUnsupported
		}
		r, err := integer(fields[2])
		if err != nil || r < 1 || r > 32 {
			return kdfParams{}, ErrUnsupported
		}
		p, err := integer(fields[3])
		if err != nil || p < 1 || p > 32 {
			return kdfParams{}, ErrUnsupported
		}
		if len(fields) == 5 {
			keyLen, err := integer(fields[4])
			if err != nil || keyLen != expectedKeyLen {
				return kdfParams{}, ErrUnsupported
			}
		}
		// Bouncy Castle's BCFKS KDF uses r as the parallelization value.
		// Bound both memory and work before processing an untrusted store.
		if uint64(n)*uint64(r)*128 > 64<<20 || uint64(n)*uint64(r)*uint64(r) > 4<<20 {
			return kdfParams{}, ErrUnsupported
		}
		return kdfParams{salt: salt, keyLen: expectedKeyLen, scryptN: n, scryptR: r}, nil
	}
	if !a.oid.Equal(oidPBKDF2) {
		return kdfParams{}, ErrUnsupported
	}
	fields, err := elements(a.params, 4)
	if err != nil || len(fields) < 3 {
		return kdfParams{}, ErrFormat
	}
	salt, err := octets(fields[0])
	if err != nil || len(salt) == 0 || len(salt) > maxSalt {
		return kdfParams{}, ErrUnsupported
	}
	count, err := integer(fields[1])
	if err != nil || count < 1 || count > maxIterations {
		return kdfParams{}, ErrUnsupported
	}
	pos, keyLen := 2, expectedKeyLen
	if fields[pos].Class == 0 && fields[pos].Tag == asn1.TagInteger {
		keyLen, err = integer(fields[pos])
		if err != nil || keyLen != expectedKeyLen {
			return kdfParams{}, ErrUnsupported
		}
		pos++
	}
	if pos != len(fields)-1 {
		return kdfParams{}, ErrUnsupported
	}
	prf, err := parseAlg(fields[pos])
	if err != nil {
		return kdfParams{}, err
	}
	fn, err := digestFor(prf.oid)
	if err != nil {
		return kdfParams{}, err
	}
	return kdfParams{salt: salt, iterations: count, keyLen: keyLen, hash: fn}, nil
}
func pkcs12Chars(value string) []byte {
	units := utf16.Encode([]rune(value))
	if len(units) == 0 {
		return nil
	}
	out := make([]byte, 0, (len(units)+1)*2)
	for _, u := range units {
		out = append(out, byte(u>>8), byte(u))
	}
	return append(out, 0, 0)
}
func derive(params kdfParams, password, purpose string) ([]byte, error) {
	pass := pkcs12Chars(password)
	suffix := pkcs12Chars(purpose)
	material := append(pass, suffix...)
	defer clear(material)
	defer clear(suffix)
	if params.scryptN != 0 {
		return scrypt.Key(material, params.salt, params.scryptN, params.scryptR, params.scryptR, params.keyLen)
	}
	return pbkdf2.Key(params.hash, string(material), params.salt, params.iterations, params.keyLen)
}

// LooksLike is a conservative structural check; successful inspection also
// requires the actual MAC and authenticated decryption to verify.
func LooksLike(data []byte) bool {
	raw, err := top(data)
	if err != nil {
		return false
	}
	outer, err := elements(raw, 2)
	if err != nil || len(outer) != 2 {
		return false
	}
	encrypted, err := elements(outer[0], 2)
	if err != nil || len(encrypted) != 2 {
		return false
	}
	alg, err := parseAlg(encrypted[0])
	if err != nil || !alg.oid.Equal(oidPBES2) {
		return false
	}
	_, err = octets(encrypted[1])
	return err == nil
}

func Inspect(data []byte, password string) ([]Entry, error) {
	if len(data) > 16<<20 || len(password) > 16<<10 {
		return nil, ErrUnsupported
	}
	raw, err := top(data)
	if err != nil {
		return nil, err
	}
	outer, err := elements(raw, 2)
	if err != nil || len(outer) != 2 {
		return nil, ErrFormat
	}
	integrity, err := elements(outer[1], 3)
	if err != nil || len(integrity) != 3 {
		return nil, ErrUnsupported
	}
	macAlg, err := parseAlg(integrity[0])
	if err != nil {
		return nil, err
	}
	macHash, err := digestFor(macAlg.oid)
	if err != nil {
		return nil, err
	}
	macKDF, err := parseKDF(integrity[1], 64)
	if err != nil {
		return nil, err
	}
	expectedMAC, err := octets(integrity[2])
	if err != nil || len(expectedMAC) != macHash().Size() {
		return nil, ErrFormat
	}
	macKey, err := derive(macKDF, password, "INTEGRITY_CHECK")
	if err != nil {
		return nil, ErrUnsupported
	}
	defer clear(macKey)
	mac := hmac.New(macHash, macKey)
	mac.Write(outer[0].FullBytes)
	if !hmac.Equal(mac.Sum(nil), expectedMAC) {
		return nil, ErrIntegrity
	}

	encrypted, err := elements(outer[0], 2)
	if err != nil || len(encrypted) != 2 {
		return nil, ErrFormat
	}
	protect, err := parseAlg(encrypted[0])
	if err != nil || !protect.oid.Equal(oidPBES2) {
		return nil, ErrUnsupported
	}
	params, err := elements(protect.params, 2)
	if err != nil || len(params) != 2 {
		return nil, ErrFormat
	}
	storeKDF, err := parseKDF(params[0], 32)
	if err != nil {
		return nil, err
	}
	enc, err := parseAlg(params[1])
	if err != nil || !enc.oid.Equal(oidAES256CCM) {
		return nil, ErrUnsupported
	}
	ccmParams, err := elements(enc.params, 2)
	if err != nil || len(ccmParams) < 1 {
		return nil, ErrFormat
	}
	nonce, err := octets(ccmParams[0])
	if err != nil || len(nonce) < 7 || len(nonce) > 13 {
		return nil, ErrUnsupported
	}
	tagSize := 12
	if len(ccmParams) == 2 {
		tagSize, err = integer(ccmParams[1])
		if err != nil {
			return nil, err
		}
	}
	ciphertext, err := octets(encrypted[1])
	if err != nil {
		return nil, err
	}
	storeKey, err := derive(storeKDF, password, "STORE_ENCRYPTION")
	if err != nil {
		return nil, ErrUnsupported
	}
	defer clear(storeKey)
	block, err := aes.NewCipher(storeKey)
	if err != nil {
		return nil, ErrUnsupported
	}
	aead, err := ccm.NewCCM(block, tagSize, len(nonce))
	if err != nil {
		return nil, ErrUnsupported
	}
	plain, err := aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, ErrIntegrity
	}
	defer clear(plain)
	return parseStore(plain, macAlg.oid)
}
func parseStore(data []byte, macAlg asn1.ObjectIdentifier) ([]Entry, error) {
	raw, err := top(data)
	if err != nil {
		return nil, err
	}
	fields, err := elements(raw, 6)
	if err != nil || len(fields) < 5 {
		return nil, ErrFormat
	}
	version, err := integer(fields[0])
	if err != nil || version != 1 {
		return nil, ErrUnsupported
	}
	checkAlg, err := parseAlg(fields[1])
	if err != nil || !checkAlg.oid.Equal(macAlg) {
		return nil, ErrFormat
	}
	if fields[2].Class != 0 || fields[2].Tag != asn1.TagGeneralizedTime || fields[3].Class != 0 || fields[3].Tag != asn1.TagGeneralizedTime {
		return nil, ErrFormat
	}
	objects, err := elements(fields[4], maxElements)
	if err != nil {
		return nil, err
	}
	var out []Entry
	aliases := map[string]bool{}
	for _, rawObj := range objects {
		entry, err := elements(rawObj, 6)
		if err != nil || len(entry) < 5 {
			return nil, ErrFormat
		}
		kind, err := integer(entry[0])
		if err != nil {
			return nil, err
		}
		if entry[1].Class != 0 || entry[1].Tag != asn1.TagUTF8String || len(entry[1].Bytes) > 4096 || !utf8.Valid(entry[1].Bytes) {
			return nil, ErrFormat
		}
		alias := string(entry[1].Bytes)
		if alias == "" || aliases[alias] {
			return nil, ErrFormat
		}
		aliases[alias] = true
		if entry[2].Class != 0 || entry[2].Tag != asn1.TagGeneralizedTime || entry[3].Class != 0 || entry[3].Tag != asn1.TagGeneralizedTime {
			return nil, ErrFormat
		}
		value, err := octets(entry[4])
		if err != nil {
			return nil, err
		}
		var certBytes []byte
		entryType := ""
		switch kind {
		case 0:
			certBytes = value
			entryType = "trusted-certificate"
		case 1, 3:
			private, err := top(value)
			if err != nil {
				return nil, err
			}
			fields, err := elements(private, 2)
			if err != nil || len(fields) != 2 {
				return nil, ErrFormat
			}
			chain, err := elements(fields[1], 128)
			if err != nil || len(chain) == 0 {
				return nil, ErrFormat
			}
			certBytes = chain[0].FullBytes
			entryType = "private-key"
		case 2, 4, 5:
			continue // no certificate; never decrypt secret keys
		default:
			return nil, ErrUnsupported
		}
		// The decrypted container is cleared after parsing; certificates need
		// their own backing bytes so their fingerprints remain intact.
		cert, err := x509.ParseCertificate(append([]byte(nil), certBytes...))
		if err != nil {
			return nil, ErrFormat
		}
		out = append(out, Entry{Alias: alias, EntryType: entryType, Certificate: cert})
	}
	return out, nil
}
