// Package bks reads certificate metadata from a Bouncy Castle BKS store.
// Private keys and secret-key payloads are not decrypted or returned.
package bks

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/binary"
	"errors"
	"fmt"
	"unicode/utf16"
)

var (
	ErrFormat      = errors.New("malformed BKS keystore")
	ErrIntegrity   = errors.New("BKS password is incorrect or keystore integrity is invalid")
	ErrUnsupported = errors.New("unsupported BKS format or resource limits")
)

const (
	maxStoreBytes    = 16 << 20
	maxPasswordBytes = 16 << 10
	maxSaltBytes     = 1024
	maxIterations    = 1_000_000
	maxEntries       = 4096
	maxChain         = 128
	sha1Bytes        = 20
)

type Entry struct {
	Alias string
	// A BKS sealed key is not decrypted, so its actual type cannot be known.
	EntryType   string
	Certificate []byte
}
type Result struct {
	Version       uint32
	WeakIntegrity bool
	Entries       []Entry
}

// LooksLike is a conservative header check; Inspect must still validate MAC and structure.
func LooksLike(data []byte) bool {
	if len(data) < 4+4+1+4+1+sha1Bytes {
		return false
	}
	version := binary.BigEndian.Uint32(data[:4])
	if version > 2 {
		return false
	}
	saltLen := binary.BigEndian.Uint32(data[4:8])
	return saltLen > 0 && saltLen <= maxSaltBytes && uint64(saltLen)+4+4+4+1+sha1Bytes <= uint64(len(data))
}

// Inspect verifies the BKS MAC before parsing any entries. Versions 0/1 use
// only a brute-forceable 16-bit MAC key and must be reported as weak.
func Inspect(data []byte, password string) (*Result, error) {
	if len(data) > maxStoreBytes || len(password) > maxPasswordBytes {
		return nil, ErrUnsupported
	}
	if !LooksLike(data) {
		return nil, ErrFormat
	}
	version := binary.BigEndian.Uint32(data[:4])
	saltLen := int(binary.BigEndian.Uint32(data[4:8]))
	iterationPos := 8 + saltLen
	salt := data[8:iterationPos]
	iterations := binary.BigEndian.Uint32(data[iterationPos : iterationPos+4])
	if iterations == 0 || iterations > maxIterations {
		return nil, ErrUnsupported
	}
	payload := data[iterationPos+4 : len(data)-sha1Bytes]
	if len(payload) == 0 || payload[len(payload)-1] != 0 {
		return nil, ErrFormat
	}
	keyLength := sha1Bytes
	if version < 2 {
		keyLength = 2
	}
	key := deriveMACKey(password, salt, int(iterations), keyLength)
	mac := hmac.New(sha1.New, key)
	mac.Write(payload)
	computed := mac.Sum(nil)
	clear(key)
	if !hmac.Equal(computed, data[len(data)-sha1Bytes:]) {
		return nil, ErrIntegrity
	}
	entries, err := parseEntries(payload)
	if err != nil {
		return nil, err
	}
	return &Result{Version: version, WeakIntegrity: version < 2, Entries: entries}, nil
}

// PKCS#12 Appendix B derivation, ID=3 (MAC material), SHA-1 and v=64.
// This derives at most one SHA-1 block, which covers both BKS v1 and v2 keys.
func deriveMACKey(password string, salt []byte, iterations, outLen int) []byte {
	units := utf16.Encode([]rune(password))
	pass := make([]byte, 0, (len(units)+1)*2)
	if len(units) != 0 {
		for _, u := range units {
			pass = append(pass, byte(u>>8), byte(u))
		}
		pass = append(pass, 0, 0)
	}
	repeated := func(in []byte) []byte {
		if len(in) == 0 {
			return nil
		}
		n := 64 * ((len(in) + 63) / 64)
		out := make([]byte, n)
		for i := range out {
			out[i] = in[i%len(in)]
		}
		return out
	}
	s, p := repeated(salt), repeated(pass)
	h := sha1.New()
	var d [64]byte
	for i := range d {
		d[i] = 3
	}
	h.Write(d[:])
	h.Write(s)
	h.Write(p)
	a := h.Sum(nil)
	for i := 1; i < iterations; i++ {
		h.Reset()
		h.Write(a)
		a = h.Sum(a[:0])
	}
	out := append([]byte(nil), a[:outLen]...)
	clear(pass)
	clear(p)
	clear(s)
	clear(a)
	clear(units)
	return out
}

type reader struct {
	data []byte
	pos  int
}

func (r *reader) take(n uint64) ([]byte, error) {
	if r.pos < 0 || r.pos > len(r.data) || n > uint64(len(r.data)-r.pos) {
		return nil, ErrFormat
	}
	start := r.pos
	r.pos += int(n)
	return r.data[start:r.pos], nil
}
func (r *reader) u8() (byte, error) {
	b, e := r.take(1)
	if e != nil {
		return 0, e
	}
	return b[0], nil
}
func (r *reader) u16() (uint16, error) {
	b, e := r.take(2)
	if e != nil {
		return 0, e
	}
	return binary.BigEndian.Uint16(b), nil
}
func (r *reader) u32() (uint32, error) {
	b, e := r.take(4)
	if e != nil {
		return 0, e
	}
	return binary.BigEndian.Uint32(b), nil
}
func (r *reader) utf() (string, error) {
	n, e := r.u16()
	if e != nil {
		return "", e
	}
	b, e := r.take(uint64(n))
	if e != nil {
		return "", e
	}
	return modifiedUTF8(b)
}
func (r *reader) blob() ([]byte, error) {
	n, e := r.u32()
	if e != nil {
		return nil, e
	}
	return r.take(uint64(n))
}
func (r *reader) cert() ([]byte, error) {
	typ, e := r.utf()
	if e != nil {
		return nil, e
	}
	if typ != "X.509" && typ != "X509" {
		return nil, fmt.Errorf("%w: certificate type %q", ErrUnsupported, typ)
	}
	cert, e := r.blob()
	if e != nil {
		return nil, e
	}
	if len(cert) == 0 {
		return nil, ErrFormat
	}
	return cert, nil
}
func parseEntries(payload []byte) ([]Entry, error) {
	r := reader{data: payload}
	out := make([]Entry, 0)
	seen := make(map[string]struct{})
	count := 0
	for {
		kind, e := r.u8()
		if e != nil {
			return nil, e
		}
		if kind == 0 {
			if r.pos != len(payload) {
				return nil, ErrFormat
			}
			return out, nil
		}
		count++
		if count > maxEntries {
			return nil, ErrUnsupported
		}
		if kind < 1 || kind > 4 {
			return nil, ErrUnsupported
		}
		alias, e := r.utf()
		if e != nil {
			return nil, e
		}
		if _, ok := seen[alias]; ok {
			return nil, ErrFormat
		}
		seen[alias] = struct{}{}
		if _, e = r.take(8); e != nil {
			return nil, e
		} // timestamp
		n, e := r.u32()
		if e != nil {
			return nil, e
		}
		if n > maxChain {
			return nil, ErrUnsupported
		}
		var leaf []byte
		for i := uint32(0); i < n; i++ {
			cert, e := r.cert()
			if e != nil {
				return nil, e
			}
			if i == 0 {
				leaf = cert
			}
		}
		switch kind {
		case 1:
			if n != 0 {
				return nil, ErrFormat
			}
			cert, e := r.cert()
			if e != nil {
				return nil, e
			}
			out = append(out, Entry{Alias: alias, EntryType: "trusted-certificate", Certificate: cert})
		case 2:
			keyType, e := r.u8()
			if e != nil {
				return nil, e
			}
			if keyType > 2 {
				return nil, ErrFormat
			}
			if _, e = r.utf(); e != nil {
				return nil, e
			} // encoding
			if _, e = r.utf(); e != nil {
				return nil, e
			} // algorithm
			if _, e = r.blob(); e != nil {
				return nil, e
			} // skip encoded key
			if leaf != nil {
				entryType := "key-entry"
				if keyType == 0 {
					entryType = "private-key"
				}
				out = append(out, Entry{Alias: alias, EntryType: entryType, Certificate: leaf})
			}
		case 3, 4:
			if _, e = r.blob(); e != nil {
				return nil, e
			} // opaque sealed key, never decrypt
			if leaf != nil {
				out = append(out, Entry{Alias: alias, EntryType: "key-entry", Certificate: leaf})
			}
		}
	}
}

func modifiedUTF8(input []byte) (string, error) {
	units := make([]uint16, 0, len(input))
	for i := 0; i < len(input); {
		b := input[i]
		switch {
		case b >= 1 && b <= 0x7f:
			units = append(units, uint16(b))
			i++
		case b >= 0xc0 && b <= 0xdf:
			if i+1 >= len(input) || input[i+1]&0xc0 != 0x80 {
				return "", ErrFormat
			}
			v := uint16(b&0x1f)<<6 | uint16(input[i+1]&0x3f)
			if v < 0x80 && !(b == 0xc0 && input[i+1] == 0x80) {
				return "", ErrFormat
			}
			units = append(units, v)
			i += 2
		case b >= 0xe0 && b <= 0xef:
			if i+2 >= len(input) || input[i+1]&0xc0 != 0x80 || input[i+2]&0xc0 != 0x80 {
				return "", ErrFormat
			}
			v := uint16(b&0x0f)<<12 | uint16(input[i+1]&0x3f)<<6 | uint16(input[i+2]&0x3f)
			if v < 0x800 {
				return "", ErrFormat
			}
			units = append(units, v)
			i += 3
		default:
			return "", ErrFormat
		}
	}
	for i := 0; i < len(units); i++ {
		v := units[i]
		if v >= 0xd800 && v <= 0xdbff {
			if i+1 >= len(units) || units[i+1] < 0xdc00 || units[i+1] > 0xdfff {
				return "", ErrFormat
			}
			i++
		} else if v >= 0xdc00 && v <= 0xdfff {
			return "", ErrFormat
		}
	}
	return string(utf16.Decode(units)), nil
}
