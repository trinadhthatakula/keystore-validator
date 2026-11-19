// Package jceks recognizes Java's JCEKS container and validates its store
// digest. Key and trusted-certificate entries have the same encoding as JKS;
// the caller must still parse and validate all entries before using the result.
package jceks

import (
	"crypto/sha1"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"unicode/utf16"
)

var ErrFormat = errors.New("invalid JCEKS format")
var ErrIntegrity = errors.New("incorrect password or damaged JCEKS")

const magic uint32 = 0xcececece

func LooksLike(data []byte) bool {
	return len(data) >= 4 && binary.BigEndian.Uint32(data[:4]) == magic
}

func digest(data []byte, password string) []byte {
	h := sha1.New()
	for _, ch := range utf16.Encode([]rune(password)) {
		h.Write([]byte{byte(ch >> 8), byte(ch)})
	}
	h.Write([]byte("Mighty Aphrodite"))
	h.Write(data)
	return h.Sum(nil)
}

// AsJKS authenticates the original JCEKS file before converting its container
// header for the JKS certificate parser. It never decrypts any private key.
// JCEKS secret-key entries require Java serialization and must be rejected by
// the caller's bounded JKS parser.
func AsJKS(data []byte, password string) ([]byte, error) {
	if !LooksLike(data) || len(data) < 12+sha1.Size || len(data) > 16*1024*1024 {
		return nil, ErrFormat
	}
	body := data[:len(data)-sha1.Size]
	expected := digest(body, password)
	if subtle.ConstantTimeCompare(expected, data[len(body):]) != 1 {
		return nil, ErrIntegrity
	}
	out := append([]byte(nil), data...)
	binary.BigEndian.PutUint32(out[:4], 0xfeedfeed)
	copy(out[len(body):], digest(out[:len(body)], password))
	return out, nil
}
