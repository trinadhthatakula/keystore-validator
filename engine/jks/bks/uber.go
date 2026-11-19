package bks

import (
	"crypto/cipher"
	"crypto/sha1"
	"crypto/subtle"
	"encoding/binary"
	"unicode/utf16"

	"golang.org/x/crypto/twofish"
	pkcs12 "software.sslmate.com/src/go-pkcs12"
)

// InspectUber decrypts the outer UBER container and checks its SHA-1 trailer.
// Individual sealed key entries are not unlocked or returned.
func InspectUber(data []byte, password string) (*Result, error) {
	if !LooksLike(data) || len(data) > maxStoreBytes || len(password) > maxPasswordBytes {
		return nil, ErrFormat
	}
	version := binary.BigEndian.Uint32(data[:4])
	saltLen := int(binary.BigEndian.Uint32(data[4:8]))
	if version < 1 || version > 2 || saltLen != 20 {
		return nil, ErrFormat
	}
	iterationPos := 8 + saltLen
	if iterationPos+4 >= len(data) {
		return nil, ErrFormat
	}
	iterations := int(binary.BigEndian.Uint32(data[iterationPos : iterationPos+4]))
	if iterations < 1 || iterations > 65536 {
		return nil, ErrUnsupported
	}
	ciphertext := data[iterationPos+4:]
	if len(ciphertext) == 0 || len(ciphertext)%twofish.BlockSize != 0 {
		return nil, ErrFormat
	}
	units := utf16.Encode([]rune(password))
	encoded := make([]byte, 0, (len(units)+1)*2)
	if len(units) > 0 {
		for _, unit := range units {
			encoded = append(encoded, byte(unit>>8), byte(unit))
		}
		encoded = append(encoded, 0, 0)
	}
	defer clear(encoded)
	salt := data[8:iterationPos]
	key, err := pkcs12.DeriveLegacySHA1(encoded, salt, iterations, 1, 32)
	if err != nil {
		return nil, ErrUnsupported
	}
	defer clear(key)
	iv, err := pkcs12.DeriveLegacySHA1(encoded, salt, iterations, 2, 16)
	if err != nil {
		return nil, ErrUnsupported
	}
	defer clear(iv)
	block, err := twofish.NewCipher(key)
	if err != nil {
		return nil, ErrUnsupported
	}
	plain := make([]byte, len(ciphertext))
	defer clear(plain)
	cipher.NewCBCDecrypter(block, iv).CryptBlocks(plain, ciphertext)
	padding := int(plain[len(plain)-1])
	if padding < 1 || padding > twofish.BlockSize || padding > len(plain) {
		return nil, ErrIntegrity
	}
	for _, value := range plain[len(plain)-padding:] {
		if int(value) != padding {
			return nil, ErrIntegrity
		}
	}
	plain = plain[:len(plain)-padding]
	if len(plain) < sha1.Size {
		return nil, ErrIntegrity
	}
	body, expected := plain[:len(plain)-sha1.Size], plain[len(plain)-sha1.Size:]
	actual := sha1.Sum(body)
	if subtle.ConstantTimeCompare(actual[:], expected) != 1 {
		return nil, ErrIntegrity
	}
	entries, err := parseEntries(body)
	if err != nil {
		return nil, err
	}
	// parseEntries returns certificate slices into plain; copy them before clear.
	for i := range entries {
		entries[i].Certificate = append([]byte(nil), entries[i].Certificate...)
	}
	return &Result{Version: version, Entries: entries}, nil
}
