package keystore

import (
	"encoding/binary"
	"unicode/utf16"
)

const (
	magic uint32 = 0xfeedfeed

	version01 uint32 = 1
	version02 uint32 = 2

	privateKeyTag         uint32 = 1
	trustedCertificateTag uint32 = 2
)

var byteOrder = binary.BigEndian

var whitenerMessage = []byte("Mighty Aphrodite")

func passwordBytes(password []byte) []byte {
	units := utf16.Encode([]rune(string(password)))
	result := make([]byte, 0, len(units)*2)
	for _, unit := range units {
		result = append(result, byte(unit>>8), byte(unit))
	}

	return result
}

func zeroing(buf []byte) {
	for i := range buf {
		buf[i] = 0
	}
}
