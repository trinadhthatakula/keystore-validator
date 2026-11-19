package pkcs12

import "errors"

// DeriveLegacySHA1 exposes the bounded RFC 7292 KDF for legacy container
// decryption. The password must already use that format's password encoding.
func DeriveLegacySHA1(password, salt []byte, iterations int, purpose byte, size int) ([]byte, error) {
	if iterations < 1 || iterations > maxInspectionIterations || len(salt) < 1 || len(salt) > maxInspectionSalt || len(password) > 32770 || purpose < 1 || purpose > 3 || size < 1 || size > 64 {
		return nil, errors.New("unsupported legacy key derivation parameters")
	}
	return pbkdf(sha1Sum, 20, 64, salt, password, iterations, purpose, size), nil
}
