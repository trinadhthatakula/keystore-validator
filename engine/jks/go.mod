module keystorevalidator/jks

go 1.24.0

require (
	github.com/pavlo-v-chernykh/keystore-go/v4 v4.5.0
	github.com/pion/dtls/v3 v3.1.15
	golang.org/x/crypto v0.48.0
	software.sslmate.com/src/go-pkcs12 v0.7.1
)

replace github.com/pavlo-v-chernykh/keystore-go/v4 => ./keystore

replace software.sslmate.com/src/go-pkcs12 => ./pkcs12
