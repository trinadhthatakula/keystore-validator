// Certificate-only inspection of password-protected PKCS#12 stores.
package pkcs12

import (
	"crypto/x509"
	"encoding/asn1"
	"encoding/hex"
	"errors"
	"fmt"
)

// CertificateEntry associates a certificate with authenticated bag metadata.
// This association does not prove private-key possession.
type CertificateEntry struct {
	Alias       string
	EntryType   string
	Certificate *x509.Certificate
}
type bagMetadata struct {
	alias   string
	localID []byte
	trusted bool
}
type certItem struct {
	meta bagMetadata
	cert *x509.Certificate
	used bool
}

func readBagMetadata(attrs []pkcs12Attribute) (bagMetadata, error) {
	var out bagMetadata
	seen := map[string]bool{}
	if len(attrs) > 64 {
		return out, errors.New("too many bag attributes")
	}
	for _, attr := range attrs {
		switch {
		case attr.Id.Equal(oidFriendlyName):
			if seen["alias"] {
				return out, errors.New("duplicate friendly name")
			}
			seen["alias"] = true
			var value asn1.RawValue
			if err := unmarshal(attr.Value.Bytes, &value); err != nil || value.Class != 0 || value.Tag != 30 || value.IsCompound {
				return out, errors.New("invalid friendly name")
			}
			alias, err := decodeBMPString(value.Bytes)
			if err != nil || len(alias) > 4096 {
				return out, errors.New("invalid friendly name")
			}
			out.alias = alias
		case attr.Id.Equal(oidLocalKeyID):
			if seen["id"] {
				return out, errors.New("duplicate local key id")
			}
			seen["id"] = true
			if err := unmarshal(attr.Value.Bytes, &out.localID); err != nil || len(out.localID) > 128 {
				return out, errors.New("invalid local key id")
			}
		case attr.Id.Equal(oidJavaTrustStore):
			out.trusted = true
		}
	}
	return out, nil
}

// InspectCertificates verifies the MAC and reads public certificates. Shrouded
// key bags are never individually decrypted; only their public bag attributes
// are examined. Encrypted SafeContents are decrypted to reach certificate bags.
func InspectCertificates(data []byte, password string) ([]CertificateEntry, error) {
	encoded, err := bmpStringZeroTerminated(password)
	if err != nil {
		return nil, err
	}
	defer func() {
		for i := range encoded {
			encoded[i] = 0
		}
	}()
	bags, _, err := getSafeContents(data, encoded, 1, 32)
	if err != nil {
		return nil, err
	}
	var keys []bagMetadata
	var certs []certItem
	for _, bag := range bags {
		meta, err := readBagMetadata(bag.Attributes)
		if err != nil {
			return nil, err
		}
		switch {
		case bag.Id.Equal(oidPKCS8ShroundedKeyBag), bag.Id.Equal(oidKeyBag):
			keys = append(keys, meta)
		case bag.Id.Equal(oidCertBag):
			der, err := decodeCertBag(bag.Value.Bytes)
			if err != nil {
				return nil, err
			}
			cert, err := x509.ParseCertificate(der)
			if err != nil {
				return nil, err
			}
			certs = append(certs, certItem{meta: meta, cert: cert})
		default:
			return nil, NotImplementedError("unsupported safe bag type " + bag.Id.String())
		}
	}
	result := make([]CertificateEntry, 0, len(certs))
	aliases := map[string]bool{}
	add := func(alias, typ string, cert *x509.Certificate) error {
		if alias == "" {
			alias = fmt.Sprintf("certificate-%d", len(result)+1)
		}
		if aliases[alias] {
			return errors.New("ambiguous duplicate certificate alias")
		}
		aliases[alias] = true
		result = append(result, CertificateEntry{Alias: alias, EntryType: typ, Certificate: cert})
		return nil
	}
	for _, key := range keys {
		matches := []int{}
		for i, c := range certs {
			if c.used || c.meta.trusted {
				continue
			}
			if len(key.localID) > 0 && len(c.meta.localID) > 0 && string(key.localID) == string(c.meta.localID) {
				matches = append(matches, i)
				continue
			}
			if len(key.localID) == 0 && key.alias != "" && key.alias == c.meta.alias {
				matches = append(matches, i)
			}
		}
		if len(matches) > 1 {
			return nil, errors.New("ambiguous key to certificate association")
		}
		if len(matches) == 0 {
			continue
		}
		i := matches[0]
		certs[i].used = true
		alias := key.alias
		if alias == "" {
			alias = certs[i].meta.alias
		}
		if alias == "" && len(key.localID) > 0 {
			alias = hex.EncodeToString(key.localID)
		}
		if err := add(alias, "private-key", certs[i].cert); err != nil {
			return nil, err
		}
	}
	for _, c := range certs {
		if c.used {
			continue
		}
		if c.meta.trusted {
			if err := add(c.meta.alias, "trusted-certificate", c.cert); err != nil {
				return nil, err
			}
			continue
		}
		if c.meta.alias != "" || len(keys) == 0 {
			if err := add(c.meta.alias, "certificate", c.cert); err != nil {
				return nil, err
			}
		}
	}
	if len(result) == 0 {
		return nil, errors.New("no certificate entries")
	}
	return result, nil
}
