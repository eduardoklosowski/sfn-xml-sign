package certificateutils

import (
	"crypto/rsa"
	"crypto/x509"
	"fmt"
)

func ExtractPublicKey(cert *x509.Certificate) (*rsa.PublicKey, error) {
	pubKey, ok := cert.PublicKey.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("certificate not contains a RSA public key")
	}
	return pubKey, nil
}
