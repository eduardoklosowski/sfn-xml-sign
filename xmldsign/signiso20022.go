package xmldsign

import (
	"crypto/rsa"
	"crypto/x509"

	"github.com/beevik/etree"
)

func SingIso20022(cert *x509.Certificate, key *rsa.PrivateKey, data []byte) ([]byte, error) {
	document := etree.NewDocument()
	err := document.ReadFromBytes(data)
	if err != nil {
		return nil, err
	}

	signedData, err := document.WriteToBytes()
	if err != nil {
		return nil, err
	}

	return signedData, nil
}
