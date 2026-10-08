package xmldsign

import (
	"crypto/x509"

	"github.com/beevik/etree"
)

func Verify(cert *x509.Certificate, data []byte) error {
	document := etree.NewDocument()
	err := document.ReadFromBytes(data)
	if err != nil {
		return err
	}

	return nil
}
