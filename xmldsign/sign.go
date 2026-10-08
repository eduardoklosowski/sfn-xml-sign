package xmldsign

import (
	"crypto/rsa"
	"crypto/x509"

	"github.com/eduardoklosowski/sfn-xml-sign/internal/certificateutils"
	"github.com/eduardoklosowski/sfn-xml-sign/internal/xmlutils"
)

func Sing(cert *x509.Certificate, key *rsa.PrivateKey, data []byte) ([]byte, error) {
	certInfo := certificateutils.NewCertificateInfo(*cert)

	signedData, err := xmlutils.Sign(certInfo, key, data)
	if err != nil {
		return nil, err
	}

	return signedData, nil
}
