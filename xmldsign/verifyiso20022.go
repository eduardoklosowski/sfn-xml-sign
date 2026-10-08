package xmldsign

import (
	"crypto/x509"

	"github.com/eduardoklosowski/sfn-xml-sign/internal/certificateutils"
	"github.com/eduardoklosowski/sfn-xml-sign/internal/xmlutils"
)

func VerifyIso20022(cert *x509.Certificate, data []byte) error {
	certInfo := certificateutils.NewCertificateInfo(*cert)
	key, err := certificateutils.ExtractPublicKey(cert)
	if err != nil {
		return err
	}

	err = xmlutils.VerifyIso20022(certInfo, key, data)
	if err != nil {
		return err
	}

	return nil
}
