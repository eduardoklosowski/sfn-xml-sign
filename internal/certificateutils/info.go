package certificateutils

import "crypto/x509"

type CertificateInfo struct {
	cert x509.Certificate
}

func NewCertificateInfo(cert x509.Certificate) CertificateInfo {
	return CertificateInfo{cert: cert}
}

func (i CertificateInfo) IssuerName() string {
	return i.cert.Issuer.String()
}

func (i CertificateInfo) SerialNumber() string {
	return i.cert.SerialNumber.String()
}
