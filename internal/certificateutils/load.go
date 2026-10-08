package certificateutils

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
)

func Load(filePath string) (*x509.Certificate, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("invalid PEM content in '%s'", filePath)
	}
	if block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("found '%s' instead of 'CERTIFICATE' in '%s'", block.Type, filePath)
	}

	return x509.ParseCertificate(block.Bytes)
}
