package xmlutils

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"

	"github.com/beevik/etree"
	dsig "github.com/russellhaering/goxmldsig"
)

func signElement(canonicalizer dsig.Canonicalizer, privateKey *rsa.PrivateKey, element *etree.Element) ([]byte, error) {
	xml, err := canonicalizer.Canonicalize(element)
	if err != nil {
		return nil, err
	}
	digest := sha256.Sum256(xml)
	sig, err := rsa.SignPKCS1v15(nil, privateKey, crypto.SHA256, digest[:])
	if err != nil {
		return nil, err
	}
	return sig, nil
}

func signDsElement(canonicalizer dsig.Canonicalizer, privateKey *rsa.PrivateKey, element *etree.Element) ([]byte, error) {
	element = element.Copy()
	element.CreateAttr("xmlns:ds", "http://www.w3.org/2000/09/xmldsig#")
	return signElement(canonicalizer, privateKey, element)
}
