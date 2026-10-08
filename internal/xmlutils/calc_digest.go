package xmlutils

import (
	"crypto/sha256"

	"github.com/beevik/etree"
	dsig "github.com/russellhaering/goxmldsig"
)

func calcElementDigest(canonicalizer dsig.Canonicalizer, element *etree.Element) ([]byte, error) {
	canon, err := canonicalizer.Canonicalize(element)
	if err != nil {
		return nil, err
	}
	digest := sha256.Sum256(canon)
	return digest[:], nil
}

func calcDsElementDigest(canonicalizer dsig.Canonicalizer, element *etree.Element) ([]byte, error) {
	element = element.Copy()
	element.CreateAttr("xmlns:ds", "http://www.w3.org/2000/09/xmldsig#")
	return calcElementDigest(canonicalizer, element)
}
