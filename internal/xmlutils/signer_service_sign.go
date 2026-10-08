package xmlutils

import (
	"crypto/rsa"
	"fmt"

	"github.com/beevik/etree"
	"github.com/eduardoklosowski/sfn-xml-sign/internal/certificateutils"
	dsig "github.com/russellhaering/goxmldsig"
)

func Sign(certInfo certificateutils.CertificateInfo, key *rsa.PrivateKey, data []byte) ([]byte, error) {
	canonicalizer := dsig.MakeC14N10ExclusiveCanonicalizerWithPrefixList("")

	doc := etree.NewDocument()
	err := doc.ReadFromBytes(data)
	if err != nil {
		return nil, fmt.Errorf("invalid XML: %w", err)
	}

	if signature := doc.FindElement("/*/Signature"); signature != nil {
		signature.Parent().RemoveChild(signature)
	}

	keyInfo := generateKeyInfo(certInfo)
	keyInfoDigest, err := calcDsElementDigest(canonicalizer, keyInfo)
	if err != nil {
		return nil, fmt.Errorf("calc digest of <KeyInfo>: %w", err)
	}

	documentDigest, err := calcElementDigest(canonicalizer, doc.Root())
	if err != nil {
		return nil, fmt.Errorf("calc digest of XML: %w", err)
	}

	signedInfo := generateSignedInfo(keyInfoDigest, documentDigest)
	signatureValue, err := signDsElement(canonicalizer, key, signedInfo)
	if err != nil {
		return nil, fmt.Errorf("sign <SignedInfo>: %w", err)
	}

	signature := generateSignature(keyInfo, signedInfo, signatureValue)
	doc.Root().AddChild(signature)

	signedData, err := doc.WriteToBytes()
	if err != nil {
		return nil, err
	}

	return signedData, nil
}

func SignIso20022(certInfo certificateutils.CertificateInfo, key *rsa.PrivateKey, data []byte) ([]byte, error) {
	canonicalizer := dsig.MakeC14N10ExclusiveCanonicalizerWithPrefixList("")

	doc := etree.NewDocument()
	err := doc.ReadFromBytes(data)
	if err != nil {
		return nil, err
	}

	header := doc.FindElement("/Envelope/AppHdr")
	if header == nil {
		return nil, fmt.Errorf("not found <AppHdr>")
	}
	document := doc.FindElement("/Envelope/Document")
	if document == nil {
		return nil, fmt.Errorf("not found <Document>")
	}
	if signature := header.FindElement("./Sgntr/ds:Signature"); signature != nil {
		signature.Parent().RemoveChild(signature)
	}

	keyInfo := generateKeyInfo(certInfo)
	keyInfoDigest, err := calcDsElementDigest(canonicalizer, keyInfo)
	if err != nil {
		return nil, fmt.Errorf("calc digest of <KeyInfo>: %w", err)
	}

	headerDigest, err := calcElementDigest(canonicalizer, header)
	if err != nil {
		return nil, fmt.Errorf("calc digest of <AppHdr>: %w", err)
	}

	documentDigest, err := calcElementDigest(canonicalizer, document)
	if err != nil {
		return nil, fmt.Errorf("calc digest of <Document>: %w", err)
	}

	signedInfo := generateIso20022SignedInfo(keyInfoDigest, headerDigest, documentDigest)
	signatureValue, err := signDsElement(canonicalizer, key, signedInfo)
	if err != nil {
		return nil, fmt.Errorf("sign <SignedInfo>: %w", err)
	}

	signature := generateSignature(keyInfo, signedInfo, signatureValue)
	sgntr := header.FindElement("./Sgntr")
	if sgntr == nil {
		return nil, fmt.Errorf("not found <Sgntr>")
	}
	sgntr.AddChild(signature)

	signedData, err := doc.WriteToBytes()
	if err != nil {
		return nil, err
	}

	return signedData, nil
}
