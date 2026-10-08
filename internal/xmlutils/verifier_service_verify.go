package xmlutils

import (
	"crypto"
	"crypto/rsa"
	"encoding/base64"
	"fmt"

	"github.com/beevik/etree"
	"github.com/eduardoklosowski/sfn-xml-sign/internal/certificateutils"
	dsig "github.com/russellhaering/goxmldsig"
)

func Verify(certInfo certificateutils.CertificateInfo, key *rsa.PublicKey, data []byte) error {
	canonicalizer := dsig.MakeC14N10ExclusiveCanonicalizerWithPrefixList("")

	xmlDoc := etree.NewDocument()
	err := xmlDoc.ReadFromBytes(data)
	if err != nil {
		return fmt.Errorf("invalid XML: %w", err)
	}

	signature := xmlDoc.FindElement("/*/Signature")
	if signature == nil {
		return fmt.Errorf("not found <Signature>")
	}
	signature.Parent().RemoveChild(signature)
	signedInfo := signature.FindElement("./SignedInfo")
	if signedInfo == nil {
		return fmt.Errorf("not found <SignedInfo>")
	}

	digestValuesElements := signedInfo.FindElements("./Reference/DigestValue")
	if len(digestValuesElements) == 0 {
		return fmt.Errorf("not found <DigestValue> of <Reference>")
	}
	digests := make(map[string]struct{}, len(digestValuesElements))
	for _, element := range digestValuesElements {
		digests[element.Text()] = struct{}{}
	}

	keyInfo := signature.FindElement("./KeyInfo")
	if keyInfo == nil {
		return fmt.Errorf("not found <KeyInfo>")
	}
	keyInfoDigest, err := calcDsElementDigest(canonicalizer, keyInfo)
	if err != nil {
		return fmt.Errorf("calc digest of <KeyInfo>: %w", err)
	}
	if _, exists := digests[base64.StdEncoding.EncodeToString(keyInfoDigest)]; !exists {
		return fmt.Errorf("invalid digest of <KeyInfo>")
	}

	document := xmlDoc.Root()
	documentDigest, err := calcElementDigest(canonicalizer, document)
	if err != nil {
		return fmt.Errorf("calc digest of XML: %w", err)
	}
	if _, exists := digests[base64.StdEncoding.EncodeToString(documentDigest)]; !exists {
		return fmt.Errorf("invalid digest of XML")
	}

	issuerNameElement := keyInfo.FindElement("./X509Data/X509IssuerSerial/X509IssuerName")
	if issuerNameElement == nil {
		return fmt.Errorf("not found certificate issuer name in signature")
	}
	if issuerNameElement.Text() != certInfo.IssuerName() {
		return fmt.Errorf("mismatch issuer name, document has '%s' but certificate has '%s'", issuerNameElement.Text(), certInfo.IssuerName())
	}
	serialNumberElement := keyInfo.FindElement("./X509Data/X509IssuerSerial/X509SerialNumber")
	if serialNumberElement == nil {
		return fmt.Errorf("not found certificate serial number in signature")
	}
	if serialNumberElement.Text() != certInfo.SerialNumber() {
		return fmt.Errorf("mismatch serial number, document has '%s' but certificate has '%s'", serialNumberElement.Text(), certInfo.SerialNumber())
	}

	signedInfoDigest, err := calcDsElementDigest(canonicalizer, signedInfo)
	if err != nil {
		return fmt.Errorf("calc digest of <SignedInfo>: %w", err)
	}
	signatureValueElement := signature.FindElement("./SignatureValue")
	if signatureValueElement == nil {
		return fmt.Errorf("not found <SignatureValue>")
	}
	signatureValue, err := base64.StdEncoding.DecodeString(signatureValueElement.Text())
	if err != nil {
		return fmt.Errorf("invalid base64 in <SignatureValue>: %w", err)
	}
	err = rsa.VerifyPKCS1v15(key, crypto.SHA256, signedInfoDigest, signatureValue)
	if err != nil {
		return fmt.Errorf("invalid signature: %w", err)
	}

	return nil
}

func VerifyIso20022(certInfo certificateutils.CertificateInfo, key *rsa.PublicKey, xmlBytes []byte) error {
	canonicalizer := dsig.MakeC14N10ExclusiveCanonicalizerWithPrefixList("")

	xmlDoc := etree.NewDocument()
	err := xmlDoc.ReadFromBytes(xmlBytes)
	if err != nil {
		return fmt.Errorf("invalid XML: %w", err)
	}

	signature := xmlDoc.FindElement("/Envelope/AppHdr/Sgntr/Signature")
	if signature == nil {
		return fmt.Errorf("not found <Signature>")
	}
	signature.Parent().RemoveChild(signature)
	signedInfo := signature.FindElement("./SignedInfo")
	if signedInfo == nil {
		return fmt.Errorf("not found <SignedInfo>")
	}

	digestValuesElements := signedInfo.FindElements("./Reference/DigestValue")
	if len(digestValuesElements) == 0 {
		return fmt.Errorf("not found <DigestValue> of <Reference>")
	}
	digests := make(map[string]struct{}, len(digestValuesElements))
	for _, element := range digestValuesElements {
		digests[element.Text()] = struct{}{}
	}

	keyInfo := signature.FindElement("./KeyInfo")
	if keyInfo == nil {
		return fmt.Errorf("not found <KeyInfo>")
	}
	keyInfoDigest, err := calcDsElementDigest(canonicalizer, keyInfo)
	if err != nil {
		return fmt.Errorf("calc digest of <KeyInfo>: %w", err)
	}
	if _, exists := digests[base64.StdEncoding.EncodeToString(keyInfoDigest)]; !exists {
		return fmt.Errorf("invalid digest of <KeyInfo>")
	}

	header := xmlDoc.FindElement("/Envelope/AppHdr")
	if header == nil {
		return fmt.Errorf("not found <AppHdr>")
	}
	headerDigest, err := calcElementDigest(canonicalizer, header)
	if err != nil {
		return fmt.Errorf("calc digest of <AppHdr>: %w", err)
	}
	if _, exists := digests[base64.StdEncoding.EncodeToString(headerDigest)]; !exists {
		return fmt.Errorf("invalid digest of <AppHdr>")
	}

	document := xmlDoc.FindElement("/Envelope/Document")
	if document == nil {
		return fmt.Errorf("not found <Document>")
	}
	documentDigest, err := calcElementDigest(canonicalizer, document)
	if err != nil {
		return fmt.Errorf("calc digest of <Document>: %w", err)
	}
	if _, exists := digests[base64.StdEncoding.EncodeToString(documentDigest)]; !exists {
		return fmt.Errorf("invalid digest of <Document>")
	}

	issuerNameElement := keyInfo.FindElement("./X509Data/X509IssuerSerial/X509IssuerName")
	if issuerNameElement == nil {
		return fmt.Errorf("not found certificate issuer name in signature")
	}
	if issuerNameElement.Text() != certInfo.IssuerName() {
		return fmt.Errorf("mismatch issuer name, document has '%s' but certificate has '%s'", issuerNameElement.Text(), certInfo.IssuerName())
	}
	serialNumberElement := keyInfo.FindElement("./X509Data/X509IssuerSerial/X509SerialNumber")
	if serialNumberElement == nil {
		return fmt.Errorf("not found certificate serial number in signature")
	}
	if serialNumberElement.Text() != certInfo.SerialNumber() {
		return fmt.Errorf("mismatch serial number, document has '%s' but certificate has '%s'", serialNumberElement.Text(), certInfo.SerialNumber())
	}

	signedInfoDigest, err := calcDsElementDigest(canonicalizer, signedInfo)
	if err != nil {
		return fmt.Errorf("calc digest of <SignedInfo>: %w", err)
	}
	signatureValueElement := signature.FindElement("./SignatureValue")
	if signatureValueElement == nil {
		return fmt.Errorf("not found <SignatureValue>")
	}
	signatureValue, err := base64.StdEncoding.DecodeString(signatureValueElement.Text())
	if err != nil {
		return fmt.Errorf("invalid base64 in <SignatureValue>: %w", err)
	}
	err = rsa.VerifyPKCS1v15(key, crypto.SHA256, signedInfoDigest, signatureValue)
	if err != nil {
		return fmt.Errorf("invalid signature: %w", err)
	}

	return nil
}
