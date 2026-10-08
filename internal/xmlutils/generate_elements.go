package xmlutils

import (
	"encoding/base64"

	"github.com/beevik/etree"
	"github.com/eduardoklosowski/sfn-xml-sign/internal/certificateutils"
)

func generateKeyInfo(cert certificateutils.CertificateInfo) *etree.Element {
	e := etree.NewElement("ds:KeyInfo")
	e.CreateAttr("Id", "key-info-id")
	e.CreateChild("ds:X509Data", func(e *etree.Element) {
		e.CreateChild("ds:X509IssuerSerial", func(e *etree.Element) {
			e.CreateChild("ds:X509IssuerName", func(e *etree.Element) {
				e.CreateText(cert.IssuerName())
			})
			e.CreateChild("ds:X509SerialNumber", func(e *etree.Element) {
				e.CreateText(cert.SerialNumber())
			})
		})
	})
	return e
}

func generateSignedInfo(keyInfoDigest, documentDigest []byte) *etree.Element {
	e := etree.NewElement("ds:SignedInfo")
	e.CreateChild("ds:CanonicalizationMethod", func(e *etree.Element) {
		e.CreateAttr("Algorithm", "http://www.w3.org/2001/10/xml-exc-c14n#")
	})
	e.CreateChild("ds:SignatureMethod", func(e *etree.Element) {
		e.CreateAttr("Algorithm", "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256")
	})
	e.CreateChild("ds:Reference", func(e *etree.Element) {
		e.CreateAttr("URI", "#key-info-id")
		e.CreateChild("ds:Transforms", func(e *etree.Element) {
			e.CreateChild("ds:Transform", func(e *etree.Element) {
				e.CreateAttr("Algorithm", "http://www.w3.org/2001/10/xml-exc-c14n#")
			})
		})
		e.CreateChild("ds:DigestMethod", func(e *etree.Element) {
			e.CreateAttr("Algorithm", "http://www.w3.org/2001/04/xmlenc#sha256")
		})
		e.CreateChild("ds:DigestValue", func(e *etree.Element) {
			e.CreateText(base64.StdEncoding.EncodeToString(keyInfoDigest))
		})
	})
	e.CreateChild("ds:Reference", func(e *etree.Element) {
		e.CreateAttr("URI", "")
		e.CreateChild("ds:Transforms", func(e *etree.Element) {
			e.CreateChild("ds:Transform", func(e *etree.Element) {
				e.CreateAttr("Algorithm", "http://www.w3.org/2000/09/xmldsig#enveloped-signature")
			})
			e.CreateChild("ds:Transform", func(e *etree.Element) {
				e.CreateAttr("Algorithm", "http://www.w3.org/2001/10/xml-exc-c14n#")
			})
		})
		e.CreateChild("ds:DigestMethod", func(e *etree.Element) {
			e.CreateAttr("Algorithm", "http://www.w3.org/2001/04/xmlenc#sha256")
		})
		e.CreateChild("ds:DigestValue", func(e *etree.Element) {
			e.CreateText(base64.StdEncoding.EncodeToString(documentDigest))
		})
	})
	return e
}

func generateIso20022SignedInfo(keyInfoDigest, headerDigest, documentDigest []byte) *etree.Element {
	e := etree.NewElement("ds:SignedInfo")
	e.CreateChild("ds:CanonicalizationMethod", func(e *etree.Element) {
		e.CreateAttr("Algorithm", "http://www.w3.org/2001/10/xml-exc-c14n#")
	})
	e.CreateChild("ds:SignatureMethod", func(e *etree.Element) {
		e.CreateAttr("Algorithm", "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256")
	})
	e.CreateChild("ds:Reference", func(e *etree.Element) {
		e.CreateAttr("URI", "#key-info-id")
		e.CreateChild("ds:Transforms", func(e *etree.Element) {
			e.CreateChild("ds:Transform", func(e *etree.Element) {
				e.CreateAttr("Algorithm", "http://www.w3.org/2001/10/xml-exc-c14n#")
			})
		})
		e.CreateChild("ds:DigestMethod", func(e *etree.Element) {
			e.CreateAttr("Algorithm", "http://www.w3.org/2001/04/xmlenc#sha256")
		})
		e.CreateChild("ds:DigestValue", func(e *etree.Element) {
			e.CreateText(base64.StdEncoding.EncodeToString(keyInfoDigest))
		})
	})
	e.CreateChild("ds:Reference", func(e *etree.Element) {
		e.CreateAttr("URI", "")
		e.CreateChild("ds:Transforms", func(e *etree.Element) {
			e.CreateChild("ds:Transform", func(e *etree.Element) {
				e.CreateAttr("Algorithm", "http://www.w3.org/2000/09/xmldsig#enveloped-signature")
			})
			e.CreateChild("ds:Transform", func(e *etree.Element) {
				e.CreateAttr("Algorithm", "http://www.w3.org/2001/10/xml-exc-c14n#")
			})
		})
		e.CreateChild("ds:DigestMethod", func(e *etree.Element) {
			e.CreateAttr("Algorithm", "http://www.w3.org/2001/04/xmlenc#sha256")
		})
		e.CreateChild("ds:DigestValue", func(e *etree.Element) {
			e.CreateText(base64.StdEncoding.EncodeToString(headerDigest))
		})
	})
	e.CreateChild("ds:Reference", func(e *etree.Element) {
		e.CreateChild("ds:Transforms", func(e *etree.Element) {
			e.CreateChild("ds:Transform", func(e *etree.Element) {
				e.CreateAttr("Algorithm", "http://www.w3.org/2001/10/xml-exc-c14n#")
			})
		})
		e.CreateChild("ds:DigestMethod", func(e *etree.Element) {
			e.CreateAttr("Algorithm", "http://www.w3.org/2001/04/xmlenc#sha256")
		})
		e.CreateChild("ds:DigestValue", func(e *etree.Element) {
			e.CreateText(base64.StdEncoding.EncodeToString(documentDigest))
		})
	})
	return e
}

func generateSignature(keyInfo, signedInfo *etree.Element, SignatureValue []byte) *etree.Element {
	e := etree.NewElement("ds:Signature")
	e.CreateAttr("xmlns:ds", "http://www.w3.org/2000/09/xmldsig#")
	e.AddChild(signedInfo)
	e.CreateChild("ds:SignatureValue", func(e *etree.Element) {
		e.CreateText(base64.StdEncoding.EncodeToString(SignatureValue))
	})
	e.AddChild(keyInfo)
	return e
}
