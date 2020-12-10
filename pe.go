package winexetag

import (
	"crypto/x509"
	"errors"
)

// NewPE32Binary returns a Binary that contains details of the PE32 binary given in contents.
func NewPE32Binary(contents []byte) (*PE32Binary, error) {
	offset, size, certSizeOffset, err := getAttributeCertificates(contents)
	if err != nil {
		return nil, errors.New("authenticodetag: error parsing headers: " + err.Error())
	}

	attributeCertificates := contents[offset : offset+size]
	asn1Data, appendedTag, err := processAttributeCertificates(attributeCertificates)
	if err != nil {
		return nil, errors.New("authenticodetag: error parsing attribute certificate section: " + err.Error())
	}

	signedData, err := parseSignedData(asn1Data)
	if err != nil {
		return nil, err
	}

	return &PE32Binary{
		contents:       contents,
		attrCertOffset: offset,
		certSizeOffset: certSizeOffset,
		asn1Bytes:      asn1Data,
		appendedTag:    appendedTag,
		signedData:     signedData,
	}, nil
}

// PE32Binary represents a PE binary.
type PE32Binary struct {
	contents       []byte      // the full file
	attrCertOffset int         // the offset to the attribute certificates table
	certSizeOffset int         // the offset to the size of the attribute certificates table
	asn1Bytes      []byte      // the PKCS#7, SignedData in DER form.
	appendedTag    []byte      // the appended tag, if any.
	signedData     *signedData // the parsed SignedData structure.
}

func (bin *PE32Binary) GetTagCert() (cert *x509.Certificate, index int, err error) {
	return getTagCert(bin.signedData)
}

// SetTag returns a PE binary based on bin, but where the
// superfluous certificate contains the given tag data.
// The (parsed) bin.signedData is modified; but bin.asn1Bytes, which contains
// the raw original bytes, is not.
func (bin *PE32Binary) SetTag(tag []byte) (contents []byte, err error) {
	asn1Bytes, err := SetTagCertTag(bin.signedData, tag)
	if err != nil {
		return nil, err
	}

	return bin.buildBinary(asn1Bytes, bin.appendedTag)
}

