package winexetag

import (
	"crypto/x509"
	"errors"
	"io"
)

// NewPE32Binary returns a Binary that contains details of the PE32 binary given in contents.
func NewPE32Binary(reader io.ReadSeeker) (*PE32Binary, error) {
	offset, size, certSizeOffset, err := getAttributeCertificates(reader)
	if err != nil {
		return nil, errors.New("authenticodetag: error parsing headers: " + err.Error())
	}

	if _, err = reader.Seek(offset, io.SeekStart); err != nil {
		return nil, err
	}
	attributeCertificates := make([]byte, size)
	if _, err = reader.Read(attributeCertificates); err != nil {
		return nil, err
	}

	asn1Data, appendedTag, err := processAttributeCertificates(attributeCertificates)
	if err != nil {
		return nil, errors.New("authenticodetag: error parsing attribute certificate section: " + err.Error())
	}

	signedData, err := parseSignedData(asn1Data)
	if err != nil {
		return nil, err
	}

	return &PE32Binary{
		reader:         reader,
		attrCertOffset: offset,
		certSizeOffset: certSizeOffset,
		asn1Bytes:      asn1Data,
		appendedTag:    appendedTag,
		signedData:     signedData,
	}, nil
}

// PE32Binary represents a PE binary.
type PE32Binary struct {
	reader         io.ReadSeeker // the file reader
	attrCertOffset int64         // the offset to the attribute certificates table
	certSizeOffset int64         // the offset to the size of the attribute certificates table
	asn1Bytes      []byte        // the PKCS#7, SignedData in DER form.
	appendedTag    []byte        // the appended tag, if any.
	signedData     *signedData   // the parsed SignedData structure.
}

func (bin *PE32Binary) GetTagCert() (cert *x509.Certificate, index int, err error) {
	return getTagCert(bin.signedData)
}

// SetTag returns a PE binary based on bin, but where the
// superfluous certificate contains the given tag data.
// The (parsed) bin.signedData is modified; but bin.asn1Bytes, which contains
// the raw original bytes, is not.
func (bin *PE32Binary) SetTag(writer io.Writer, tag []byte) (err error) {
	asn1Bytes, err := SetTagCertTag(bin.signedData, tag)
	if err != nil {
		return err
	}

	return bin.buildBinary(writer, asn1Bytes, bin.appendedTag)
}
