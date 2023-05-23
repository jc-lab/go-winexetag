package winexetag

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math/big"
	"os"
	"time"
)

const (
	// notBeforeTime and notAfterTime are the validity period of the
	// certificate that we generate. They are deliberately set so that they
	// are already expired.
	notBeforeTime = "Mon Jan 1 10:00:00 UTC 2019"
	notAfterTime  = "Mon Apr 1 10:00:00 UTC 2019"
)

// dataDirectory represents the IMAGE_DATA_DIRECTORY structure from
// http://msdn.microsoft.com/en-us/library/windows/desktop/ms680305(v=vs.85).aspx.
type dataDirectory struct {
	VirtualAddress uint32
	Size           uint32
}

// A subset of the known COFF "characteristic" flags found in
// IMAGE_FILE_HEADER.Characteristics.
const (
	coffCharacteristicExecutableImage = 2
	coffCharacteristicDLL             = 0x2000
)

const (
	pe32Magic     = 0x10b
	pe32PlusMagic = 0x20b
)

const (
	certificateTableIndex = 4
)

func getTagCert(signedData *signedData) (cert *x509.Certificate, index int, err error) {
	n := len(signedData.PKCS7.Certs)
	if n == 0 {
		return nil, -1, nil
	}

	for index, certASN1 := range signedData.PKCS7.Certs {
		if cert, err = x509.ParseCertificate(certASN1.FullBytes); err != nil {
			return nil, -1, err
		}

		for _, ext := range cert.Extensions {
			if !ext.Critical && ext.Id.Equal(oidTagCert) {
				return cert, index, nil
			}
		}
	}

	return nil, -1, nil
}

// SetTagCertTag modifies signedData, adding the tagging cert with the given tag.
// It returns the asn1 serialization of the modified signedData.
func SetTagCertTag(signedData *signedData, tag []byte) ([]byte, error) {
	cert, index, err := getTagCert(signedData)
	if err != nil {
		return nil, fmt.Errorf("couldn't identify if any existing certificates are tagging certs because of parse error: %w", err)
	}

	if cert != nil {
		pkcs7 := &signedData.PKCS7
		certs := pkcs7.Certs

		var newCerts []asn1.RawValue
		newCerts = append(newCerts, certs[:index]...)
		newCerts = append(newCerts, certs[index+1:]...)
		pkcs7.Certs = newCerts
	}

	notBefore := parseUnixTimeOrDie(notBeforeTime)
	notAfter := parseUnixTimeOrDie(notAfterTime)

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}

	issuerTemplate := x509.Certificate{
		SerialNumber: new(big.Int).SetInt64(1),
		Subject: pkix.Name{
			CommonName: "Unknown Issuer",
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
		SignatureAlgorithm:    x509.ECDSAWithSHA256,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	template := x509.Certificate{
		SerialNumber: new(big.Int).SetInt64(1),
		Subject: pkix.Name{
			CommonName: "Installation Tag Certificate",
		},
		Issuer: pkix.Name{
			CommonName: "Unknown Issuer",
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
		SignatureAlgorithm:    x509.ECDSAWithSHA256,
		BasicConstraintsValid: true,
		IsCA:                  false,
		ExtraExtensions: []pkix.Extension{
			{
				// This includes the tag in an extension in the
				// certificate.
				Id:    oidTagCert,
				Value: tag,
			},
		},
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &issuerTemplate, &priv.PublicKey, priv)
	if err != nil {
		return nil, err
	}

	signedData.PKCS7.Certs = append(signedData.PKCS7.Certs, asn1.RawValue{
		FullBytes: derBytes,
	})

	asn1Bytes, err := asn1.Marshal(*signedData)
	if err != nil {
		return nil, err
	}
	return asn1Bytes, nil
}

// Certificate constants. See
// http://msdn.microsoft.com/en-us/library/ms920091.aspx.
const (
	// Despite MSDN claiming that 0x100 is the only, current revision - in
	// practice it's 0x200.
	attributeCertificateRevision            = 0x200
	attributeCertificateTypePKCS7SignedData = 2
)

// Binary represents a taggable binary of any format.
type Binary interface {
	GetTagCert() (cert *x509.Certificate, index int, err error)
	GetTag() (tag []byte, err error)
	SetTag(writer io.Writer, tag []byte) (err error)
}

// oidTagCert is an OID that we use for the extension in the superfluous
// certificate. It's in the Google arc, but not officially assigned.
var oidTagCert = asn1.ObjectIdentifier([]int{1, 3, 6, 1, 4, 1, 88888, 1, 32, 9999})

func parseUnixTimeOrDie(unixTime string) time.Time {
	t, err := time.Parse(time.UnixDate, unixTime)
	if err != nil {
		panic(err)
	}
	return t
}

// NewBinary returns a Binary that contains details of the PE32 or MSI binary given in |contents|.
// |contents| is modified if it is an MSI file.
func NewBinary(contents []byte) (Binary, error) {
	pe, peErr := NewPE32Binary(bytes.NewReader(contents))
	if peErr == nil {
		return pe, peErr
	}
	//msi, msiErr := NewMSIBinary(contents)
	//if msiErr == nil {
	//	return msi, msiErr
	//}
	return nil, errors.New("Could not parse input as either PE32 or MSI:\nPE32: " + peErr.Error()) //  + "\nMSI: " + msiErr.Error()
}

// buildBinary builds a PE binary based on bin but with the given SignedData
// and appended tag.
func (bin *PE32Binary) buildBinary(writer io.Writer, asn1Data, tag []byte) (err error) {
	if _, err = bin.reader.Seek(0, io.SeekStart); err != nil {
		return
	}
	if _, err = io.CopyN(writer, bin.reader, bin.certSizeOffset); err != nil {
		return
	}
	// Certificate Data Directory's Size Offset

	for (len(asn1Data)+len(tag))&7 > 0 {
		tag = append(tag, 0)
	}
	attrCertSectionLen := uint32(8 + len(asn1Data) + len(tag))

	// Update Certificate Data Directory's Size
	var lengthBytes [4]byte
	binary.LittleEndian.PutUint32(lengthBytes[:], attrCertSectionLen)
	if _, err = writer.Write(lengthBytes[:4]); err != nil {
		return
	}

	// Copy before certificate content
	if _, err = bin.reader.Seek(bin.certSizeOffset+4, io.SeekStart); err != nil {
		return
	}
	if _, err = io.CopyN(writer, bin.reader, bin.attrCertOffset-(bin.certSizeOffset+4)); err != nil {
		return
	}

	var header [8]byte
	binary.LittleEndian.PutUint32(header[:], attrCertSectionLen)
	binary.LittleEndian.PutUint16(header[4:], attributeCertificateRevision)
	binary.LittleEndian.PutUint16(header[6:], attributeCertificateTypePKCS7SignedData)
	if _, err = writer.Write(header[:]); err != nil {
		return
	}

	println(hex.EncodeToString(asn1Data))
	println(base64.StdEncoding.EncodeToString(asn1Data))

	if _, err = writer.Write(asn1Data); err != nil {
		return
	}
	if _, err = writer.Write(tag); err != nil {
		return
	}
	return nil
}

func (bin *PE32Binary) GetTag() (tag []byte, err error) {
	crt, _, err := bin.GetTagCert()
	if err != nil {
		return nil, err
	}

	if crt == nil {
		return nil, os.ErrNotExist
	}

	for _, xt := range crt.Extensions {
		if xt.Id.Equal(oidTagCert) {
			return bytes.TrimRight(xt.Value, "\000"), nil
		}
	}

	return nil, os.ErrNotExist
}
