package winexetag

import (
	"bytes"
	"encoding/asn1"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)


// processAttributeCertificates parses an attribute certificates section of a
// PE file and returns the ASN.1 data and trailing data of the sole attribute
// certificate included.
func processAttributeCertificates(certs []byte) (asn1, appendedTag []byte, err error) {
	if len(certs) < 8 {
		err = errors.New("attribute certificate truncated")
		return
	}

	// This reads a WIN_CERTIFICATE structure from
	// http://msdn.microsoft.com/en-us/library/ms920091.aspx.
	certLen := binary.LittleEndian.Uint32(certs[:4])
	revision := binary.LittleEndian.Uint16(certs[4:6])
	certType := binary.LittleEndian.Uint16(certs[6:8])

	if int(certLen) != len(certs) {
		err = errors.New("multiple attribute certificates found")
		return
	}

	if revision != attributeCertificateRevision {
		err = fmt.Errorf("unknown attribute certificate revision: %x", revision)
		return
	}

	if certType != attributeCertificateTypePKCS7SignedData {
		err = fmt.Errorf("unknown attribute certificate type: %d", certType)
		return
	}

	asn1 = certs[8:]

	if len(asn1) < 2 {
		err = errors.New("ASN.1 structure truncated")
		return
	}

	asn1Length, err := lengthAsn1(asn1)
	if err != nil {
		return
	}
	appendedTag = asn1[asn1Length:]
	asn1 = asn1[:asn1Length]

	return
}

// signedData represents a PKCS#7, SignedData strucure.
type signedData struct {
	Type  asn1.ObjectIdentifier
	PKCS7 struct {
		Version     int
		Digests     asn1.RawValue
		ContentInfo asn1.RawValue
		Certs       []asn1.RawValue `asn1:"tag:0,optional,set"`
		SignerInfos asn1.RawValue
	} `asn1:"explicit,tag:0"`
}

// getAttributeCertificates takes a PE file and returns the offset and size of
// the attribute certificates section in the file, or an error. If found, it
// additionally returns an offset to the location in the file where the size of
// the table is stored.
func getAttributeCertificates(bin []byte) (offset, size, sizeOffset int, err error) {
	// offsetOfPEHeaderOffset is the offset into the binary where the
	// offset of the PE header is found.
	const offsetOfPEHeaderOffset = 0x3c
	if len(bin) < offsetOfPEHeaderOffset+4 {
		err = errors.New("binary truncated")
		return
	}

	peOffset := int(binary.LittleEndian.Uint32(bin[offsetOfPEHeaderOffset:]))
	if peOffset < 0 || peOffset+4 < peOffset {
		err = errors.New("overflow finding PE signature")
		return
	}
	if len(bin) < peOffset+4 {
		err = errors.New("binary truncated")
		return
	}
	pe := bin[peOffset:]
	if !bytes.Equal(pe[:4], []byte{'P', 'E', 0, 0}) {
		err = errors.New("PE header not found at expected offset")
		return
	}

	r := io.Reader(bytes.NewReader(pe[4:]))
	var fileHeader fileHeader
	if err = binary.Read(r, binary.LittleEndian, &fileHeader); err != nil {
		return
	}

	if fileHeader.Characteristics&coffCharacteristicExecutableImage == 0 {
		err = errors.New("file is not an executable image")
		return
	}

	if fileHeader.Characteristics&coffCharacteristicDLL != 0 {
		err = errors.New("file is a DLL")
		return
	}

	r = io.LimitReader(r, int64(fileHeader.SizeOfOptionalHeader))
	var optionalHeader optionalHeader
	if err = binary.Read(r, binary.LittleEndian, &optionalHeader); err != nil {
		return
	}

	// addressSize is the size of various fields in the Windows-specific
	// header to follow.
	var addressSize int

	switch optionalHeader.Magic {
	case pe32PlusMagic:
		addressSize = 8
	case pe32Magic:
		addressSize = 4

		// PE32 contains an additional field in the optional header.
		var baseOfData uint32
		if err = binary.Read(r, binary.LittleEndian, &baseOfData); err != nil {
			return
		}
	default:
		err = fmt.Errorf("unknown magic in optional header: %x", optionalHeader.Magic)
		return
	}

	// Skip the Windows-specific header section up to the number of data
	// directory entries.
	toSkip := addressSize + 40 + addressSize*4 + 4
	skipBuf := make([]byte, toSkip)
	if _, err = r.Read(skipBuf); err != nil {
		return
	}

	// Read the number of directory entries, which is also the last value
	// in the Windows-specific header.
	var numDirectoryEntries uint32
	if err = binary.Read(r, binary.LittleEndian, &numDirectoryEntries); err != nil {
		return
	}

	if numDirectoryEntries > 4096 {
		err = fmt.Errorf("invalid number of directory entries: %d", numDirectoryEntries)
		return
	}

	dataDirectory := make([]dataDirectory, numDirectoryEntries)
	if err = binary.Read(r, binary.LittleEndian, dataDirectory); err != nil {
		return
	}

	if numDirectoryEntries <= certificateTableIndex {
		err = errors.New("file does not have enough data directory entries for a certificate")
		return
	}
	certEntry := dataDirectory[certificateTableIndex]
	if certEntry.VirtualAddress == 0 {
		err = errors.New("file does not have certificate data")
		return
	}

	certEntryEnd := certEntry.VirtualAddress + certEntry.Size
	if certEntryEnd < certEntry.VirtualAddress {
		err = errors.New("overflow while calculating end of certificate entry")
		return
	}

	if int(certEntryEnd) != len(bin) {
		err = fmt.Errorf("certificate entry is not at end of file: %d vs %d", int(certEntryEnd), len(bin))
		return
	}

	var dummyByte [1]byte
	if _, readErr := r.Read(dummyByte[:]); readErr == nil || readErr != io.EOF {
		err = errors.New("optional header contains extra data after data directory")
		return
	}

	offset = int(certEntry.VirtualAddress)
	size = int(certEntry.Size)
	sizeOffset = int(peOffset) + 4 + fileHeaderSize + int(fileHeader.SizeOfOptionalHeader) - 8*(int(numDirectoryEntries)-certificateTableIndex) + 4

	if binary.LittleEndian.Uint32(bin[sizeOffset:]) != certEntry.Size {
		err = errors.New("internal error when calculating certificate data size offset")
		return
	}

	return
}

func lengthAsn1(asn1 []byte) (asn1Length int, err error) {
	// Read the ASN.1 length of the object.
	if asn1[1]&0x80 == 0 {
		// Short form length.
		asn1Length = int(asn1[1]) + 2
	} else {
		numBytes := int(asn1[1] & 0x7f)
		if numBytes == 0 || numBytes > 2 {
			err = fmt.Errorf("bad number of bytes in ASN.1 length: %d", numBytes)
			return
		}
		if len(asn1) < numBytes+2 {
			err = errors.New("ASN.1 structure truncated")
			return
		}
		asn1Length = int(asn1[2])
		if numBytes == 2 {
			asn1Length <<= 8
			asn1Length |= int(asn1[3])
		}
		asn1Length += 2 + numBytes
	}
	return
}

func parseSignedData(asn1Data []byte) (*signedData, error) {
	var signedData signedData
	if _, err := asn1.Unmarshal(asn1Data, &signedData); err != nil {
		return nil, errors.New("authenticodetag: error while parsing SignedData structure: " + err.Error())
	}

	der, err := asn1.Marshal(signedData)
	if err != nil {
		return nil, errors.New("authenticodetag: error while marshaling SignedData structure: " + err.Error())
	}

	if !bytes.Equal(der, asn1Data) {
		return nil, errors.New("authenticodetag: ASN.1 parse/unparse test failed")
	}
	return &signedData, nil
}

