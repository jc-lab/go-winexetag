package winexetag

import (
	"bytes"
	"encoding/asn1"
	"encoding/binary"
	"errors"
	"fmt"
	"github.com/lunixbochs/struc"
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
func getAttributeCertificates(reader io.ReadSeeker) (offset int64, size int, sizeOffset int64, err error) {
	var dosHeader IMAGE_DOS_HEADER
	var fileHeader IMAGE_FILE_HEADER

	if _, err = reader.Seek(0, io.SeekStart); err != nil {
		return
	}
	if err = dosHeader.ReadFrom(reader); err != nil {
		return
	}

	peHeaderOffset := dosHeader.Lfanew
	if _, err = reader.Seek(int64(peHeaderOffset), io.SeekStart); err != nil {
		return
	}

	peSignatureBuf := make([]byte, 4)
	if _, err = io.ReadFull(reader, peSignatureBuf); err != nil {
		return
	}
	if !bytes.Equal(peSignatureBuf, IMAGE_NT_HEADER_SIGNATURE) {
		err = errors.New("PE header not found at expected offset")
		return
	}

	if err = fileHeader.ReadFrom(reader); err != nil {
		return
	}

	if fileHeader.Machine != IMAGE_FILE_MACHINE_AMD64 && fileHeader.Machine != IMAGE_FILE_MACHINE_I386 {
		err = errors.New("not supported machine")
		return
	}

	optionalHeaderRaw := make([]byte, fileHeader.SizeOfOptionalHeader)
	if _, err = io.ReadFull(reader, optionalHeaderRaw); err != nil {
		return
	}
	optionalHeaderReader := bytes.NewReader(optionalHeaderRaw)

	// addressSize is the size of various fields in the Windows-specific
	// header to follow.
	var addressSize int
	var baseOfData uint32
	var numOfDirectoryEntries uint32

	if fileHeader.Machine == IMAGE_FILE_MACHINE_AMD64 {
		var optionalHeader IMAGE_OPTIONAL_HEADER64
		if err = optionalHeader.ReadFrom(optionalHeaderReader); err != nil {
			return
		}
		addressSize = 8
		baseOfData = optionalHeader.BaseOfCode
		numOfDirectoryEntries = optionalHeader.NumberOfRvaAndSizes
	} else if fileHeader.Machine == IMAGE_FILE_MACHINE_I386 {
		var optionalHeader IMAGE_OPTIONAL_HEADER32
		if err = optionalHeader.ReadFrom(optionalHeaderReader); err != nil {
			return
		}
		addressSize = 4
		baseOfData = optionalHeader.BaseOfData
		numOfDirectoryEntries = optionalHeader.NumberOfRvaAndSizes
	} else {
	}

	_ = addressSize
	_ = baseOfData

	//dataDirectoriesRaw := make([]byte, 8*numOfDirectoryEntries)
	//if _, err = io.ReadFull(reader, dataDirectoriesRaw); err != nil {
	//	return
	//}

	dataDirectories := make([]IMAGE_DATA_DIRECTORY, numOfDirectoryEntries)
	for i := 0; i < int(numOfDirectoryEntries); i++ {
		if err = struc.Unpack(optionalHeaderReader, &dataDirectories[i]); err != nil {
			return
		}
	}

	if numOfDirectoryEntries <= certificateTableIndex {
		err = errors.New("file does not have enough data directory entries for a certificate")
		return
	}
	certEntry := dataDirectories[certificateTableIndex]
	if certEntry.VirtualAddress == 0 {
		err = errors.New("file does not have certificate data")
		return
	}

	certEntryEnd := certEntry.VirtualAddress + certEntry.Size
	if certEntryEnd < certEntry.VirtualAddress {
		err = errors.New("overflow while calculating end of certificate entry")
		return
	}

	offset = int64(certEntry.VirtualAddress)
	size = int(certEntry.Size)
	sizeOffset = int64(peHeaderOffset) + 4 + IMAGE_FILE_HEADER_SIZE + int64(fileHeader.SizeOfOptionalHeader) - 8*(int64(numOfDirectoryEntries)-certificateTableIndex) + 4

	if _, err = reader.Seek(sizeOffset, io.SeekStart); err != nil {
		return
	}
	buf := make([]byte, size)
	if _, err = io.ReadFull(reader, buf); err != nil {
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
