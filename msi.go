package winexetag

import (
	"bytes"
	"crypto/x509"
	"encoding/binary"
	"errors"
	fmt "fmt"
	"io"
	"os"
)

// Variables now defined as secT and offT were initially hardcoded as |int| for simplicity,
// but this produced errors when run on a Windows machine, which defaulted to a 32-bit arch.
// See b/172261939.

// secT is the type of a sector ID, or an index into the FAT (which describes what is in
// that sector), or a number of sectors.
type secT uint32

// offT is the type of an offset into the MSI file contents, or a number of bytes.
type offT uint64

// MSIBinary represents an MSI binary.
// |headerBytes| and |contents| are non-overlapping slices of the same backing array.
type MSIBinary struct {
	headerBytes     []byte       // the header (512 bytes).
	header          *MSIHeader   // the parsed msi header.
	sector          SectorFormat // sector parameters.
	contents        []byte       // the file content (no header), with SignedData removed.
	sigDirOffset    offT         // the offset of the signedData stream directory in |contents|.
	sigDirEntry     *MSIDirEntry // the parsed contents of the signedData stream directory.
	signedDataBytes []byte       // the PKCS#7, SignedData in asn1 DER form.
	signedData      *signedData  // the parsed SignedData structure.
	fatEntries      []secT       // a copy of the FAT entries in one list.
	difatEntries    []secT       // a copy of the DIFAT entries in one list.
	difatSectors    []secT       // a list of the dedicated DIFAT sectors (if any), for convenience.
}

// MSIHeader represents a parsed MSI header.
type MSIHeader struct {
	Magic                      [8]byte
	Clsid                      [16]byte
	MinorVersion               uint16
	DllVersion                 uint16
	ByteOrder                  uint16
	SectorShift                uint16
	MiniSectorShift            uint16
	Reserved                   [6]byte
	NumDirSectors              uint32
	NumFatSectors              uint32
	FirstDirSector             uint32
	TransactionSignatureNumber uint32
	MiniStreamCutoffSize       uint32
	FirstMiniFatSector         uint32
	NumMiniFatSectors          uint32
	FirstDifatSector           uint32
	NumDifatSectors            uint32
}

// MSIDirEntry represents a parsed MSI directory entry for a stream.
type MSIDirEntry struct {
	Name              [64]byte
	NumNameBytes      uint16
	ObjectType        uint8
	ColorFlag         uint8
	Left              uint32
	Right             uint32
	Child             uint32
	Clsid             [16]byte
	StateFlags        uint32
	CreateTime        uint64
	ModifyTime        uint64
	StreamFirstSector uint32
	StreamSize        uint64
}

// SectorFormat represents parameters of an MSI file sector.
type SectorFormat struct {
	Size offT // the size of a sector in bytes; 512 for dll v3 and 4096 for v4.
	Ints int  // the number of int32s in a sector.
}

const (
	numHeaderContentBytes = 76
	numHeaderTotalBytes   = 512
	numDifatHeaderEntries = 109
	numDirEntryBytes      = 128
	miniStreamSectorSize  = 64
	miniStreamCutoffSize  = 4096
	// Constants and names from https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-cfb/
	fatFreesect   = 0xFFFFFFFF // An unallocated sector (used in the FAT or DIFAT).
	fatEndofchain = 0xFFFFFFFE // End of a linked chain (in the FAT); or end of DIFAT sector chain.
	fatFatsect    = 0xFFFFFFFD // A FAT sector (used in the FAT).
	fatDifsect    = 0xFFFFFFFC // A DIFAT sector (used in the FAT).
	fatReserved   = 0xFFFFFFFB // Reserved value.
)

func newSectorFormat(sectorShift uint16) (format SectorFormat, err error) {
	sectorSize := offT(1) << sectorShift
	if sectorSize != 4096 && sectorSize != 512 {
		return format, fmt.Errorf("unexpected msi sector shift, wanted sector size 4096 or 512, got %d", sectorSize)
	}
	return SectorFormat{
		Size: sectorSize,
		Ints: int(sectorSize / 4),
	}, nil
}

// isLastInSector returns whether the index into difatEntries corresponds to the last entry in
// a sector.
//
// The last entry in each difat sector is a pointer to the next difat sector.
// (Or is an end-of-chain marker.)
// This does not apply to the last entry stored in the MSI header.
func (format SectorFormat) isLastInSector(index int) bool {
	return index > numDifatHeaderEntries && (index-numDifatHeaderEntries+1)%format.Ints == 0
}

// readStream reads the stream starting at the given start sector. The name is optional,
// it is only used for error reporting.
func (bin *MSIBinary) readStream(name string, start secT, streamSize offT, forceFAT, freeData bool) (stream []byte, err error) {
	var sectorSize offT
	var fatEntries []secT // May be FAT or mini FAT.
	var contents []byte   // May be file contents or mini stream.
	if forceFAT || streamSize >= miniStreamCutoffSize {
		fatEntries = bin.fatEntries
		contents = bin.contents
		sectorSize = bin.sector.Size
	} else {
		// Load the mini FAT.
		s, err := bin.readStream("mini FAT", secT(bin.header.FirstMiniFatSector), offT(bin.header.NumMiniFatSectors)*bin.sector.Size, true, false)
		if err != nil {
			return nil, err
		}
		for offset := 0; offset < len(s); offset += 4 {
			fatEntries = append(fatEntries, secT(binary.LittleEndian.Uint32(s[offset:])))
		}
		// Load the mini stream. (root directory's stream, root must be dir entry zero)
		root := &MSIDirEntry{}
		offset := offT(bin.header.FirstDirSector) * bin.sector.Size
		binary.Read(bytes.NewBuffer(bin.contents[offset:]), binary.LittleEndian, root)
		contents, err = bin.readStream("mini stream", secT(root.StreamFirstSector), offT(root.StreamSize), true, false)
		if err != nil {
			return nil, err
		}
		sectorSize = miniStreamSectorSize
	}
	sector := start
	size := streamSize
	for size > 0 {
		if sector == fatEndofchain || sector == fatFreesect {
			return nil, fmt.Errorf("msi readStream: ran out of sectors in copying stream %q", name)
		}
		n := size
		if n > sectorSize {
			n = sectorSize
		}
		offset := sectorSize * offT(sector)
		stream = append(stream, contents[offset:offset+n]...)
		size -= n

		// Zero out the existing stream bytes, if requested.
		// For example, new signedData will be written at the end of
		// the file (which may be where the existing stream is, but this works regardless).
		// The stream bytes could be left as unused junk, but unused bytes in an MSI file are
		// typically zeroed.

		// Set the data in the sector to zero.
		if freeData {
			for i := offT(0); i < n; i++ {
				contents[offset+i] = 0
			}
		}
		// Find the next sector, then free the FAT entry of the current sector.
		old := sector
		sector = fatEntries[sector]
		if freeData {
			fatEntries[old] = fatFreesect
		}
	}
	return stream, nil
}

// Parse-time functionality is broken out into populate*() methods for clarity.

// populateFatEntries does what it says and should only be called from NewMSIBinary().
func (bin *MSIBinary) populateFatEntries() error {
	var fatEntries []secT
	for i, sector := range bin.difatEntries {
		// The last entry in a difat sector is a chaining entry.
		isLastInSector := bin.sector.isLastInSector(i)
		if sector == fatFreesect || sector == fatEndofchain || isLastInSector {
			continue
		}
		offset := offT(sector) * bin.sector.Size
		for i := 0; i < bin.sector.Ints; i++ {
			fatEntries = append(fatEntries, secT(binary.LittleEndian.Uint32(bin.contents[offset+offT(i)*4:])))
		}
	}
	bin.fatEntries = fatEntries
	return nil
}

// populateDifatEntries does what it says and should only be called from NewMSIBinary().
func (bin *MSIBinary) populateDifatEntries() error {
	// Copy the difat entries and make a list of difat sectors (if any).
	// The first 109 difat entries must exist and are read from the MSI header, the rest come from
	// optional additional sectors.
	difatEntries := make([]secT, numDifatHeaderEntries, numDifatHeaderEntries+int(bin.header.NumDifatSectors)*bin.sector.Ints)
	for i := 0; i < numDifatHeaderEntries; i++ {
		difatEntries[i] = secT(binary.LittleEndian.Uint32(bin.headerBytes[numHeaderContentBytes+i*4:]))
	}

	// Code (here and elsewhere) that manages additional difat sectors probably won't run in prod,
	// but is implemented to avoid a hidden scaling limit.
	// (109 difat sector entries) x (1024 fat sector entries/difat sector) x (4096 bytes/ fat sector)
	// => files up to ~457 MB in size don't require additional difat sectors.
	var difatSectors []secT
	for i := 0; i < int(bin.header.NumDifatSectors); i++ {
		var sector secT
		if i == 0 {
			sector = secT(bin.header.FirstDifatSector)
		} else {
			sector = difatEntries[len(difatEntries)-1]
		}
		difatSectors = append(difatSectors, sector)
		start := offT(sector) * bin.sector.Size
		for j := 0; j < bin.sector.Ints; j++ {
			difatEntries = append(difatEntries, secT(binary.LittleEndian.Uint32(bin.contents[start+offT(j)*4:])))
		}
	}
	bin.difatEntries = difatEntries
	bin.difatSectors = difatSectors
	return nil
}

var (
	// UTF-16 for "\05DigitalSignature"
	signatureName = []byte{0x05, 0x00, 0x44, 0x00, 0x69, 0x00, 0x67, 0x00, 0x69, 0x00, 0x74, 0x00, 0x61, 0x00, 0x6c, 0x00, 0x53, 0x00, 0x69, 0x00, 0x67, 0x00, 0x6e, 0x00, 0x61, 0x00, 0x74, 0x00, 0x75, 0x00, 0x72, 0x00, 0x65, 0x00, 0x00, 0x00}
)

// signedDataDirFromSector returns the directory entry for the signedData stream,
// if it exists in the given sector.
func (bin *MSIBinary) signedDataDirFromSector(dirSector secT) (sigDirEntry *MSIDirEntry, offset offT, found bool) {
	sigDirEntry = &MSIDirEntry{}
	// Fixed 128 byte directory entry size.
	for i := offT(0); i < bin.sector.Size/numDirEntryBytes; i++ {
		offset = offT(dirSector)*bin.sector.Size + i*numDirEntryBytes
		binary.Read(bytes.NewBuffer(bin.contents[offset:]), binary.LittleEndian, sigDirEntry)
		if bytes.Equal(sigDirEntry.Name[:sigDirEntry.NumNameBytes], signatureName) {
			return sigDirEntry, offset, true
		}
	}
	return
}

// populateSignatureDirEntry does what it says and should only be called from NewMSIBinary().
func (bin *MSIBinary) populateSignatureDirEntry() error {
	dirSector := secT(bin.header.FirstDirSector)
	for {
		if sigDirEntry, sigDirOffset, found := bin.signedDataDirFromSector(dirSector); found {
			bin.sigDirEntry = sigDirEntry
			bin.sigDirOffset = sigDirOffset
			return nil
		}
		// Did not find the entry, go to the next directory sector.
		// This is run on MSIs that Google creates, so don't worry about a malicious infinite loop
		// in the entries.
		dirSector = bin.fatEntries[dirSector]
		if dirSector == fatEndofchain {
			return errors.New("did not find signature stream in MSI file")
		}
	}
}

// populateSignedData does what it says and should only be called from NewMSIBinary().
func (bin *MSIBinary) populateSignedData() (err error) {
	sector := secT(bin.sigDirEntry.StreamFirstSector)
	size := offT(bin.sigDirEntry.StreamSize)
	if bin.header.DllVersion == 3 {
		size = size & 0x7FFFFFFF
	}
	stream, err := bin.readStream("signedData", sector, size, false, true)
	if err != nil {
		return err
	}
	bin.signedDataBytes = stream
	bin.signedData, err = parseSignedData(bin.signedDataBytes)
	if err != nil {
		return err
	}
	return nil
}

var (
	msiHeaderSignature = []byte{0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1}
	msiHeaderClsid     = make([]byte, 16)
)

// NewMSIBinary returns a Binary that contains details of the MSI binary given in |contents|.
// |contents| is modified; the region occupied by the cert section is zeroed out.
func NewMSIBinary(fileContents []byte) (*MSIBinary, error) {
	// Parses the MSI header, the directory entry for the SignedData, and the SignedData itself.
	// Makes copies of the list of FAT and DIFAT entries, for easier manipulation.
	// Zeroes out the SignedData stream in |contents|, as it may move.
	// When writing, the elements: (header, dir entry, SignedData, FAT and DIFAT entries)
	// are considered dirty (modified), and written back into fileContents.
	if len(fileContents) < numHeaderTotalBytes {
		return nil, fmt.Errorf("msi file is too short to contain header, want >= %d bytes got %d bytes", numHeaderTotalBytes, len(fileContents))
	}

	// Parse the header.
	headerBytes := fileContents[:numHeaderTotalBytes]
	var header MSIHeader
	binary.Read(bytes.NewBuffer(headerBytes[:numHeaderContentBytes]), binary.LittleEndian, &header)
	if !bytes.Equal(header.Magic[:], msiHeaderSignature) || !bytes.Equal(header.Clsid[:], msiHeaderClsid) {
		return nil, fmt.Errorf("msi file is not an msi file: either the header signature is missing or the clsid is not zero as required")
	}

	format, err := newSectorFormat(header.SectorShift)
	if err != nil {
		return nil, err
	}
	if offT(len(fileContents)) < format.Size {
		return nil, fmt.Errorf("msi file is too short to contain a full header sector, want >= %d bytes got %d bytes", format.Size, len(fileContents))
	}
	contents := fileContents[format.Size:]

	bin := &MSIBinary{
		headerBytes: headerBytes,
		header:      &header,
		sector:      format,
		contents:    contents,
	}

	// The difat entries must be populated before the fat entries.
	if err := bin.populateDifatEntries(); err != nil {
		return nil, err
	}
	if err := bin.populateFatEntries(); err != nil {
		return nil, err
	}
	// The signature dir entry must be populated before the signed data.
	if err := bin.populateSignatureDirEntry(); err != nil {
		return nil, err
	}
	if err := bin.populateSignedData(); err != nil {
		return nil, err
	}
	return bin, nil
}

// firstFreeFatEntry returns the index of the first free entry at the end of a slice of fat entries.
// It returns one past the end of list if there are no free entries at the end.
func firstFreeFatEntry(entries []secT) secT {
	firstFreeIndex := secT(len(entries))
	for entries[firstFreeIndex-1] == fatFreesect {
		firstFreeIndex--
	}
	return firstFreeIndex
}

func (bin *MSIBinary) firstFreeFatEntry() secT {
	return firstFreeFatEntry(bin.fatEntries)
}

// ensureFreeFatEntries ensures there are at least n free entries at the end of the FAT list,
// and returns the first free entry.
//
// The bin.fatEntry slice may be modified, any local references to the slice are invalidated.
// bin.fatEntry elements may be assigned, so any local references to entries (such as the
// first free index) are also invalidated.
// The function is re-entrant.
func (bin *MSIBinary) ensureFreeFatEntries(n secT) secT {
	sizeFat := secT(len(bin.fatEntries))
	firstFreeIndex := bin.firstFreeFatEntry() // Is past end of slice if there are no free entries.
	if sizeFat-firstFreeIndex >= n {
		// Nothing to do, there were already enough free sectors.
		return firstFreeIndex
	}
	// Append another FAT sector.
	for i := 0; i < bin.sector.Ints; i++ {
		bin.fatEntries = append(bin.fatEntries, fatFreesect)
	}
	// firstFreeIndex is free; assign it to the created FAT sector.
	// (Do not change the order of these calls; assignDifatEntry() could invalidate firstFreeIndex.)
	bin.fatEntries[firstFreeIndex] = fatFatsect
	bin.assignDifatEntry(firstFreeIndex)

	// Update the MSI header.
	bin.header.NumFatSectors++

	// If n is large enough, it's possible adding an additional sector was insufficient.
	// This won't happen for our use case; but the call to verify or fix it is cheap.
	bin.ensureFreeFatEntries(n)

	return bin.firstFreeFatEntry()
}

// assignDifatEntries assigns an entry (the sector# of a FAT sector) to the end of the difat list.
//
// The bin.fatEntry slice may be modified, any local references to the slice are invalidated.
// bin.fatEntry elements may be assigned, so any local references to entries (such as the
// first free index) are also invalidated.
func (bin *MSIBinary) assignDifatEntry(fatSector secT) {
	bin.ensureFreeDifatEntry()
	// Find first free entry at end of list.
	i := len(bin.difatEntries) - 1

	// If there are sectors, i could be pointing to a fatEndofchain marker, but in that case
	// it is guaranteed (by ensureFreeDifatEntry()) that the prior element is a free sector,
	// and the following loop works.

	// As long as the prior element is a free sector, decrement i.
	// If the prior element is at the end of a difat sector, skip over it.
	for bin.difatEntries[i-1] == fatFreesect ||
		(bin.sector.isLastInSector(i-1) && bin.difatEntries[i-2] == fatFreesect) {
		i--
	}
	bin.difatEntries[i] = fatSector
}

// ensureFreeDifatEntry ensures there is at least one free entry at the end of the DIFAT list.
//
// The bin.fatEntry slice may be modified, any local references to the slice are invalidated.
// bin.fatEntry elements may be assigned, so any local references to entries (such as the
// first free index) are also invalidated.
func (bin *MSIBinary) ensureFreeDifatEntry() {
	// By construction, difatEntries is at least numDifatHeaderEntries (109) long.
	i := len(bin.difatEntries) - 1
	if bin.difatEntries[i] == fatEndofchain {
		i--
	}
	if bin.difatEntries[i] == fatFreesect {
		return // There is at least one free entry.
	}

	oldDifatTail := len(bin.difatEntries) - 1

	// Allocate another sector of difat entries.
	for i := 0; i < bin.sector.Ints; i++ {
		bin.difatEntries = append(bin.difatEntries, fatFreesect)
	}
	bin.difatEntries[len(bin.difatEntries)-1] = fatEndofchain

	// Assign the new difat sector in the FAT.
	sector := bin.ensureFreeFatEntries(1)
	bin.fatEntries[sector] = fatDifsect

	// Assign the "next sector" pointer in the previous sector or header.
	if bin.header.NumDifatSectors == 0 {
		bin.header.FirstDifatSector = uint32(sector)
	} else {
		bin.difatEntries[oldDifatTail] = sector
	}
	bin.header.NumDifatSectors++
	bin.difatSectors = append(bin.difatSectors, sector) // A helper slice.
}

// buildBinary builds an MSI binary based on bin but with the given SignedData and appended tag.
// Appended tag is not supported for MSI.
// buildBinary may add free sectors to |bin|, but otherwise does not modify it.
func (bin *MSIBinary) buildBinary(writer io.Writer, signedData, tag []byte) error {
	if len(tag) > 0 {
		return errors.New("appended tags not supported in MSI files")
	}
	// Writing to the mini FAT is not supported.
	if len(signedData) < miniStreamCutoffSize {
		return fmt.Errorf("writing SignedData less than %d bytes is not supported", len(signedData))
	}
	// Ensure enough free FAT entries for the signedData.
	numSignedDataSectors := secT((offT(len(signedData))-1)/bin.sector.Size) + 1
	firstSignedDataSector := bin.ensureFreeFatEntries(numSignedDataSectors)

	// Allocate sectors for the signedData, in a copy of the FAT entries.
	newFatEntries := make([]secT, len(bin.fatEntries))
	copy(newFatEntries, bin.fatEntries)
	for i := secT(0); i < numSignedDataSectors-1; i++ {
		newFatEntries[firstSignedDataSector+i] = firstSignedDataSector + i + 1
	}
	newFatEntries[firstSignedDataSector+numSignedDataSectors-1] = fatEndofchain

	// Update the signedData stream's directory entry (location and size), in copy of dir entry.
	newSigDirEntry := *bin.sigDirEntry
	newSigDirEntry.StreamFirstSector = uint32(firstSignedDataSector)
	newSigDirEntry.StreamSize = uint64(len(signedData))

	// Write out the...
	// ...header,
	headerSectorBytes := make([]byte, bin.sector.Size)
	out := new(bytes.Buffer)
	binary.Write(out, binary.LittleEndian, bin.header)
	copy(headerSectorBytes[:], out.Bytes())
	for i := 0; i < numDifatHeaderEntries; i++ {
		binary.LittleEndian.PutUint32(headerSectorBytes[numHeaderContentBytes+i*4:], uint32(bin.difatEntries[i]))
	}
	// ...content,
	// Make a copy of the content bytes, since new data will be overlaid on it.
	// The new content slice should accommodate the new content size.
	firstFreeSector := firstFreeFatEntry(newFatEntries)
	contents := make([]byte, bin.sector.Size*offT(firstFreeSector)) // zero-based sector counting.
	copy(contents, bin.contents)

	// ...signedData directory entry (from local modified copy),
	out.Reset()
	binary.Write(out, binary.LittleEndian, &newSigDirEntry)
	copy(contents[bin.sigDirOffset:], out.Bytes())

	// ...difat entries,
	// They might have been modified, although usually not.
	for i, sector := range bin.difatSectors {
		index := numDifatHeaderEntries + i*bin.sector.Ints
		offset := offT(sector) * bin.sector.Size
		for j := 0; j < bin.sector.Ints; j++ {
			binary.LittleEndian.PutUint32(contents[offset+offT(j)*4:], uint32(bin.difatEntries[index+j]))
		}
	}
	// ...fat entries (from local modified copy),
	index := 0
	for i, sector := range bin.difatEntries {
		// The last entry in each difat sector is a pointer to the next difat sector.
		// This does not apply to the header entries.
		isLastInSector := bin.sector.isLastInSector(i)
		if sector != fatFreesect && sector != fatEndofchain && !isLastInSector {
			offset := offT(sector) * bin.sector.Size
			for i := 0; i < bin.sector.Ints; i++ {
				binary.LittleEndian.PutUint32(contents[offset+offT(i)*4:], uint32(newFatEntries[index+i]))
			}
			index += bin.sector.Ints
		}
	}
	// ...signedData
	// |contents| was zero-initialized, so no need to add padding to end of sector.
	// The sectors allocated for signedData were guaranteed contiguous.
	copy(contents[offT(firstSignedDataSector)*bin.sector.Size:], signedData)

	if _, err := writer.Write(headerSectorBytes); err != nil {
		return err
	}
	if _, err := writer.Write(contents); err != nil {
		return err
	}
	return nil
}

func (bin *MSIBinary) GetTagCert() (cert *x509.Certificate, index int, err error) {
	return getTagCert(bin.signedData)
}

// SetTagCertTag returns an MSI binary based on bin, but where the
// superfluous certificate contains the given tag data.
// The (parsed) bin.signedData is modified; but bin.signedDataBytes, which contains
// the raw original bytes, is not.
func (bin *MSIBinary) SetTag(writer io.Writer, tag []byte) (err error) {
	asn1Bytes, err := SetTagCertTag(bin.signedData, tag)
	if err != nil {
		return err
	}

	return bin.buildBinary(writer, asn1Bytes, nil)
}

func (bin *MSIBinary) GetTag() (tag []byte, err error) {
	crt, _, err := bin.GetTagCert()
	if err != nil {
		return nil, err
	}

	for _, xt := range crt.Extensions {
		if xt.Id.Equal(oidTagCert) {
			return xt.Value, nil
		}
	}

	return nil, os.ErrNotExist
}
