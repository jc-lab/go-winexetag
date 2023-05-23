package winexetag

import (
	"errors"
	"github.com/lunixbochs/struc"
	"io"
)

const (
	IMAGE_DOS_SIGNATURE              = 0x5A4D
	IMAGE_DOS_HEADER_SIZE            = 64
	IMAGE_FILE_HEADER_SIZE           = 20
	IMAGE_NUMBEROF_DIRECTORY_ENTRIES = 14
)

var (
	IMAGE_NT_HEADER_SIGNATURE = []byte{'P', 'E', 0, 0}
)

var (
	ErrTruncated = errors.New("truncated file")
)

type ImageFileMachine = uint16

const (
	IMAGE_FILE_MACHINE_I386  ImageFileMachine = 0x014c
	IMAGE_FILE_MACHINE_IA64  ImageFileMachine = 0x0200
	IMAGE_FILE_MACHINE_AMD64 ImageFileMachine = 0x8664
)

type IMAGE_DOS_HEADER struct {
	Magic    uint16     `struc:"uint16,little"` // Magic number
	Cblp     uint16     `struc:"uint16,little"` // Byte on last page of file
	Cp       uint16     `struc:"uint16,little"` // Pages in file
	Crlc     uint16     `struc:"uint16,little"` // Relocations
	Cparhdr  uint16     `struc:"uint16,little"` // Size of header in paragraphs
	Minalloc uint16     `struc:"uint16,little"` // Minimum extra paragraphs needed
	Maxalloc uint16     `struc:"uint16,little"` // Maximum extra paragraphs needed
	Ss       uint16     `struc:"uint16,little"` // Initial (relative) SS value
	Sp       uint16     `struc:"uint16,little"` // Initial SP value
	Csum     uint16     `struc:"uint16,little"` // Checksum
	Ip       uint16     `struc:"uint16,little"` // Initial IP value
	Cs       uint16     `struc:"uint16,little"` // Initial (relative) CS value
	Lfarlc   uint16     `struc:"uint16,little"` // File address of relocation table
	Ovno     uint16     `struc:"uint16,little"` // Overlay number
	Res      [4]uint16  `struc:"[4]uint16"`     // Reserved words
	Oemid    uint16     `struc:"uint16,little"` // OEM identifier (for e_oeminfo)
	Oeminfo  uint16     `struc:"uint16,little"` // OEM information; e_oemid specific
	Res2     [10]uint16 `struc:"[10]uint16"`    // Reserved words
	Lfanew   int32      `struc:"int32,little"`  // File address of new exe header
}

func (h *IMAGE_DOS_HEADER) ReadFrom(reader io.Reader) error {
	return struc.Unpack(reader, h)
}

// The structures here were taken from "Microsoft Portable Executable and
// Common Object File Format Specification".

// IMAGE_FILE_HEADER represents the IMAGE_FILE_HEADER structure from
// http://msdn.microsoft.com/en-us/library/windows/desktop/ms680313(v=vs.85).aspx.
type IMAGE_FILE_HEADER struct {
	Machine               ImageFileMachine `struc:"uint16,little"`
	NumberOfSections      uint16           `struc:"uint16,little"`
	TimeDateStamp         uint32           `struc:"uint32,little"`
	PointerForSymbolTable uint32           `struc:"uint32,little"`
	NumberOfSymbols       uint32           `struc:"uint32,little"`
	SizeOfOptionalHeader  uint16           `struc:"uint16,little"`
	Characteristics       uint16           `struc:"uint16,little"`
}

func (h *IMAGE_FILE_HEADER) ReadFrom(reader io.Reader) error {
	return struc.Unpack(reader, h)
}

type IMAGE_DATA_DIRECTORY struct {
	VirtualAddress uint32 `struc:"uint32,little"`
	Size           uint32 `struc:"uint32,little"`
}

// IMAGE_OPTIONAL_HEADER32 represents the IMAGE_OPTIONAL_HEADER structure from
// http://msdn.microsoft.com/en-us/library/windows/desktop/ms680339(v=vs.85).aspx.
type IMAGE_OPTIONAL_HEADER32 struct {
	Magic                       uint16 `struc:"uint16,little"` // Magic number
	MajorLinkerVersion          byte   `struc:"byte"`          // Major linker version
	MinorLinkerVersion          byte   `struc:"byte"`          // Minor linker version
	SizeOfCode                  uint32 `struc:"uint32,little"` // Size of code
	SizeOfInitializedData       uint32 `struc:"uint32,little"` // Size of initialized data
	SizeOfUninitializedData     uint32 `struc:"uint32,little"` // Size of uninitialized data
	AddressOfEntryPoint         uint32 `struc:"uint32,little"` // Address of entry point
	BaseOfCode                  uint32 `struc:"uint32,little"` // Base address of code
	BaseOfData                  uint32 `struc:"uint32,little"` // Base address of data
	ImageBase                   uint32 `struc:"uint32,little"` // Image base address
	SectionAlignment            uint32 `struc:"uint32,little"` // Section alignment
	FileAlignment               uint32 `struc:"uint32,little"` // File alignment
	MajorOperatingSystemVersion uint16 `struc:"uint16,little"` // Major operating system version
	MinorOperatingSystemVersion uint16 `struc:"uint16,little"` // Minor operating system version
	MajorImageVersion           uint16 `struc:"uint16,little"` // Major image version
	MinorImageVersion           uint16 `struc:"uint16,little"` // Minor image version
	MajorSubsystemVersion       uint16 `struc:"uint16,little"` // Major subsystem version
	MinorSubsystemVersion       uint16 `struc:"uint16,little"` // Minor subsystem version
	Win32VersionValue           uint32 `struc:"uint32,little"` // Win32 version value
	SizeOfImage                 uint32 `struc:"uint32,little"` // Size of image
	SizeOfHeaders               uint32 `struc:"uint32,little"` // Size of headers
	CheckSum                    uint32 `struc:"uint32,little"` // Checksum
	Subsystem                   uint16 `struc:"uint16,little"` // Subsystem
	DllCharacteristics          uint16 `struc:"uint16,little"` // DLL characteristics
	SizeOfStackReserve          uint32 `struc:"uint32,little"` // Size of stack to reserve
	SizeOfStackCommit           uint32 `struc:"uint32,little"` // Size of stack to commit
	SizeOfHeapReserve           uint32 `struc:"uint32,little"` // Size of heap to reserve
	SizeOfHeapCommit            uint32 `struc:"uint32,little"` // Size of heap to commit
	LoaderFlags                 uint32 `struc:"uint32,little"` // Loader flags
	NumberOfRvaAndSizes         uint32 `struc:"uint32,little"` // Number of data-directory entries
	//DataDirectory               [IMAGE_NUMBEROF_DIRECTORY_ENTRIES]IMAGE_DATA_DIRECTORY `struc:"[16]IMAGE_DATA_DIRECTORY"` // Data directory
}

func (h *IMAGE_OPTIONAL_HEADER32) ReadFrom(reader io.Reader) error {
	return struc.Unpack(reader, h)
}

type IMAGE_OPTIONAL_HEADER64 struct {
	Magic                       uint16 `struc:"uint16,little"` // Magic number
	MajorLinkerVersion          byte   `struc:"byte"`          // Major linker version
	MinorLinkerVersion          byte   `struc:"byte"`          // Minor linker version
	SizeOfCode                  uint32 `struc:"uint32,little"` // Size of code
	SizeOfInitializedData       uint32 `struc:"uint32,little"` // Size of initialized data
	SizeOfUninitializedData     uint32 `struc:"uint32,little"` // Size of uninitialized data
	AddressOfEntryPoint         uint32 `struc:"uint32,little"` // Address of entry point
	BaseOfCode                  uint32 `struc:"uint32,little"` // Base address of code
	ImageBase                   uint64 `struc:"uint64,little"` // Image base address
	SectionAlignment            uint32 `struc:"uint32,little"` // Section alignment
	FileAlignment               uint32 `struc:"uint32,little"` // File alignment
	MajorOperatingSystemVersion uint16 `struc:"uint16,little"` // Major operating system version
	MinorOperatingSystemVersion uint16 `struc:"uint16,little"` // Minor operating system version
	MajorImageVersion           uint16 `struc:"uint16,little"` // Major image version
	MinorImageVersion           uint16 `struc:"uint16,little"` // Minor image version
	MajorSubsystemVersion       uint16 `struc:"uint16,little"` // Major subsystem version
	MinorSubsystemVersion       uint16 `struc:"uint16,little"` // Minor subsystem version
	Win32VersionValue           uint32 `struc:"uint32,little"` // Win32 version value
	SizeOfImage                 uint32 `struc:"uint32,little"` // Size of image
	SizeOfHeaders               uint32 `struc:"uint32,little"` // Size of headers
	CheckSum                    uint32 `struc:"uint32,little"` // Checksum
	Subsystem                   uint16 `struc:"uint16,little"` // Subsystem
	DllCharacteristics          uint16 `struc:"uint16,little"` // DLL characteristics
	SizeOfStackReserve          uint64 `struc:"uint64,little"` // Size of stack to reserve
	SizeOfStackCommit           uint64 `struc:"uint64,little"` // Size of stack to commit
	SizeOfHeapReserve           uint64 `struc:"uint64,little"` // Size of heap to reserve
	SizeOfHeapCommit            uint64 `struc:"uint64,little"` // Size of heap to commit
	LoaderFlags                 uint32 `struc:"uint32,little"` // Loader flags
	NumberOfRvaAndSizes         uint32 `struc:"uint32,little"` // Number of data-directory entries
	//DataDirectory               [IMAGE_NUMBEROF_DIRECTORY_ENTRIES]IMAGE_DATA_DIRECTORY `struc:"[16]IMAGE_DATA_DIRECTORY"` // Data directory
}

func (h *IMAGE_OPTIONAL_HEADER64) ReadFrom(reader io.Reader) error {
	return struc.Unpack(reader, h)
}
