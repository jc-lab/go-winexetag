// Program exetag-tool manipulates "tags" in Authenticode-signed
// Windows binaries.
//
// Traditionally we have inserted tag data after the PKCS#7 blob in the file
// (called an "appended tag" here). This area is not hashed in when checking
// the signature so we can alter it at serving time without invalidating the
// Authenticode signature.
//
// However, Microsoft are changing the verification function to forbid that so
// this tool also handles "superfluous certificate" tags. These are dummy
// certificates, inserted into the PKCS#7 certificate chain, that can contain
// arbitrary data in extensions. Since they are also not hashed when verifying
// signatures, that data can also be changed without invalidating it.
//
// The tool supports PE32 exe files and MSI files.
package main

import (
	"encoding/hex"
	"flag"
	"fmt"
	exetag "github.com/ianatha/go-winexetag"
	"io/ioutil"
	"os"
	"strings"
)

var (
	setTag       *string = flag.String("set-tag", "", "If set, this flag contains a string and a tagging certificate tag with that value will be set and the binary rewritten. If the string begins with '0x' then it will be interpreted as hex")
	paddedLength *int    = flag.Int("padded-length", 0, "A cert tag will be padded with zeros to at least this number of bytes")
	outFilename  *string = flag.String("out", "", "If set, the updated binary is written to this file. Otherwise the binary is updated in place.")
)

func main() {
	flag.Parse()
	args := flag.Args()
	if len(args) != 1 {
		fmt.Fprintf(os.Stderr, "Usage: %s [flags] binary.exe\n", os.Args[0])
		os.Exit(255)
	}
	inFilename := args[0]
	if len(*outFilename) == 0 {
		outFilename = &inFilename
	}

	contents, err := ioutil.ReadFile(inFilename)
	if err != nil {
		panic(err)
	}

	bin, err := exetag.NewBinary(contents)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", err)
		os.Exit(1)
	}

	didSomething := false

	if len(*setTag) > 0 {
		var tagContents []byte

		if strings.HasPrefix(*setTag, "0x") {
			tagContents, err = hex.DecodeString((*setTag)[2:])
			if err != nil {
				fmt.Fprintf(os.Stderr, "Failed to parse tag contents from command line: %s\n", err)
				os.Exit(1)
			}
		} else {
			tagContents = []byte(*setTag)
		}

		for len(tagContents) < *paddedLength {
			tagContents = append(tagContents, 0)
		}
		// print-tag-details only works if the length requires 2 bytes to specify. (The length bytes
		// length is part of the search string.)
		// Lorry only tags properly (aside from tag-in-zip) if the length is 8206 or more. b/173139534
		// Omaha may or may not have a practical buffer size limit; 8206 is known to work.
		if len(tagContents) < 0x100 || len(tagContents) > 0xffff {
			fmt.Fprintf(os.Stderr, "Want final tag length in range [256, 65535], got %d\n", len(tagContents))
			os.Exit(1)
		}

		writer, err := os.OpenFile(*outFilename, os.O_RDWR|os.O_CREATE, 0644)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error while open output file: %v\n", err)
			os.Exit(1)
		}
		defer writer.Close()

		if err = bin.SetTag(writer, tagContents); err != nil {
			fmt.Fprintf(os.Stderr, "Error while setting superfluous certificate tag: %s\n", err)
			os.Exit(1)
		}
		didSomething = true
	}

	if !didSomething {
		// By default, print basic information.
		appendedTag, ok := bin.GetTag()
		if ok != nil {
			fmt.Printf("No appended tag\n")
		} else {
			fmt.Printf("Appended tag included, %d bytes\n", len(appendedTag))
		}
	}
}
