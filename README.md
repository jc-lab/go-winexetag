# go-winexetag
[![GoDoc](https://godoc.org/github.com/ianatha/go-winexetag?status.svg)](https://godoc.org/github.com/ianatha/go-winexetag) [![Go Reference](https://pkg.go.dev/badge/github.com/ianatha/go-winexetag.svg)](https://pkg.go.dev/github.com/ianatha/go-winexetag)

Embed custom data in code-signed PE (Windows) executables without breaking
the signature.

This project is comprised of three parts:
* The `winexetag` library.
* `exetag-tool`, a CLI tool, to manipulate tags on code-signed PE files.
* `exetag-httpd`, a rudimentary HTTP server, to tag code-signed EXE files on the fly.

## Origin
Original source code extracted from `certificate_tag`, a tool included in
[Google's Omaha project](https://github.com/google/omaha/blob/master/common/certificate_tag/certificate_tag.go), which
is the open-source version of Google Update for Windows.