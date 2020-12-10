package main

import (
	exetag "github.com/ianatha/go-winexetag"
	"log"
	"net/http"
	"path/filepath"
	"regexp"
)

func customExeHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		http.Error(w, "Method is not supported.", http.StatusNotFound)
		return
	}

	q := r.URL.Query()
	from, from_ok := q["from"]
	data, data_ok := q["data"]
	desc, desc_ok := q["desc"]

	if !data_ok || !from_ok || !desc_ok {
		http.Error(w, "bad input data", http.StatusBadRequest)
		return
	}

	descS := removeNonAlpha(desc[0])
	ext := filepath.Ext(from[0])
	extlen := len(ext)
	newFilename := filepath.Base(from[0])[:len(from[0])-extlen] + "-for-" + descS + ext

	w.Header().Set("Content-Type", "application/vnd.microsoft.portable-executable")
	w.Header().Set("Content-Disposition", "attachment; filename=\""+newFilename+"\"")
	w.Header().Set("Keep-Alive", "timeout=30, max=2")
	w.WriteHeader(http.StatusOK)
	if f, ok := w.(http.Flusher); ok {
		f.Flush()
	}

	exeContents, err := fetchFrom(ORIGIN, from[0])
	if err != nil {
		http.Error(w, "error fetching bin", http.StatusInternalServerError)
		return
	}

	bin, err := exetag.NewBinary(exeContents)
	if err != nil {
		http.Error(w, "error fetching bin", http.StatusInternalServerError)
		return
	}

	contents, err := bin.SetTag(minBytes([]byte(data[0]), 256))
	if err != nil {
		http.Error(w, "error fetching bin", http.StatusInternalServerError)
		return
	}

	_, err = w.Write(contents)
	if err != nil {
		http.Error(w, "error writing bin", http.StatusInternalServerError)
	}
}

func minBytes(bb []byte, minSize int) []byte {
	if len(bb) > minSize {
		return bb
	}

	tmp := make([]byte, minSize)
	copy(tmp, bb)
	return tmp
}

func removeNonAlpha(s string) string {
	reg, err := regexp.Compile("[^a-zA-Z0-9]+")
	if err != nil {
		log.Fatal(err)
	}
	processedString := reg.ReplaceAllString(s, "_")
	return processedString
}
