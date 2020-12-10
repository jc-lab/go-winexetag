package main

import "net/http"

func primeHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		http.Error(w, "Method is not supported.", http.StatusNotFound)
		return
	}

	q := r.URL.Query()
	from, from_ok := q["from"]

	if !from_ok {
		http.Error(w, "bad input data", http.StatusBadRequest)
		return
	}

	go fetchFrom(ORIGIN, from[0])

	w.Write([]byte("async-ok"))
}
