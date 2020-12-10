package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"time"
)

func indexHandler(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.Error(w, "404 not found.", http.StatusNotFound)
		return
	}

	if r.Method != "GET" {
		http.Error(w, "405 method not allowed.", http.StatusMethodNotAllowed)
		return
	}

	fmt.Fprintf(w, "OK")
}

func NewLoggingddleware() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		fn := func(w http.ResponseWriter, r *http.Request) {
			// Logic here
			log.Printf("%s %s", r.Method, r.URL)

			// Call the next handler
			next.ServeHTTP(w, r)
		}

		return http.HandlerFunc(fn)
	}
}

var ORIGIN string

func main() {
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	origin := os.Getenv("ORIGIN")
	if origin == "" {
		log.Fatalf("You must define an ORIGIN by setting the env var")
	}

	ORIGIN = origin

	mux := http.NewServeMux()
	mux.HandleFunc("/custom_exe", customExeHandler)
	mux.HandleFunc("/prime", primeHandler)
	mux.HandleFunc("/", indexHandler)

	srv := &http.Server{
		Addr: ":" + port,
		ReadTimeout: 1 * time.Second,
		WriteTimeout: 5 * time.Second,
		IdleTimeout: 5 * time.Second,
		Handler: NewLoggingddleware()(mux),
	}

	log.Printf("PORT=%s Starting...", port)

	if err := srv.ListenAndServe(); err != nil {
		log.Fatal(err)
	}
}