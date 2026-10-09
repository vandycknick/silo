// Command forwardprobe is the real guest HTTP service used by the live forward gate.
package main

import (
	"encoding/json"
	"io"
	"log"
	"net/http"
	"time"
)

func main() {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		io.WriteString(w, "SILO_FORWARD_GUEST")
	})
	mux.HandleFunc("/headers", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"host": r.Host, "x_forwarded_host": r.Header.Get("X-Forwarded-Host"), "x_forwarded_proto": r.Header.Get("X-Forwarded-Proto")})
	})
	mux.HandleFunc("/stream", func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "first\n")
		w.(http.Flusher).Flush()
		select {
		case <-r.Context().Done():
			return
		case <-time.After(time.Second):
		}
		io.WriteString(w, "second\n")
	})
	// A separate held stream makes stop/cancellation proof independent of VM
	// shutdown speed, without changing /stream's one-second contract.
	mux.HandleFunc("/hold-stream", func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "first\n")
		w.(http.Flusher).Flush()
		<-r.Context().Done()
	})
	log.Fatal((&http.Server{Addr: "0.0.0.0:8080", Handler: mux, ReadHeaderTimeout: 30 * time.Second}).ListenAndServe())
}
