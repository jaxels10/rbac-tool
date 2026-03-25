package main

import (
	_ "embed"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"os"
	"syscall"

	"github.com/user/rbac-tool/internal/k8s"
)

//go:embed templates/index.html
var indexHTML string

func main() {
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	client, err := k8s.NewClient()
	if err != nil {
		log.Fatalf("failed to create kubernetes client: %v", err)
	}

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		if _, err := io.WriteString(w, indexHTML); err != nil && !errors.Is(err, syscall.EPIPE) && !errors.Is(err, syscall.ECONNRESET) {
			log.Printf("write error: %v", err)
		}
	})

	http.HandleFunc("/api/rbac", func(w http.ResponseWriter, r *http.Request) {
		data, err := client.GetRBACData(r.Context())
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(data); err != nil && !errors.Is(err, syscall.EPIPE) && !errors.Is(err, syscall.ECONNRESET) {
			log.Printf("json encode error: %v", err)
		}
	})

	log.Printf("RBAC Tool listening on :%s", port)
	log.Fatal(http.ListenAndServe(":"+port, nil))
}
