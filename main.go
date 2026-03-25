package main

import (
	"context"
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

type feedbackRequest struct {
	ID     string `json:"id"`
	Status string `json:"status"` // "confirmed", "dismissed", or "" to reset
}

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

	// Optionally seed feedback model from a file mounted at deploy time.
	if seedFile := os.Getenv("FEEDBACK_SEED_FILE"); seedFile != "" {
		if raw, err := os.ReadFile(seedFile); err == nil {
			var seed map[string]string
			if json.Unmarshal(raw, &seed) == nil {
				if err := client.SeedFeedback(context.Background(), seed); err != nil {
					log.Printf("warning: failed to load feedback seed: %v", err)
				} else {
					log.Printf("loaded %d feedback entries from seed file", len(seed))
				}
			}
		} else {
			log.Printf("warning: could not read feedback seed file %s: %v", seedFile, err)
		}
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

	http.HandleFunc("/api/feedback", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		var req feedbackRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		if req.ID == "" {
			http.Error(w, "id required", http.StatusBadRequest)
			return
		}
		if err := client.SetFeedback(r.Context(), req.ID, req.Status); err != nil {
			log.Printf("set feedback: %v", err)
			http.Error(w, "failed to save feedback", http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})

	log.Printf("RBAC Tool listening on :%s", port)
	log.Fatal(http.ListenAndServe(":"+port, nil))
}
