package server

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"
)

type Config struct {
	Addr     string
	StateDir string
	MaxTTL   int
}

func Run(cfg Config) error {
	mux := http.NewServeMux()

	mux.HandleFunc("GET /healthz", handleHealth)
	mux.HandleFunc("GET /.well-known/openid-configuration", handleDiscovery)
	mux.HandleFunc("GET /jwks.json", handleJWKS)
	mux.HandleFunc("POST /token", handleToken(cfg))

	srv := &http.Server{
		Addr:              cfg.Addr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}

	log.Printf("tapid listening on http://%s", cfg.Addr)
	return srv.ListenAndServe()
}

func handleHealth(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func handleDiscovery(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusNotImplemented, map[string]string{"error": "not_implemented"})
}

func handleJWKS(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusNotImplemented, map[string]string{"error": "not_implemented"})
}

func handleToken(cfg Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		audience := r.FormValue("audience")
		if audience == "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "audience_required"})
			return
		}
		writeJSON(w, http.StatusNotImplemented, map[string]string{
			"error":  "not_implemented",
			"detail": fmt.Sprintf("audience=%s max_ttl=%d", audience, cfg.MaxTTL),
		})
	}
}

func writeJSON(w http.ResponseWriter, code int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(body)
}
