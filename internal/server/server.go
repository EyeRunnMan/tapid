package server

import (
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"strconv"
	"time"

	"github.com/EyeRunnMan/tapid/internal/jwks"
	"github.com/EyeRunnMan/tapid/internal/jwt"
	"github.com/EyeRunnMan/tapid/internal/keystore"
	"github.com/EyeRunnMan/tapid/internal/state"
)

type Config struct {
	Addr   string
	MaxTTL int

	Device  state.Device
	Signer  keystore.Store
}

func Run(cfg Config) error {
	if cfg.Signer == nil {
		return errors.New("server: nil signer")
	}
	if cfg.Device.IssuerURL == "" {
		return errors.New("server: empty issuer URL")
	}
	if cfg.MaxTTL <= 0 {
		cfg.MaxTTL = 3600
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", handleHealth)
	mux.HandleFunc("GET /.well-known/openid-configuration", handleDiscovery(cfg))
	mux.HandleFunc("GET /jwks.json", handleJWKS(cfg))
	mux.HandleFunc("POST /token", handleToken(cfg))

	srv := &http.Server{
		Addr:              cfg.Addr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}
	log.Printf("tapid listening on http://%s (issuer=%s tier=%s)",
		cfg.Addr, cfg.Device.IssuerURL, cfg.Device.KeyTier)
	return srv.ListenAndServe()
}

func handleHealth(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func handleDiscovery(cfg Config) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, jwks.Discovery(cfg.Device.IssuerURL))
	}
}

func handleJWKS(cfg Config) http.HandlerFunc {
	set, err := jwks.FromPublicKey(cfg.Signer.PublicKey(), cfg.Device.Kid)
	if err != nil {
		// Build error is unrecoverable — daemon shouldn't have started.
		// Return a closure that 500s consistently so the operator notices.
		return func(w http.ResponseWriter, _ *http.Request) {
			writeJSON(w, http.StatusInternalServerError, map[string]string{
				"error": "jwks_build_failed", "detail": err.Error(),
			})
		}
	}
	return func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, set)
	}
}

// tokenClaims is the JWT body. Field order matches SPEC §7.
type tokenClaims struct {
	Iss        string `json:"iss"`
	Sub        string `json:"sub"`
	Aud        string `json:"aud"`
	Iat        int64  `json:"iat"`
	Exp        int64  `json:"exp"`
	Jti        string `json:"jti"`
	DeviceID   string `json:"device_id"`
	DeviceName string `json:"device_name,omitempty"`
	KeyTier    string `json:"key_tier"`
}

type tokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:"expires_in"`
}

func handleToken(cfg Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			writeJSON(w, http.StatusBadRequest, errResp("bad_request"))
			return
		}
		audience := r.FormValue("audience")
		if audience == "" {
			writeJSON(w, http.StatusBadRequest, errResp("audience_required"))
			return
		}

		ttl := cfg.MaxTTL
		if v := r.FormValue("ttl"); v != "" {
			n, err := strconv.Atoi(v)
			if err != nil || n <= 0 {
				writeJSON(w, http.StatusBadRequest, errResp("ttl_invalid"))
				return
			}
			if n > cfg.MaxTTL {
				n = cfg.MaxTTL
			}
			ttl = n
		}

		now := time.Now().UTC()
		jti, err := newJTI()
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, errResp("jti_failed"))
			return
		}
		claims := tokenClaims{
			Iss:        cfg.Device.IssuerURL,
			Sub:        "device:" + cfg.Device.DeviceID,
			Aud:        audience,
			Iat:        now.Unix(),
			Exp:        now.Add(time.Duration(ttl) * time.Second).Unix(),
			Jti:        jti,
			DeviceID:   cfg.Device.DeviceID,
			DeviceName: hostnameSafe(),
			KeyTier:    cfg.Device.KeyTier,
		}

		tok, err := jwt.Sign(claims, cfg.Device.Kid, cfg.Signer)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, errResp("sign_failed"))
			return
		}
		writeJSON(w, http.StatusOK, tokenResponse{
			AccessToken: tok,
			TokenType:   "Bearer",
			ExpiresIn:   ttl,
		})
	}
}

func errResp(code string) map[string]string { return map[string]string{"error": code} }

func writeJSON(w http.ResponseWriter, code int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(body)
}
