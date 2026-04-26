package server

import (
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/EyeRunnMan/tapid/internal/jwks"
	"github.com/EyeRunnMan/tapid/internal/jwt"
	"github.com/EyeRunnMan/tapid/internal/keystore"
	"github.com/EyeRunnMan/tapid/internal/state"
)

type Config struct {
	Addr   string
	MaxTTL int

	Device state.Device
	Signer keystore.Store

	// AllowedAudiences, when non-empty, restricts /token to mint only for
	// these audience strings. Empty = allow any. v0.4 hardening.
	AllowedAudiences []string

	// RateLimitPerSec caps total /token mints across the daemon. 0 = unlimited.
	RateLimitPerSec int
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
	mux.HandleFunc("GET /.well-known/openid-configuration", hostGuard(handleDiscovery(cfg)))
	mux.HandleFunc("GET /jwks.json", hostGuard(handleJWKS(cfg)))
	mux.HandleFunc("POST /token", hostGuard(originGuard(rateLimited(cfg, handleToken(cfg)))))

	srv := &http.Server{
		Addr:              cfg.Addr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}
	log.Printf("tapid listening on http://%s (issuer=%s tier=%s aud-allow=%v rate=%d/s)",
		cfg.Addr, cfg.Device.IssuerURL, cfg.Device.KeyTier,
		cfg.AllowedAudiences, cfg.RateLimitPerSec)
	return srv.ListenAndServe()
}

// hostGuard rejects requests whose Host header isn't a loopback name.
// Defends against DNS rebinding: browsers always send the original hostname
// (the attacker's domain) in Host, so a rebound 127.0.0.1 connection from
// evil.com still has Host: evil.com and gets blocked.
func hostGuard(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		h := strings.ToLower(r.Host)
		// Strip port for the comparison so 127.0.0.1:53682 and 127.0.0.1 both pass.
		hostOnly := h
		if i := strings.LastIndex(h, ":"); i >= 0 {
			hostOnly = h[:i]
		}
		switch hostOnly {
		case "127.0.0.1", "localhost", "[::1]", "::1":
			next(w, r)
		default:
			writeJSON(w, http.StatusForbidden, map[string]string{
				"error": "host_not_allowed",
				"got":   r.Host,
			})
		}
	}
}

// originGuard rejects any request that carries an Origin header. Browsers
// send Origin on cross-origin requests (and on POSTs in many cases);
// non-browser clients (curl, fetch from Node, requests in Python, Go's
// http.Client) don't. So Origin presence is a strong "this came from a
// browser" signal — and we don't want browsers minting.
func originGuard(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if origin := r.Header.Get("Origin"); origin != "" && origin != "null" {
			writeJSON(w, http.StatusForbidden, map[string]string{
				"error":  "browser_origin_not_allowed",
				"origin": origin,
			})
			return
		}
		next(w, r)
	}
}

// rateLimited applies a global token-bucket cap on /token. Simple
// implementation — refills RateLimitPerSec tokens per second up to a burst
// of RateLimitPerSec*2.
func rateLimited(cfg Config, next http.HandlerFunc) http.HandlerFunc {
	if cfg.RateLimitPerSec <= 0 {
		return next
	}
	rl := newBucket(cfg.RateLimitPerSec)
	return func(w http.ResponseWriter, r *http.Request) {
		if !rl.take() {
			writeJSON(w, http.StatusTooManyRequests, map[string]string{
				"error": "rate_limited",
			})
			return
		}
		next(w, r)
	}
}

type bucket struct {
	mu       sync.Mutex
	cap      float64
	tokens   float64
	lastFill time.Time
	rate     float64
}

func newBucket(perSec int) *bucket {
	return &bucket{
		cap:      float64(perSec * 2),
		tokens:   float64(perSec * 2),
		rate:     float64(perSec),
		lastFill: time.Now(),
	}
}

func (b *bucket) take() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	now := time.Now()
	elapsed := now.Sub(b.lastFill).Seconds()
	b.tokens += elapsed * b.rate
	if b.tokens > b.cap {
		b.tokens = b.cap
	}
	b.lastFill = now
	if b.tokens < 1 {
		return false
	}
	b.tokens -= 1
	return true
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
	allowed := make(map[string]struct{}, len(cfg.AllowedAudiences))
	for _, a := range cfg.AllowedAudiences {
		allowed[a] = struct{}{}
	}

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
		if len(allowed) > 0 {
			if _, ok := allowed[audience]; !ok {
				writeJSON(w, http.StatusForbidden, map[string]string{
					"error":    "audience_not_allowed",
					"audience": audience,
				})
				return
			}
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
			auditLog(cfg, "mint_failed", audience, ttl, jti, err.Error())
			writeJSON(w, http.StatusInternalServerError, errResp("sign_failed"))
			return
		}
		auditLog(cfg, "mint", audience, ttl, jti, "")
		writeJSON(w, http.StatusOK, tokenResponse{
			AccessToken: tok,
			TokenType:   "Bearer",
			ExpiresIn:   ttl,
		})
	}
}

// auditLog emits a single JSON line to stdout per request decision. Pipe to
// journalctl / Event Viewer / Datadog. Never includes the JWT itself.
func auditLog(cfg Config, event, audience string, ttl int, jti, errMsg string) {
	rec := map[string]any{
		"ts":        time.Now().UTC().Format(time.RFC3339),
		"event":     event,
		"audience":  audience,
		"ttl":       ttl,
		"jti":       jti,
		"sub":       "device:" + cfg.Device.DeviceID,
		"device_id": cfg.Device.DeviceID,
		"key_tier":  cfg.Device.KeyTier,
	}
	if errMsg != "" {
		rec["error"] = errMsg
	}
	if b, err := json.Marshal(rec); err == nil {
		log.Println("audit", string(b))
	}
}

func errResp(code string) map[string]string { return map[string]string{"error": code} }

func writeJSON(w http.ResponseWriter, code int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(body)
}
