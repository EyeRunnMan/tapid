// Package jwt is a tiny EdDSA-only JWT signer/verifier.
//
// Hand-rolled (~80 LOC) to avoid pulling a JWT library and its reflection
// surface. Supports exactly one alg: EdDSA (Ed25519). No nbf, no none, no kid
// guessing — the caller passes kid explicitly.
package jwt

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/EyeRunnMan/tapid/internal/keystore"
)

// Header is the JWT header. We always emit alg=EdDSA, typ=JWT.
type Header struct {
	Alg string `json:"alg"`
	Typ string `json:"typ"`
	Kid string `json:"kid"`
}

// Sign produces a compact JWS: base64url(header) "." base64url(claims) "." base64url(sig).
//
// claims must be a JSON-serializable struct or map. The signer's PublicKey
// is not used here — the caller is responsible for key/kid consistency.
func Sign(claims any, kid string, signer keystore.Store) (string, error) {
	if signer == nil {
		return "", errors.New("jwt: nil signer")
	}
	if kid == "" {
		return "", errors.New("jwt: empty kid")
	}

	hdrJSON, err := json.Marshal(Header{Alg: signer.Alg(), Typ: "JWT", Kid: kid})
	if err != nil {
		return "", fmt.Errorf("jwt: marshal header: %w", err)
	}
	claimsJSON, err := json.Marshal(claims)
	if err != nil {
		return "", fmt.Errorf("jwt: marshal claims: %w", err)
	}

	enc := base64.RawURLEncoding
	signingInput := enc.EncodeToString(hdrJSON) + "." + enc.EncodeToString(claimsJSON)

	sig, err := signer.Sign([]byte(signingInput))
	if err != nil {
		return "", fmt.Errorf("jwt: sign: %w", err)
	}

	return signingInput + "." + enc.EncodeToString(sig), nil
}

// Decode splits a JWT into raw header/claims/sig bytes (base64-decoded).
// Does NOT verify. Useful for tests and `tapid debug`.
func Decode(token string) (header, claims, sig []byte, err error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, nil, nil, errors.New("jwt: not a 3-part token")
	}
	enc := base64.RawURLEncoding
	header, err = enc.DecodeString(parts[0])
	if err != nil {
		return nil, nil, nil, fmt.Errorf("jwt: decode header: %w", err)
	}
	claims, err = enc.DecodeString(parts[1])
	if err != nil {
		return nil, nil, nil, fmt.Errorf("jwt: decode claims: %w", err)
	}
	sig, err = enc.DecodeString(parts[2])
	if err != nil {
		return nil, nil, nil, fmt.Errorf("jwt: decode sig: %w", err)
	}
	return header, claims, sig, nil
}
