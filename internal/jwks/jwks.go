// Package jwks builds the discovery document and JWKS for publishing.
package jwks

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/base64"
	"fmt"
)

// DiscoveryDoc is the OIDC discovery payload.
type DiscoveryDoc struct {
	Issuer                           string   `json:"issuer"`
	JWKSURI                          string   `json:"jwks_uri"`
	IDTokenSigningAlgValuesSupported []string `json:"id_token_signing_alg_values_supported"`
	ResponseTypesSupported           []string `json:"response_types_supported"`
	SubjectTypesSupported            []string `json:"subject_types_supported"`
}

// Discovery returns the discovery doc for an issuer URL with the default
// jwks_uri (<issuer>/jwks.json) and ES256 alg.
func Discovery(issuerURL string) DiscoveryDoc {
	return DiscoveryDoc{
		Issuer:                           issuerURL,
		JWKSURI:                          issuerURL + "/jwks.json",
		IDTokenSigningAlgValuesSupported: []string{"ES256"},
		ResponseTypesSupported:           []string{"id_token"},
		SubjectTypesSupported:            []string{"public"},
	}
}

// WithJWKS overrides the jwks_uri (used by gist publish where JWKS is a
// sibling file URL, not a child path).
func (d DiscoveryDoc) WithJWKS(jwksURL string) DiscoveryDoc {
	d.JWKSURI = jwksURL
	return d
}

// WithAlg overrides the supported alg list.
func (d DiscoveryDoc) WithAlg(alg string) DiscoveryDoc {
	d.IDTokenSigningAlgValuesSupported = []string{alg}
	return d
}

// JWK is a single key entry. Fields used depend on kty:
//   - EC : Crv ("P-256"), X, Y
//   - OKP: Crv ("Ed25519"), X       (legacy, unused in v0.2.1+)
type JWK struct {
	Kty string `json:"kty"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	Y   string `json:"y,omitempty"`
	Use string `json:"use"`
	Kid string `json:"kid"`
	Alg string `json:"alg"`
}

// Set is the JWKS envelope.
type Set struct {
	Keys []JWK `json:"keys"`
}

// FromPublicKey builds a JWKS from any supported public key type.
func FromPublicKey(pub crypto.PublicKey, kid string) (Set, error) {
	switch p := pub.(type) {
	case *ecdsa.PublicKey:
		if p.Curve != elliptic.P256() {
			return Set{}, fmt.Errorf("jwks: ecdsa key must be on P-256, got %s", p.Curve.Params().Name)
		}
		x, y, err := pointBytes(p)
		if err != nil {
			return Set{}, err
		}
		return Set{Keys: []JWK{{
			Kty: "EC",
			Crv: "P-256",
			X:   base64.RawURLEncoding.EncodeToString(x),
			Y:   base64.RawURLEncoding.EncodeToString(y),
			Use: "sig",
			Kid: kid,
			Alg: "ES256",
		}}}, nil
	default:
		return Set{}, fmt.Errorf("jwks: unsupported public key type %T", pub)
	}
}

// pointBytes returns the X and Y coordinates of an ECDSA P-256 public key as
// fixed-width 32-byte big-endian byte slices. Goes via crypto/ecdh to avoid
// the deprecated ecdsa.PublicKey field accessors; the conversion preserves
// the same point.
func pointBytes(pub *ecdsa.PublicKey) ([]byte, []byte, error) {
	ecdhPub, err := pub.ECDH()
	if err != nil {
		return nil, nil, fmt.Errorf("jwks: ecdsa→ecdh: %w", err)
	}
	raw := ecdhPub.Bytes() // SEC1 uncompressed: 0x04 || X(32) || Y(32) for P-256
	if len(raw) != 65 || raw[0] != 0x04 {
		return nil, nil, fmt.Errorf("jwks: unexpected point encoding (len=%d, prefix=%x)", len(raw), raw[0])
	}
	return raw[1:33], raw[33:65], nil
}
