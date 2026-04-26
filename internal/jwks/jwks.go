// Package jwks builds the discovery document and JWKS for publishing.
package jwks

import (
	"crypto/ed25519"
	"encoding/base64"
)

// DiscoveryDoc is the OIDC discovery payload.
type DiscoveryDoc struct {
	Issuer                            string   `json:"issuer"`
	JWKSURI                           string   `json:"jwks_uri"`
	IDTokenSigningAlgValuesSupported  []string `json:"id_token_signing_alg_values_supported"`
	ResponseTypesSupported            []string `json:"response_types_supported"`
	SubjectTypesSupported             []string `json:"subject_types_supported"`
}

// Discovery returns the discovery doc for an issuer URL.
func Discovery(issuerURL string) DiscoveryDoc {
	return DiscoveryDoc{
		Issuer:                           issuerURL,
		JWKSURI:                          issuerURL + "/jwks.json",
		IDTokenSigningAlgValuesSupported: []string{"EdDSA"},
		ResponseTypesSupported:           []string{"id_token"},
		SubjectTypesSupported:            []string{"public"},
	}
}

// JWK is a single key entry.
type JWK struct {
	Kty string `json:"kty"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	Use string `json:"use"`
	Kid string `json:"kid"`
	Alg string `json:"alg"`
}

// Set is the JWKS envelope.
type Set struct {
	Keys []JWK `json:"keys"`
}

// FromEd25519 builds a JWKS from an Ed25519 public key with the given kid.
func FromEd25519(pub ed25519.PublicKey, kid string) Set {
	return Set{
		Keys: []JWK{{
			Kty: "OKP",
			Crv: "Ed25519",
			X:   base64.RawURLEncoding.EncodeToString(pub),
			Use: "sig",
			Kid: kid,
			Alg: "EdDSA",
		}},
	}
}
