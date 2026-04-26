// Package keystore manages the device signing key across tiered backends.
//
// Tier selection per SPEC §5:
//   1. TPM 2.0 / Apple Secure Enclave  (non-extractable)         [v0.3]
//   2. OS keyring                       (DPAPI / Keychain / DBus) [v0.3]
//   3. KMS-wrapped file                 (AWS / GCP / Azure / age) [v0.4]
//   4. Passphrase-encrypted file        (fallback)                [v0.1 — implemented]
//
// Algorithm: ES256 (ECDSA P-256). Chosen because:
//   - Universally supported by OIDC verifiers (Infisical, Vault, AWS STS, GCP WIF).
//   - Same alg required by macOS Secure Enclave (no Ed25519 support).
//   - Same alg supported by all TPM 2.0 chips (Ed25519 only on newer ones).
package keystore

import "crypto"

// Tier identifies which backend holds the active private key.
type Tier int

const (
	TierUnknown    Tier = 0
	TierTPM        Tier = 1
	TierKeyring    Tier = 2
	TierKMS        Tier = 3
	TierPassphrase Tier = 4
)

func (t Tier) String() string {
	switch t {
	case TierTPM:
		return "tpm"
	case TierKeyring:
		return "keyring"
	case TierKMS:
		return "kms"
	case TierPassphrase:
		return "passphrase"
	default:
		return "unknown"
	}
}

// Store is the keystore interface. Implementations live alongside this file
// per backend (passphrase.go now; tpm.go, keyring.go, kms.go in v0.3+).
type Store interface {
	// Tier reports which backend this store uses.
	Tier() Tier
	// Alg returns the JWS algorithm identifier (currently always "ES256").
	Alg() string
	// PublicKey returns the device's public key for JWKS publishing.
	// Type matches the alg: *ecdsa.PublicKey for ES256.
	PublicKey() crypto.PublicKey
	// Sign produces a JWS-format signature over msg. For ES256 this is the
	// raw r||s 64-byte concat (NOT ASN.1 DER), per RFC 7515 §A.3.
	Sign(msg []byte) ([]byte, error)
}
