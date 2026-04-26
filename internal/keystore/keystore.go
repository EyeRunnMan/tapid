// Package keystore manages the device signing key across tiered backends.
//
// Tier selection per SPEC §5:
//   1. TPM 2.0 / Apple Secure Enclave  (non-extractable)         [v0.2]
//   2. OS keyring                       (DPAPI / Keychain / DBus) [v0.2]
//   3. KMS-wrapped file                 (AWS / GCP / Azure / age) [v0.2]
//   4. Passphrase-encrypted file        (fallback)                [v0.1 — implemented]
package keystore

import "crypto/ed25519"

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
// per backend (passphrase.go now; tpm.go, keyring.go, kms.go in v0.2).
type Store interface {
	// Tier reports which backend this store uses.
	Tier() Tier
	// PublicKey returns the device's public key for JWKS publishing.
	PublicKey() ed25519.PublicKey
	// Sign signs the given message with the device private key.
	// For tier 1, this calls into hardware; the key bytes never leave silicon.
	Sign(msg []byte) ([]byte, error)
}
