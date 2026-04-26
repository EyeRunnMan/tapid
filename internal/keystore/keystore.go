// Package keystore manages the device signing key across tiered backends.
//
// Tier selection per SPEC §5:
//   1. TPM 2.0 / Apple Secure Enclave  (non-extractable)
//   2. OS keyring                       (DPAPI / Keychain / Secret Service)
//   3. KMS-wrapped file                 (AWS / GCP / Azure / age)
//   4. Passphrase-encrypted file        (fallback)
package keystore

import (
	"crypto/ed25519"
	"errors"
)

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
// per backend (tpm.go, keyring.go, kms.go, passphrase.go).
type Store interface {
	// Tier reports which backend this store uses.
	Tier() Tier
	// PublicKey returns the device's public key for JWKS publishing.
	PublicKey() ed25519.PublicKey
	// Sign signs the given message with the device private key.
	// For tier 1, this calls into hardware; the key bytes never leave silicon.
	Sign(msg []byte) ([]byte, error)
}

// Open returns the highest-tier store available, or the requested tier if
// the caller forces one. Returns ErrNoTier if nothing usable exists.
func Open(stateDir string, force Tier) (Store, error) {
	return nil, errors.New("keystore.Open: not implemented")
}

// ErrNoTier is returned when no usable tier was found.
var ErrNoTier = errors.New("no usable key tier available")
