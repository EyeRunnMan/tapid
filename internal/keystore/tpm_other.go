//go:build !windows

package keystore

import (
	"crypto"
	"errors"
)

// ErrTPMNotSupported is returned by TPM functions on non-Windows builds.
// v0.3 ships Windows TBS only; Linux TPM 2.0 and macOS Secure Enclave land
// later (Linux is straightforward, macOS needs cgo).
var ErrTPMNotSupported = errors.New("keystore: TPM tier not supported on this OS (v0.3 = Windows only)")

// TPMStore satisfies the Store interface but every method errors.
type TPMStore struct{}

func (s *TPMStore) Tier() Tier                      { return TierTPM }
func (s *TPMStore) Alg() string                     { return "ES256" }
func (s *TPMStore) PublicKey() crypto.PublicKey     { return nil }
func (s *TPMStore) PublicKeyBlob() []byte           { return nil }
func (s *TPMStore) Sign(msg []byte) ([]byte, error) { return nil, ErrTPMNotSupported }
func (s *TPMStore) Close() error                    { return nil }

func ProbeTPM() error                            { return ErrTPMNotSupported }
func GenerateTPM(path string) (*TPMStore, error) { return nil, ErrTPMNotSupported }
func OpenTPM(path string) (*TPMStore, error)     { return nil, ErrTPMNotSupported }
