package keystore

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"golang.org/x/crypto/scrypt"
)

// Sealed key file layout (binary):
//
//   offset  size  field
//   ------  ----  -------------------------------------------
//   0       4     magic "TPKE"  (tapid passphrase key envelope)
//   4       1     version (currently 1)
//   5       1     reserved (0)
//   6       4     scrypt N (uint32 BE) — log2 cost factor stored as exponent
//   10      4     scrypt r (uint32 BE)
//   14      4     scrypt p (uint32 BE)
//   18      16    salt
//   34      12    AES-GCM nonce
//   46      ...   ciphertext (32-byte ed25519 seed) || GCM tag
//
// Everything after the magic is authenticated by GCM (file header used as AAD).

const (
	pphMagic   = "TPKE"
	pphVersion = 1

	scryptN = 1 << 16 // 65536
	scryptR = 8
	scryptP = 1
	keyLen  = 32

	saltLen  = 16
	nonceLen = 12
	headerLen = 4 + 1 + 1 + 4 + 4 + 4 + saltLen + nonceLen // 46
)

// PassphraseStore is a tier-4 keystore backed by a scrypt+AES-GCM file.
type PassphraseStore struct {
	priv ed25519.PrivateKey
	pub  ed25519.PublicKey
}

func (s *PassphraseStore) Tier() Tier               { return TierPassphrase }
func (s *PassphraseStore) PublicKey() ed25519.PublicKey { return s.pub }

func (s *PassphraseStore) Sign(msg []byte) ([]byte, error) {
	if len(s.priv) == 0 {
		return nil, errors.New("keystore: not initialized")
	}
	return ed25519.Sign(s.priv, msg), nil
}

// GeneratePassphrase creates a fresh Ed25519 keypair, encrypts the seed under
// passphrase via scrypt+AES-GCM, and writes the sealed file at path.
// Returns the resulting store ready to use.
func GeneratePassphrase(path string, passphrase []byte) (*PassphraseStore, error) {
	if len(passphrase) < 8 {
		return nil, errors.New("keystore: passphrase must be ≥8 bytes")
	}

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("keystore: generate ed25519: %w", err)
	}
	seed := priv.Seed() // 32 bytes; deterministic regen via NewKeyFromSeed

	if err := writeSealed(path, seed, passphrase); err != nil {
		return nil, err
	}
	return &PassphraseStore{priv: priv, pub: pub}, nil
}

// OpenPassphrase decrypts the sealed file at path and returns the store.
func OpenPassphrase(path string, passphrase []byte) (*PassphraseStore, error) {
	seed, err := readSealed(path, passphrase)
	if err != nil {
		return nil, err
	}
	priv := ed25519.NewKeyFromSeed(seed)
	return &PassphraseStore{priv: priv, pub: priv.Public().(ed25519.PublicKey)}, nil
}

func writeSealed(path string, seed, passphrase []byte) error {
	salt := make([]byte, saltLen)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return fmt.Errorf("keystore: read salt: %w", err)
	}
	nonce := make([]byte, nonceLen)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return fmt.Errorf("keystore: read nonce: %w", err)
	}

	dk, err := scrypt.Key(passphrase, salt, scryptN, scryptR, scryptP, keyLen)
	if err != nil {
		return fmt.Errorf("keystore: scrypt: %w", err)
	}

	header := buildHeader(salt, nonce)

	block, err := aes.NewCipher(dk)
	if err != nil {
		return fmt.Errorf("keystore: aes: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return fmt.Errorf("keystore: gcm: %w", err)
	}
	ct := aead.Seal(nil, nonce, seed, header)

	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("keystore: mkdir: %w", err)
	}

	out := make([]byte, 0, len(header)+len(ct))
	out = append(out, header...)
	out = append(out, ct...)

	if err := writeFile0600(path, out); err != nil {
		return fmt.Errorf("keystore: write: %w", err)
	}
	return nil
}

func readSealed(path string, passphrase []byte) ([]byte, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("keystore: read: %w", err)
	}
	if len(raw) < headerLen {
		return nil, errors.New("keystore: sealed file truncated")
	}

	header := raw[:headerLen]
	if string(header[:4]) != pphMagic {
		return nil, errors.New("keystore: bad magic (not a tapid sealed file)")
	}
	if header[4] != pphVersion {
		return nil, fmt.Errorf("keystore: unsupported version %d", header[4])
	}

	N := int(binary.BigEndian.Uint32(header[6:10]))
	r := int(binary.BigEndian.Uint32(header[10:14]))
	p := int(binary.BigEndian.Uint32(header[14:18]))
	salt := header[18 : 18+saltLen]
	nonce := header[18+saltLen : 18+saltLen+nonceLen]
	ct := raw[headerLen:]

	dk, err := scrypt.Key(passphrase, salt, N, r, p, keyLen)
	if err != nil {
		return nil, fmt.Errorf("keystore: scrypt: %w", err)
	}
	block, err := aes.NewCipher(dk)
	if err != nil {
		return nil, fmt.Errorf("keystore: aes: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("keystore: gcm: %w", err)
	}
	seed, err := aead.Open(nil, nonce, ct, header)
	if err != nil {
		return nil, errors.New("keystore: decrypt failed (wrong passphrase or corrupt file)")
	}
	if len(seed) != ed25519.SeedSize {
		return nil, fmt.Errorf("keystore: unexpected seed length %d", len(seed))
	}
	return seed, nil
}

func buildHeader(salt, nonce []byte) []byte {
	h := make([]byte, headerLen)
	copy(h[:4], pphMagic)
	h[4] = pphVersion
	h[5] = 0
	binary.BigEndian.PutUint32(h[6:10], uint32(scryptN))
	binary.BigEndian.PutUint32(h[10:14], uint32(scryptR))
	binary.BigEndian.PutUint32(h[14:18], uint32(scryptP))
	copy(h[18:18+saltLen], salt)
	copy(h[18+saltLen:18+saltLen+nonceLen], nonce)
	return h
}
