package keystore

import (
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
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
//   4       1     version (currently 2)
//   5       1     reserved (0)
//   6       4     scrypt N (uint32 BE)
//   10      4     scrypt r (uint32 BE)
//   14      4     scrypt p (uint32 BE)
//   18      16    salt
//   34      12    AES-GCM nonce
//   46      ...   ciphertext (PKCS8-encoded ECDSA P-256 private key) || GCM tag
//
// Header (everything before ciphertext) is authenticated by GCM as AAD.

const (
	pphMagic   = "TPKE"
	pphVersion = 2

	scryptN = 1 << 16 // 65536
	scryptR = 8
	scryptP = 1
	keyLen  = 32

	saltLen   = 16
	nonceLen  = 12
	headerLen = 4 + 1 + 1 + 4 + 4 + 4 + saltLen + nonceLen // 46
)

// PassphraseStore is a tier-4 keystore backed by scrypt+AES-GCM around an
// ECDSA P-256 private key. Alg = ES256.
type PassphraseStore struct {
	priv *ecdsa.PrivateKey
}

func (s *PassphraseStore) Tier() Tier                 { return TierPassphrase }
func (s *PassphraseStore) Alg() string                { return "ES256" }
func (s *PassphraseStore) PublicKey() crypto.PublicKey { return &s.priv.PublicKey }

// Sign hashes msg with SHA-256, signs with ECDSA P-256, and returns the
// JWS-compact signature: r||s as fixed-width 32+32 = 64 bytes (NOT ASN.1 DER),
// per RFC 7515 §A.3.
func (s *PassphraseStore) Sign(msg []byte) ([]byte, error) {
	if s.priv == nil {
		return nil, errors.New("keystore: not initialized")
	}
	hash := sha256.Sum256(msg)
	r, ss, err := ecdsa.Sign(rand.Reader, s.priv, hash[:])
	if err != nil {
		return nil, fmt.Errorf("keystore: ecdsa sign: %w", err)
	}
	out := make([]byte, 64)
	rBytes := r.Bytes()
	sBytes := ss.Bytes()
	copy(out[32-len(rBytes):32], rBytes)
	copy(out[64-len(sBytes):64], sBytes)
	return out, nil
}

// GeneratePassphrase creates a fresh P-256 keypair, marshals it to PKCS8,
// encrypts under passphrase, and writes the sealed file at path.
func GeneratePassphrase(path string, passphrase []byte) (*PassphraseStore, error) {
	if len(passphrase) < 8 {
		return nil, errors.New("keystore: passphrase must be ≥8 bytes")
	}
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("keystore: generate p256: %w", err)
	}
	blob, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, fmt.Errorf("keystore: pkcs8 marshal: %w", err)
	}
	if err := writeSealed(path, blob, passphrase); err != nil {
		return nil, err
	}
	return &PassphraseStore{priv: priv}, nil
}

// OpenPassphrase decrypts the sealed file and parses the PKCS8 P-256 key.
func OpenPassphrase(path string, passphrase []byte) (*PassphraseStore, error) {
	blob, err := readSealed(path, passphrase)
	if err != nil {
		return nil, err
	}
	parsed, err := x509.ParsePKCS8PrivateKey(blob)
	if err != nil {
		return nil, fmt.Errorf("keystore: pkcs8 parse: %w", err)
	}
	priv, ok := parsed.(*ecdsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("keystore: unexpected key type %T (want *ecdsa.PrivateKey)", parsed)
	}
	if priv.Curve != elliptic.P256() {
		return nil, errors.New("keystore: key is not on P-256")
	}
	return &PassphraseStore{priv: priv}, nil
}

func writeSealed(path string, plaintext, passphrase []byte) error {
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
	ct := aead.Seal(nil, nonce, plaintext, header)

	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("keystore: mkdir: %w", err)
	}

	out := make([]byte, 0, len(header)+len(ct))
	out = append(out, header...)
	out = append(out, ct...)
	return writeFile0600(path, out)
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
		return nil, fmt.Errorf("keystore: unsupported version %d (expected %d)", header[4], pphVersion)
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
	pt, err := aead.Open(nil, nonce, ct, header)
	if err != nil {
		return nil, errors.New("keystore: decrypt failed (wrong passphrase or corrupt file)")
	}
	return pt, nil
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
