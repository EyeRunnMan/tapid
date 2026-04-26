package keystore

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"os"

	"golang.org/x/crypto/scrypt"
)

// SealSecret encrypts arbitrary plaintext under passphrase using the same
// scrypt+AES-GCM construction as the device key (see passphrase.go), and writes
// it to path with 0600. Used for the GitHub OAuth token at ~/.tapid/github.enc.
//
// File layout matches passphrase.go (magic "TPKE" + version 1 + KDF params +
// salt + nonce + ciphertext) so the same code path verifies integrity.
func SealSecret(path string, plaintext, passphrase []byte) error {
	if len(passphrase) < 8 {
		return errors.New("keystore: passphrase must be ≥8 bytes")
	}

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

	out := make([]byte, 0, len(header)+len(ct))
	out = append(out, header...)
	out = append(out, ct...)

	return writeFile0600(path, out)
}

// OpenSecret reverses SealSecret. Returns the plaintext.
func OpenSecret(path string, passphrase []byte) ([]byte, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("keystore: read: %w", err)
	}
	if len(raw) < headerLen {
		return nil, errors.New("keystore: sealed file truncated")
	}

	header := raw[:headerLen]
	if string(header[:4]) != pphMagic {
		return nil, errors.New("keystore: bad magic")
	}
	if header[4] != pphVersion {
		return nil, fmt.Errorf("keystore: unsupported version %d", header[4])
	}

	N := int(uint32FromBE(header[6:10]))
	r := int(uint32FromBE(header[10:14]))
	p := int(uint32FromBE(header[14:18]))
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

func uint32FromBE(b []byte) uint32 {
	return uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
}
