//go:build windows

// Package keystore — TPM 2.0 backend for Windows via TBS (Trusted Boot Services).
//
// Architecture:
//
//   1. CreatePrimary in the storage hierarchy with a fixed ECC SRK template.
//      Same template + same TPM = same primary key bytes (TPM 2.0 spec
//      guarantees deterministic derivation when SeedFromHierarchy is used).
//      → primary handle is recreated on every Open without persisting.
//
//   2. CreateKey under primary produces (private, public) blobs. The private
//      blob is wrapped by the primary's seed and is unloadable on any other
//      machine or any other TPM. We persist both blobs to ~/.tapid/key.tpm.
//
//   3. Load(primary, public, private) → keyHandle, used for Sign().
//
//   4. Sign(): TPM2_Sign with ECDSA scheme, returns (R, S). We encode as the
//      JWS-required raw r||s 64-byte concatenation.
//
// Trust boundary: anyone with your OS user session can ask the TPM to sign
// while the daemon is loaded. The KEY ITSELF cannot leave the chip — disk
// imaging, backup leak, malware exfil all yield nothing.
package keystore

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math/big"
	"os"
	"path/filepath"

	"github.com/google/go-tpm/legacy/tpm2"
	"github.com/google/go-tpm/tpmutil"
)

// File layout for ~/.tapid/key.tpm:
//
//   offset  size  field
//   ------  ----  -------------------------------
//   0       4     magic "TPM2"
//   4       1     version (1)
//   5       3     reserved (zeros)
//   8       4     pub_blob_len (uint32 BE)
//   12      P     pub_blob
//   12+P    4     priv_blob_len (uint32 BE)
//   16+P    Q     priv_blob
const (
	tpmFileMagic   = "TPM2"
	tpmFileVersion = 1
)

// srkTemplate is the deterministic Storage Root Key template. Re-running
// CreatePrimary with this exact template + empty auth always derives the
// same primary key on the same TPM (per TPM 2.0 Part 1 §B.4).
var srkTemplate = tpm2.Public{
	Type:    tpm2.AlgECC,
	NameAlg: tpm2.AlgSHA256,
	Attributes: tpm2.FlagFixedTPM | tpm2.FlagFixedParent | tpm2.FlagSensitiveDataOrigin |
		tpm2.FlagUserWithAuth | tpm2.FlagRestricted | tpm2.FlagDecrypt | tpm2.FlagNoDA,
	ECCParameters: &tpm2.ECCParams{
		Symmetric: &tpm2.SymScheme{
			Alg:     tpm2.AlgAES,
			KeyBits: 128,
			Mode:    tpm2.AlgCFB,
		},
		CurveID: tpm2.CurveNISTP256,
	},
}

// signTemplate is the P-256 ECDSA signing key template. FixedTPM + FixedParent
// mean this key is bound to this TPM and this primary; it cannot be exported.
var signTemplate = tpm2.Public{
	Type:    tpm2.AlgECC,
	NameAlg: tpm2.AlgSHA256,
	Attributes: tpm2.FlagFixedTPM | tpm2.FlagFixedParent | tpm2.FlagSensitiveDataOrigin |
		tpm2.FlagUserWithAuth | tpm2.FlagSign | tpm2.FlagNoDA,
	ECCParameters: &tpm2.ECCParams{
		Sign: &tpm2.SigScheme{
			Alg:  tpm2.AlgECDSA,
			Hash: tpm2.AlgSHA256,
		},
		CurveID: tpm2.CurveNISTP256,
	},
}

// TPMStore is a tier-1 keystore backed by the system TPM.
//
// Lifecycle:
//   - Open holds the TBS handle, primary handle, and loaded key handle for
//     the duration of the daemon. Close() flushes both handles + closes TBS.
type TPMStore struct {
	rwc       io.ReadWriteCloser
	primary   tpmutil.Handle
	key       tpmutil.Handle
	pub       *ecdsa.PublicKey
	pubBlob   []byte // for thumbprinting / device_id derivation
}

func (s *TPMStore) Tier() Tier                   { return TierTPM }
func (s *TPMStore) Alg() string                  { return "ES256" }
func (s *TPMStore) PublicKey() crypto.PublicKey  { return s.pub }
func (s *TPMStore) PublicKeyBlob() []byte        { return s.pubBlob }

// Sign hashes msg with SHA-256, signs via TPM2_Sign, returns r||s 64 bytes.
func (s *TPMStore) Sign(msg []byte) ([]byte, error) {
	if s.rwc == nil {
		return nil, errors.New("keystore: tpm not open")
	}
	hash := sha256.Sum256(msg)
	sig, err := tpm2.Sign(s.rwc, s.key, "", hash[:], nil, nil)
	if err != nil {
		return nil, fmt.Errorf("keystore: tpm sign: %w", err)
	}
	if sig.ECC == nil {
		return nil, errors.New("keystore: tpm sign returned non-ECC signature")
	}
	out := make([]byte, 64)
	rBytes := sig.ECC.R.Bytes()
	sBytes := sig.ECC.S.Bytes()
	copy(out[32-len(rBytes):32], rBytes)
	copy(out[64-len(sBytes):64], sBytes)
	return out, nil
}

// Close flushes the loaded handles and closes the TBS connection.
func (s *TPMStore) Close() error {
	var firstErr error
	if s.key != 0 {
		if err := tpm2.FlushContext(s.rwc, s.key); err != nil {
			firstErr = err
		}
		s.key = 0
	}
	if s.primary != 0 {
		if err := tpm2.FlushContext(s.rwc, s.primary); err != nil && firstErr == nil {
			firstErr = err
		}
		s.primary = 0
	}
	if s.rwc != nil {
		if err := s.rwc.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
		s.rwc = nil
	}
	return firstErr
}

// ProbeTPM returns nil if the system TPM is reachable through TBS.
// Used by detectTier(); doesn't create or modify any state.
func ProbeTPM() error {
	rwc, err := tpm2.OpenTPM()
	if err != nil {
		return err
	}
	return rwc.Close()
}

// GenerateTPM creates a new signing key under the deterministic primary,
// writes the wrapped blobs to path, and returns the loaded store.
func GenerateTPM(path string) (*TPMStore, error) {
	rwc, err := tpm2.OpenTPM()
	if err != nil {
		return nil, fmt.Errorf("keystore: open tpm: %w", err)
	}
	closeOnErr := rwc
	defer func() {
		if closeOnErr != nil {
			closeOnErr.Close()
		}
	}()

	primary, _, err := tpm2.CreatePrimary(rwc, tpm2.HandleOwner, tpm2.PCRSelection{}, "", "", srkTemplate)
	if err != nil {
		return nil, fmt.Errorf("keystore: create primary: %w", err)
	}
	flushPrimaryOnErr := primary
	defer func() {
		if flushPrimaryOnErr != 0 {
			tpm2.FlushContext(rwc, flushPrimaryOnErr)
		}
	}()

	priv, pub, _, _, _, err := tpm2.CreateKey(rwc, primary, tpm2.PCRSelection{}, "", "", signTemplate)
	if err != nil {
		return nil, fmt.Errorf("keystore: create key: %w", err)
	}

	if err := writeTPMFile(path, pub, priv); err != nil {
		return nil, err
	}

	keyHandle, _, err := tpm2.Load(rwc, primary, "", pub, priv)
	if err != nil {
		return nil, fmt.Errorf("keystore: load key: %w", err)
	}
	ecPub, err := decodeECCPublic(pub)
	if err != nil {
		tpm2.FlushContext(rwc, keyHandle)
		return nil, err
	}

	flushPrimaryOnErr = 0 // store keeps it
	closeOnErr = nil
	return &TPMStore{
		rwc:     rwc,
		primary: primary,
		key:     keyHandle,
		pub:     ecPub,
		pubBlob: pub,
	}, nil
}

// OpenTPM re-derives the primary, loads the wrapped blob from path, and
// returns the ready-to-sign store.
func OpenTPM(path string) (*TPMStore, error) {
	pub, priv, err := readTPMFile(path)
	if err != nil {
		return nil, err
	}

	rwc, err := tpm2.OpenTPM()
	if err != nil {
		return nil, fmt.Errorf("keystore: open tpm: %w", err)
	}
	closeOnErr := rwc
	defer func() {
		if closeOnErr != nil {
			closeOnErr.Close()
		}
	}()

	primary, _, err := tpm2.CreatePrimary(rwc, tpm2.HandleOwner, tpm2.PCRSelection{}, "", "", srkTemplate)
	if err != nil {
		return nil, fmt.Errorf("keystore: create primary: %w", err)
	}
	flushPrimaryOnErr := primary
	defer func() {
		if flushPrimaryOnErr != 0 {
			tpm2.FlushContext(rwc, flushPrimaryOnErr)
		}
	}()

	keyHandle, _, err := tpm2.Load(rwc, primary, "", pub, priv)
	if err != nil {
		return nil, fmt.Errorf("keystore: load key (was the TPM cleared since init?): %w", err)
	}
	ecPub, err := decodeECCPublic(pub)
	if err != nil {
		tpm2.FlushContext(rwc, keyHandle)
		return nil, err
	}

	flushPrimaryOnErr = 0
	closeOnErr = nil
	return &TPMStore{
		rwc:     rwc,
		primary: primary,
		key:     keyHandle,
		pub:     ecPub,
		pubBlob: pub,
	}, nil
}

func decodeECCPublic(blob []byte) (*ecdsa.PublicKey, error) {
	pub, err := tpm2.DecodePublic(blob)
	if err != nil {
		return nil, fmt.Errorf("keystore: decode tpm public: %w", err)
	}
	if pub.Type != tpm2.AlgECC || pub.ECCParameters == nil {
		return nil, errors.New("keystore: tpm public is not ECC")
	}
	if pub.ECCParameters.CurveID != tpm2.CurveNISTP256 {
		return nil, fmt.Errorf("keystore: tpm public is not P-256 (curve=%v)", pub.ECCParameters.CurveID)
	}
	return &ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X:     new(big.Int).SetBytes(pub.ECCParameters.Point.XRaw),
		Y:     new(big.Int).SetBytes(pub.ECCParameters.Point.YRaw),
	}, nil
}

func writeTPMFile(path string, pub, priv []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("keystore: mkdir: %w", err)
	}

	out := make([]byte, 0, 8+4+len(pub)+4+len(priv))
	out = append(out, []byte(tpmFileMagic)...)
	out = append(out, tpmFileVersion, 0, 0, 0)
	out = appendU32(out, uint32(len(pub)))
	out = append(out, pub...)
	out = appendU32(out, uint32(len(priv)))
	out = append(out, priv...)
	return writeFile0600(path, out)
}

func readTPMFile(path string) (pub, priv []byte, err error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, fmt.Errorf("keystore: read tpm file: %w", err)
	}
	if len(raw) < 12 {
		return nil, nil, errors.New("keystore: tpm file truncated")
	}
	if string(raw[:4]) != tpmFileMagic {
		return nil, nil, errors.New("keystore: tpm file bad magic")
	}
	if raw[4] != tpmFileVersion {
		return nil, nil, fmt.Errorf("keystore: unsupported tpm file version %d", raw[4])
	}

	pubLen := binary.BigEndian.Uint32(raw[8:12])
	if int(pubLen) > len(raw)-16 {
		return nil, nil, errors.New("keystore: tpm file: pub_blob_len out of range")
	}
	pub = raw[12 : 12+pubLen]
	rest := raw[12+pubLen:]
	if len(rest) < 4 {
		return nil, nil, errors.New("keystore: tpm file: missing priv length")
	}
	privLen := binary.BigEndian.Uint32(rest[:4])
	if int(privLen) > len(rest)-4 {
		return nil, nil, errors.New("keystore: tpm file: priv_blob_len out of range")
	}
	priv = rest[4 : 4+privLen]
	return pub, priv, nil
}

func appendU32(b []byte, v uint32) []byte {
	var buf [4]byte
	binary.BigEndian.PutUint32(buf[:], v)
	return append(b, buf[:]...)
}
