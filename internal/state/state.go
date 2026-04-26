// Package state holds the device metadata persisted to disk alongside the key.
package state

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Device is the on-disk metadata. JSON-encoded at <state-dir>/device.json.
// All fields are public; this file is not secret (the key file is).
type Device struct {
	DeviceID  string    `json:"device_id"`
	Kid       string    `json:"kid"`
	IssuerURL string    `json:"issuer_url"`
	KeyTier   string    `json:"key_tier"`
	CreatedAt time.Time `json:"created_at"`

	// Publish mode: "manual" (user uploads JWKS), "gist" (GitHub gist; works
	// only with verifiers that accept arbitrary discovery URLs), or "repo"
	// (GitHub public repo + raw URLs; works with strict OIDC verifiers that
	// append /.well-known/openid-configuration). Empty = "manual" for
	// backward compatibility.
	PublishMode string `json:"publish_mode,omitempty"`

	// Populated only when PublishMode == "gist".
	GistID            string `json:"gist_id,omitempty"`
	GistOwner         string `json:"gist_owner,omitempty"`
	GistFileJWKS      string `json:"gist_file_jwks,omitempty"`
	GistFileDiscovery string `json:"gist_file_discovery,omitempty"`

	// Populated only when PublishMode == "repo".
	RepoOwner  string `json:"repo_owner,omitempty"`
	RepoName   string `json:"repo_name,omitempty"`
	RepoBranch string `json:"repo_branch,omitempty"`
}

const (
	deviceFile      = "device.json"
	keyFile         = "key.enc"
	tpmKeyFile      = "key.tpm"
	githubTokenFile = "github.enc"
)

// DevicePath returns the device metadata path inside stateDir.
func DevicePath(stateDir string) string { return filepath.Join(stateDir, deviceFile) }

// KeyPath returns the passphrase-encrypted key path inside stateDir.
func KeyPath(stateDir string) string { return filepath.Join(stateDir, keyFile) }

// TPMKeyPath returns the TPM-wrapped key path inside stateDir.
func TPMKeyPath(stateDir string) string { return filepath.Join(stateDir, tpmKeyFile) }

// GitHubTokenPath returns the encrypted GitHub OAuth token path inside stateDir.
func GitHubTokenPath(stateDir string) string { return filepath.Join(stateDir, githubTokenFile) }

// NewDeviceID returns a fresh random device id: 6 base32-lowercased characters.
// Used for tier-4 (passphrase) where there's no stable hardware identity.
func NewDeviceID() (string, error) {
	var b [4]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	enc := base32.StdEncoding.WithPadding(base32.NoPadding)
	s := strings.ToLower(enc.EncodeToString(b[:]))
	if len(s) < 6 {
		return s, nil
	}
	return s[:6], nil
}

// DeviceIDFromPubBlob derives a stable device id from a public key blob.
// Same TPM + same key = same device_id across reinits. Different TPM or
// rotated key = different id.
//
// id = first 6 chars of base32-lowercased SHA-256 of the public blob.
func DeviceIDFromPubBlob(pub []byte) string {
	sum := sha256.Sum256(pub)
	enc := base32.StdEncoding.WithPadding(base32.NoPadding)
	return strings.ToLower(enc.EncodeToString(sum[:]))[:6]
}

// NewKid returns a kid string. We bind kid to device_id for now: "k-<deviceID>".
// Rotating keys for a device gets a numeric suffix in v0.2.
func NewKid(deviceID string) string {
	return "k-" + deviceID
}

// Save writes Device to disk at <state-dir>/device.json with 0o600.
func (d Device) Save(stateDir string) error {
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		return fmt.Errorf("state: mkdir: %w", err)
	}
	data, err := json.MarshalIndent(d, "", "  ")
	if err != nil {
		return fmt.Errorf("state: marshal: %w", err)
	}
	return os.WriteFile(DevicePath(stateDir), data, 0o600)
}

// Load reads Device from <state-dir>/device.json.
func Load(stateDir string) (Device, error) {
	var d Device
	raw, err := os.ReadFile(DevicePath(stateDir))
	if err != nil {
		return d, fmt.Errorf("state: read: %w", err)
	}
	if err := json.Unmarshal(raw, &d); err != nil {
		return d, fmt.Errorf("state: unmarshal: %w", err)
	}
	if d.DeviceID == "" || d.Kid == "" || d.IssuerURL == "" {
		return d, errors.New("state: device.json missing required fields")
	}
	if d.PublishMode == "" {
		d.PublishMode = "manual"
	}
	return d, nil
}
