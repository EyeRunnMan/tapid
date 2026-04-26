// Package state holds the device metadata persisted to disk alongside the key.
package state

import (
	"crypto/rand"
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
}

const deviceFile = "device.json"
const keyFile = "key.enc"

// DevicePath returns the device metadata path inside stateDir.
func DevicePath(stateDir string) string { return filepath.Join(stateDir, deviceFile) }

// KeyPath returns the encrypted key path inside stateDir.
func KeyPath(stateDir string) string { return filepath.Join(stateDir, keyFile) }

// NewDeviceID returns a fresh device id: 6 base32-lowercased characters,
// stable across restarts (caller persists). ~30 bits of entropy is enough
// per device in a small org; collisions detected at registration time.
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
	return d, nil
}
