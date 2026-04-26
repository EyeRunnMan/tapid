package server

import (
	"crypto/rand"
	"encoding/base32"
	"os"
	"strings"
)

// newJTI returns a 26-char base32 unique id (sufficient entropy for replay defense
// within the JWT lifetime; relying parties may still track jti if they want stronger).
func newJTI() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	enc := base32.StdEncoding.WithPadding(base32.NoPadding)
	return strings.ToLower(enc.EncodeToString(b[:])), nil
}

func hostnameSafe() string {
	h, err := os.Hostname()
	if err != nil {
		return ""
	}
	return h
}
