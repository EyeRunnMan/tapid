//go:build windows

package keystore

import "os"

// On Windows, POSIX mode bits are advisory; ACL hardening is left to v0.2.
// We still set 0o600 so non-Windows tools see the intent.
func writeFile0600(path string, data []byte) error {
	return os.WriteFile(path, data, 0o600)
}
