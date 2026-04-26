//go:build !windows

package keystore

import "os"

func writeFile0600(path string, data []byte) error {
	return os.WriteFile(path, data, 0o600)
}
