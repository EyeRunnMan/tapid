// Package cli has tiny cross-platform helpers for the CLI front end.
package cli

import (
	"os/exec"
	"runtime"
)

// OpenBrowser tries to open url in the user's default browser.
// Best-effort; failures are ignored — the URL is also printed to the user.
func OpenBrowser(url string) {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "windows":
		cmd = exec.Command("cmd", "/c", "start", "", url)
	case "darwin":
		cmd = exec.Command("open", url)
	default:
		cmd = exec.Command("xdg-open", url)
	}
	_ = cmd.Start()
}
