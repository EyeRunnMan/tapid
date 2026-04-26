package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/EyeRunnMan/tapid/internal/jwks"
	"github.com/EyeRunnMan/tapid/internal/keystore"
	"github.com/EyeRunnMan/tapid/internal/server"
	"github.com/EyeRunnMan/tapid/internal/state"
	"golang.org/x/term"
)

const version = "0.1.0-dev"

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}

	switch os.Args[1] {
	case "init":
		runInit(os.Args[2:])
	case "serve":
		runServe(os.Args[2:])
	case "version", "-v", "--version":
		fmt.Println("tapid", version)
	case "help", "-h", "--help":
		usage()
	default:
		fmt.Fprintf(os.Stderr, "unknown subcommand: %s\n\n", os.Args[1])
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `tapid — localhost OIDC issuer for laptops and bare VPS

Usage:
  tapid init   [flags]    generate keypair, encrypt, write publish dir
  tapid serve  [flags]    run the HTTP daemon
  tapid version           print version
  tapid help              this message

Common flags:
  --state-dir <path>      where device key + metadata live (default: ~/.tapid)
  --issuer-url <url>      (init) fully-qualified issuer URL where JWKS will be hosted
  --addr <host:port>      (serve) bind address (default: 127.0.0.1:53682)
  --max-ttl <seconds>     (serve) max JWT lifetime (default: 3600)
  --passphrase-file <p>   read passphrase from file (no TTY prompt)
  --publish-dir <path>    (init) where to write jwks.json + .well-known/...
                          (default: <state-dir>/publish)

Env:
  TAPID_PASSPHRASE        passphrase via env (overrides --passphrase-file)

See SPEC.md for design.
`)
}

// ---- init ------------------------------------------------------------------

func runInit(args []string) {
	fs := flag.NewFlagSet("init", flag.ExitOnError)
	stateDir := fs.String("state-dir", defaultStateDir(), "where device key + metadata live")
	issuerURL := fs.String("issuer-url", "", "fully-qualified issuer URL where JWKS will be hosted")
	publishDir := fs.String("publish-dir", "", "where to write JWKS + discovery (default: <state-dir>/publish)")
	passFile := fs.String("passphrase-file", "", "read passphrase from file")
	_ = fs.Parse(args)

	if *issuerURL == "" {
		log.Fatal("--issuer-url is required (e.g. https://idp.example.com/devices/n4xqz1)")
	}
	*issuerURL = strings.TrimRight(*issuerURL, "/")

	if _, err := os.Stat(state.KeyPath(*stateDir)); err == nil {
		log.Fatalf("init: %s already exists; delete it to re-init", state.KeyPath(*stateDir))
	}

	pass, err := readPassphrase(*passFile, true)
	if err != nil {
		log.Fatalf("init: passphrase: %v", err)
	}
	defer zero(pass)

	deviceID, err := state.NewDeviceID()
	if err != nil {
		log.Fatalf("init: device id: %v", err)
	}
	dev := state.Device{
		DeviceID:  deviceID,
		Kid:       state.NewKid(deviceID),
		IssuerURL: *issuerURL,
		KeyTier:   keystore.TierPassphrase.String(),
		CreatedAt: time.Now().UTC(),
	}

	store, err := keystore.GeneratePassphrase(state.KeyPath(*stateDir), pass)
	if err != nil {
		log.Fatalf("init: generate key: %v", err)
	}
	if err := dev.Save(*stateDir); err != nil {
		log.Fatalf("init: save device.json: %v", err)
	}

	pub := *publishDir
	if pub == "" {
		pub = filepath.Join(*stateDir, "publish")
	}
	if err := writePublish(pub, dev, store); err != nil {
		log.Fatalf("init: publish: %v", err)
	}

	fmt.Printf("\nDevice initialized.\n")
	fmt.Printf("  device_id : %s\n", dev.DeviceID)
	fmt.Printf("  kid       : %s\n", dev.Kid)
	fmt.Printf("  issuer    : %s\n", dev.IssuerURL)
	fmt.Printf("  key tier  : %s\n", dev.KeyTier)
	fmt.Printf("  state dir : %s\n", *stateDir)
	fmt.Printf("  publish   : %s\n\n", pub)
	fmt.Printf("Next:\n")
	fmt.Printf("  1. Upload the contents of %s to %s/\n", pub, dev.IssuerURL)
	fmt.Printf("     (so that %s/.well-known/openid-configuration is reachable)\n", dev.IssuerURL)
	fmt.Printf("  2. Run:  tapid serve\n")
}

func writePublish(dir string, dev state.Device, store keystore.Store) error {
	if err := os.MkdirAll(filepath.Join(dir, ".well-known"), 0o755); err != nil {
		return err
	}
	disc := jwks.Discovery(dev.IssuerURL)
	if err := writeJSONFile(filepath.Join(dir, ".well-known", "openid-configuration"), disc); err != nil {
		return err
	}
	set := jwks.FromEd25519(store.PublicKey(), dev.Kid)
	return writeJSONFile(filepath.Join(dir, "jwks.json"), set)
}

func writeJSONFile(path string, v any) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

// ---- serve -----------------------------------------------------------------

func runServe(args []string) {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	addr := fs.String("addr", "127.0.0.1:53682", "bind address")
	stateDir := fs.String("state-dir", defaultStateDir(), "where device key + metadata live")
	maxTTL := fs.Int("max-ttl", 3600, "max JWT lifetime in seconds")
	passFile := fs.String("passphrase-file", "", "read passphrase from file")
	_ = fs.Parse(args)

	dev, err := state.Load(*stateDir)
	if err != nil {
		log.Fatalf("serve: load device: %v (run `tapid init` first)", err)
	}
	pass, err := readPassphrase(*passFile, false)
	if err != nil {
		log.Fatalf("serve: passphrase: %v", err)
	}
	defer zero(pass)

	store, err := keystore.OpenPassphrase(state.KeyPath(*stateDir), pass)
	if err != nil {
		log.Fatalf("serve: open key: %v", err)
	}

	cfg := server.Config{
		Addr:   *addr,
		MaxTTL: *maxTTL,
		Device: dev,
		Signer: store,
	}
	if err := server.Run(cfg); err != nil {
		log.Fatal(err)
	}
}

// ---- helpers ---------------------------------------------------------------

func defaultStateDir() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ".tapid"
	}
	return filepath.Join(home, ".tapid")
}

// readPassphrase pulls a passphrase from (in priority order):
//
//  1. TAPID_PASSPHRASE env var
//  2. --passphrase-file
//  3. interactive TTY prompt
//
// If confirm is true (init), the prompt asks twice and verifies they match.
func readPassphrase(file string, confirm bool) ([]byte, error) {
	if env := os.Getenv("TAPID_PASSPHRASE"); env != "" {
		return []byte(env), nil
	}
	if file != "" {
		data, err := os.ReadFile(file)
		if err != nil {
			return nil, fmt.Errorf("read passphrase file: %w", err)
		}
		return trimNewline(data), nil
	}

	fd := int(os.Stdin.Fd())
	if !term.IsTerminal(fd) {
		return nil, fmt.Errorf("no TTY and no --passphrase-file / TAPID_PASSPHRASE")
	}

	fmt.Fprint(os.Stderr, "Passphrase: ")
	p1, err := term.ReadPassword(fd)
	if err != nil {
		return nil, fmt.Errorf("read passphrase: %w", err)
	}
	fmt.Fprintln(os.Stderr)
	if !confirm {
		return p1, nil
	}
	fmt.Fprint(os.Stderr, "Confirm:    ")
	p2, err := term.ReadPassword(fd)
	if err != nil {
		return nil, fmt.Errorf("read passphrase: %w", err)
	}
	fmt.Fprintln(os.Stderr)
	if string(p1) != string(p2) {
		return nil, fmt.Errorf("passphrases do not match")
	}
	zero(p2)
	return p1, nil
}

func trimNewline(b []byte) []byte {
	for len(b) > 0 && (b[len(b)-1] == '\n' || b[len(b)-1] == '\r') {
		b = b[:len(b)-1]
	}
	return b
}

func zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

