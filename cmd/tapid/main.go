package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/EyeRunnMan/tapid/internal/cli"
	"github.com/EyeRunnMan/tapid/internal/github"
	"github.com/EyeRunnMan/tapid/internal/jwks"
	"github.com/EyeRunnMan/tapid/internal/keystore"
	"github.com/EyeRunnMan/tapid/internal/server"
	"github.com/EyeRunnMan/tapid/internal/state"
	"golang.org/x/term"
)

const version = "0.2.0-dev"

const githubScopes = "gist"

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
	case "republish":
		runRepublish(os.Args[2:])
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
  tapid init      [flags]   generate keypair, encrypt, publish JWKS
  tapid serve     [flags]   run the HTTP daemon
  tapid republish [flags]   push current JWKS to the existing gist
  tapid version             print version
  tapid help                this message

Common flags:
  --state-dir <path>          where device key + metadata live (default: ~/.tapid)
  --passphrase-file <path>    read passphrase from file (no TTY prompt)

Init flags:
  --publish=manual|gist       publishing mode (default: manual)
  --issuer-url <url>          (manual mode) fully-qualified issuer URL
  --publish-dir <path>        (manual mode) where to write JWKS + discovery
                              (default: <state-dir>/publish)
  --github-client-id <id>     (gist mode) OAuth App client ID
                              (or env TAPID_GITHUB_CLIENT_ID)

Serve flags:
  --addr <host:port>          bind address (default: 127.0.0.1:53682)
  --max-ttl <seconds>         max JWT lifetime (default: 3600)

Env:
  TAPID_PASSPHRASE            passphrase (overrides file/TTY)
  TAPID_GITHUB_CLIENT_ID      GitHub OAuth App client ID

See SPEC.md for design.
`)
}

// ---- init ------------------------------------------------------------------

func runInit(args []string) {
	fs := flag.NewFlagSet("init", flag.ExitOnError)
	stateDir := fs.String("state-dir", defaultStateDir(), "where device key + metadata live")
	publishMode := fs.String("publish", "manual", "manual|gist")
	issuerURL := fs.String("issuer-url", "", "(manual) fully-qualified issuer URL")
	publishDir := fs.String("publish-dir", "", "(manual) where to write JWKS + discovery")
	clientID := fs.String("github-client-id", os.Getenv("TAPID_GITHUB_CLIENT_ID"), "(gist) OAuth App client ID")
	passFile := fs.String("passphrase-file", "", "read passphrase from file")
	_ = fs.Parse(args)

	if _, err := os.Stat(state.KeyPath(*stateDir)); err == nil {
		log.Fatalf("init: %s already exists; delete to re-init", state.KeyPath(*stateDir))
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
		KeyTier:   keystore.TierPassphrase.String(),
		CreatedAt: time.Now().UTC(),
	}

	store, err := keystore.GeneratePassphrase(state.KeyPath(*stateDir), pass)
	if err != nil {
		log.Fatalf("init: generate key: %v", err)
	}

	switch *publishMode {
	case "manual":
		if *issuerURL == "" {
			log.Fatal("init: --issuer-url is required for manual mode")
		}
		dev.IssuerURL = strings.TrimRight(*issuerURL, "/")
		dev.PublishMode = "manual"
		pub := *publishDir
		if pub == "" {
			pub = filepath.Join(*stateDir, "publish")
		}
		if err := writePublishDir(pub, dev, store); err != nil {
			log.Fatalf("init: publish: %v", err)
		}
		printSummaryManual(dev, *stateDir, pub)

	case "gist":
		if *clientID == "" {
			log.Fatal("init: --github-client-id (or TAPID_GITHUB_CLIENT_ID) required for gist mode")
		}
		if err := initGist(*stateDir, &dev, store, *clientID, pass); err != nil {
			log.Fatalf("init: gist: %v", err)
		}
		printSummaryGist(dev, *stateDir)

	default:
		log.Fatalf("init: unknown --publish mode %q (use manual or gist)", *publishMode)
	}

	if err := dev.Save(*stateDir); err != nil {
		log.Fatalf("init: save device.json: %v", err)
	}
}

// ---- gist init flow --------------------------------------------------------

func initGist(stateDir string, dev *state.Device, store keystore.Store, clientID string, pass []byte) error {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
	defer cancel()

	fmt.Fprintln(os.Stderr, "→ requesting GitHub device code…")
	dc, err := github.StartDeviceFlow(ctx, clientID, githubScopes)
	if err != nil {
		return fmt.Errorf("device-flow start: %w", err)
	}

	fmt.Fprintf(os.Stderr, "\n  Open: %s\n  Code: %s\n  (expires in %d s)\n\n",
		dc.VerificationURI, dc.UserCode, dc.ExpiresIn)
	cli.OpenBrowser(dc.VerificationURI)

	fmt.Fprintln(os.Stderr, "→ waiting for you to approve in the browser…")
	tok, err := github.PollForToken(ctx, clientID, dc)
	if err != nil {
		return fmt.Errorf("device-flow poll: %w", err)
	}
	fmt.Fprintln(os.Stderr, "✓ authorized")

	// Phase 1: create gist with placeholder content (we don't know gist_id yet,
	// so we can't compute the issuer URL). Two filenames are reserved.
	dev.GistFileJWKS = "jwks.json"
	dev.GistFileDiscovery = "openid-configuration"
	dev.PublishMode = "gist"

	placeholder := map[string]string{
		dev.GistFileJWKS:      `{"keys":[]}`,
		dev.GistFileDiscovery: `{"placeholder":true}`,
	}
	desc := fmt.Sprintf("tapid OIDC JWKS for device %s (managed; do not edit)", dev.DeviceID)

	fmt.Fprintln(os.Stderr, "→ creating gist…")
	g, err := github.CreateGist(ctx, tok.AccessToken, desc, placeholder)
	if err != nil {
		return fmt.Errorf("create gist: %w", err)
	}
	dev.GistID = g.ID
	dev.GistOwner = g.Owner.Login
	dev.IssuerURL = github.RawURL(dev.GistOwner, dev.GistID, dev.GistFileDiscovery)

	// Phase 2: update gist with real discovery + jwks pointing at the real
	// raw URLs.
	disc, err := encodeJSON(jwks.Discovery(dev.IssuerURL).WithJWKS(
		github.RawURL(dev.GistOwner, dev.GistID, dev.GistFileJWKS)))
	if err != nil {
		return err
	}
	set, err := encodeJSON(jwks.FromEd25519(store.PublicKey(), dev.Kid))
	if err != nil {
		return err
	}
	fmt.Fprintln(os.Stderr, "→ uploading discovery + JWKS…")
	if _, err := github.UpdateGist(ctx, tok.AccessToken, dev.GistID, map[string]string{
		dev.GistFileDiscovery: disc,
		dev.GistFileJWKS:      set,
	}); err != nil {
		return fmt.Errorf("update gist: %w", err)
	}

	// Persist the OAuth token (encrypted under the same passphrase).
	if err := keystore.SealSecret(state.GitHubTokenPath(stateDir),
		[]byte(tok.AccessToken), pass); err != nil {
		return fmt.Errorf("seal github token: %w", err)
	}

	return nil
}

// ---- republish -------------------------------------------------------------

func runRepublish(args []string) {
	fs := flag.NewFlagSet("republish", flag.ExitOnError)
	stateDir := fs.String("state-dir", defaultStateDir(), "where device key + metadata live")
	passFile := fs.String("passphrase-file", "", "read passphrase from file")
	_ = fs.Parse(args)

	dev, err := state.Load(*stateDir)
	if err != nil {
		log.Fatalf("republish: load device: %v", err)
	}
	if dev.PublishMode != "gist" {
		log.Fatalf("republish: device is in %q mode; only gist mode is republishable", dev.PublishMode)
	}

	pass, err := readPassphrase(*passFile, false)
	if err != nil {
		log.Fatalf("republish: passphrase: %v", err)
	}
	defer zero(pass)

	store, err := keystore.OpenPassphrase(state.KeyPath(*stateDir), pass)
	if err != nil {
		log.Fatalf("republish: open key: %v", err)
	}
	tokenBytes, err := keystore.OpenSecret(state.GitHubTokenPath(*stateDir), pass)
	if err != nil {
		log.Fatalf("republish: open token: %v", err)
	}

	disc, err := encodeJSON(jwks.Discovery(dev.IssuerURL).WithJWKS(
		github.RawURL(dev.GistOwner, dev.GistID, dev.GistFileJWKS)))
	if err != nil {
		log.Fatal(err)
	}
	set, err := encodeJSON(jwks.FromEd25519(store.PublicKey(), dev.Kid))
	if err != nil {
		log.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if _, err := github.UpdateGist(ctx, string(tokenBytes), dev.GistID, map[string]string{
		dev.GistFileDiscovery: disc,
		dev.GistFileJWKS:      set,
	}); err != nil {
		log.Fatalf("republish: %v", err)
	}
	fmt.Println("republished:", dev.IssuerURL)
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

func writePublishDir(dir string, dev state.Device, store keystore.Store) error {
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

func encodeJSON(v any) (string, error) {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return "", err
	}
	return string(b), nil
}

func printSummaryManual(dev state.Device, stateDir, pub string) {
	fmt.Printf("\nDevice initialized (manual publish).\n")
	fmt.Printf("  device_id : %s\n", dev.DeviceID)
	fmt.Printf("  kid       : %s\n", dev.Kid)
	fmt.Printf("  issuer    : %s\n", dev.IssuerURL)
	fmt.Printf("  key tier  : %s\n", dev.KeyTier)
	fmt.Printf("  state dir : %s\n", stateDir)
	fmt.Printf("  publish   : %s\n\n", pub)
	fmt.Printf("Next:\n")
	fmt.Printf("  1. Upload contents of %s to %s/\n", pub, dev.IssuerURL)
	fmt.Printf("  2. Run:  tapid serve\n")
}

func printSummaryGist(dev state.Device, stateDir string) {
	fmt.Printf("\nDevice initialized (gist publish).\n")
	fmt.Printf("  device_id  : %s\n", dev.DeviceID)
	fmt.Printf("  kid        : %s\n", dev.Kid)
	fmt.Printf("  gist owner : %s\n", dev.GistOwner)
	fmt.Printf("  gist id    : %s\n", dev.GistID)
	fmt.Printf("  issuer URL : %s\n", dev.IssuerURL)
	fmt.Printf("  jwks URL   : %s\n",
		github.RawURL(dev.GistOwner, dev.GistID, dev.GistFileJWKS))
	fmt.Printf("  state dir  : %s\n\n", stateDir)
	fmt.Printf("Configure your relying party (Infisical, etc.) with:\n")
	fmt.Printf("  Discovery URL = %s\n", dev.IssuerURL)
	fmt.Printf("  Subject       = device:%s\n\n", dev.DeviceID)
	fmt.Printf("Then:\n")
	fmt.Printf("  tapid serve\n")
}

func defaultStateDir() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ".tapid"
	}
	return filepath.Join(home, ".tapid")
}

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
