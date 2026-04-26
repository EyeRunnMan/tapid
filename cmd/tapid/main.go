package main

import (
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/EyeRunnMan/tapid/internal/server"
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
  tapid init [flags]      generate keypair, register, prepare JWKS
  tapid serve [flags]     run the HTTP daemon
  tapid version           print version
  tapid help              this message

See SPEC.md for design and CONTRIBUTING.md for hacking.
`)
}

func runInit(args []string) {
	fs := flag.NewFlagSet("init", flag.ExitContinueOnError)
	stateDir := fs.String("state-dir", defaultStateDir(), "where device key + metadata live")
	issuerURL := fs.String("issuer-url", "", "fully-qualified issuer URL where JWKS will be hosted")
	keyTier := fs.String("key-tier", "auto", "auto|tpm|keyring|kms|passphrase")
	if err := fs.Parse(args); err != nil {
		os.Exit(2)
	}

	if *issuerURL == "" {
		log.Fatal("--issuer-url is required (e.g. https://idp.example.com/devices/n4xqz1)")
	}

	log.Printf("init: state-dir=%s issuer=%s tier=%s", *stateDir, *issuerURL, *keyTier)
	log.Println("init: not implemented yet — see SPEC §9")
	os.Exit(1)
}

func runServe(args []string) {
	fs := flag.NewFlagSet("serve", flag.ExitContinueOnError)
	addr := fs.String("addr", "127.0.0.1:53682", "bind address")
	stateDir := fs.String("state-dir", defaultStateDir(), "where device key + metadata live")
	maxTTL := fs.Int("max-ttl", 3600, "max JWT lifetime in seconds")
	if err := fs.Parse(args); err != nil {
		os.Exit(2)
	}

	cfg := server.Config{
		Addr:     *addr,
		StateDir: *stateDir,
		MaxTTL:   *maxTTL,
	}

	if err := server.Run(cfg); err != nil {
		log.Fatal(err)
	}
}

func defaultStateDir() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ".tapid"
	}
	return home + string(os.PathSeparator) + ".tapid"
}
