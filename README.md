# tapid

A localhost OIDC issuer for laptops and bare VPS. Mints workload JWTs signed by a per-host key bound to the strongest crypto the OS exposes — TPM 2.0, Apple Secure Enclave, OS keyring, KMS, or a passphrase-encrypted file.

Plug into anything that already speaks OIDC — Infisical, Doppler, Vault, AWS STS, GCP WIF, [TAP](https://github.com/EyeRunnMan/tap).

```
   ┌──────────┐    POST /token         ┌─────────────┐
   │ your app │ ─────────────────────▶ │   tapid     │
   │          │ ◀───────── JWT ─────── │  (daemon)   │
   └────┬─────┘                        └─────────────┘
        │ JWT
        ▼
   ┌──────────────────────────────────┐
   │ Infisical / Vault / TAP / AWS / … │
   └──────────────────────────────────┘
```

## Install

| Platform | Command |
| --- | --- |
| **macOS / Linux** | `curl -fsSL https://raw.githubusercontent.com/EyeRunnMan/tapid/main/install.sh \| sh` |
| **Windows (PowerShell)** | `iwr https://raw.githubusercontent.com/EyeRunnMan/tapid/main/install.ps1 \| iex` |
| **Go users** | `go install github.com/EyeRunnMan/tapid/cmd/tapid@latest` |

Both install scripts download the latest release binary, verify SHA256, drop into `~/.local/bin` (Unix) or `%LOCALAPPDATA%\tapid\bin` (Windows), and offer to add the dir to PATH.

Pin a specific version: `TAPID_VERSION=v0.3.0 curl …`.

## Quick start

### Mode A — GitHub repo publish (works with strict OIDC verifiers like Infisical)

```bash
# one-time: register an OAuth App on GitHub with the "gist" + "public_repo" scopes,
# enable Device Flow, and copy the Client ID.

export TAPID_GITHUB_CLIENT_ID=Iv1.xxxxxxxx

tapid init --publish=repo
# → opens browser, you approve
# → creates <you>/tapid-jwks repo, pushes your JWKS
# → prints your issuer URL: https://raw.githubusercontent.com/<you>/tapid-jwks/main/devices/<id>

tapid serve &

# from any tool
JWT=$(curl -s localhost:53682/token -d audience=infisical | jq -r .access_token)
```

### Mode B — manual JWKS hosting

```bash
tapid init --publish=manual --issuer-url=https://idp.your-domain.com/devices/laptop-1
# → emits ~/.tapid/publish/{jwks.json,.well-known/openid-configuration}
# → you upload to your issuer URL host
tapid serve
```

## Key tiers

`tapid init` auto-selects the best available; `--key-tier=` overrides.

| Tier | Backend | Status | Key extractable? |
| --- | --- | --- | --- |
| 1 | Windows TPM 2.0 (TBS) | shipped | no (silicon) |
| 1 | Linux TPM 2.0 / Secure Enclave | planned | no |
| 4 | passphrase-encrypted file (scrypt + AES-GCM) | shipped | with passphrase |

ES256 (ECDSA P-256) — universally supported by OIDC backends.

## Why

Cloud workloads have native OIDC (`core.getIDToken` in GitHub Actions, GCE metadata server, AWS IRSA, `VERCEL_OIDC_TOKEN`). Laptops and bare VPS have nothing — the fallback is always a static credential on disk that survives forever if leaked. tapid is the missing primitive: a tiny daemon that gives every host its own non-extractable signing key and exposes a standards-compliant OIDC issuer over localhost.

Anti-lock-in: single Go binary, JWKS hosted as static files anywhere, plain ES256, no SaaS, no telemetry.

See [`SPEC.md`](./SPEC.md) for the full design and threat model.

## Status

- v0.1 — passphrase keystore + JWT mint
- v0.2 — GitHub OAuth + Gist publish
- v0.2.1 — ES256 + GitHub repo publish (Infisical-compatible)
- **v0.3 — Windows TPM 2.0 hardware-bound key (current)**

Roadmap: see [`SPEC.md §12`](./SPEC.md).

## License

MIT.
