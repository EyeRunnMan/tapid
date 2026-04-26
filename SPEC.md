# tapid — Token-Authenticated Identity Daemon

**Version:** 0.1 (draft)
**Status:** Spec. Scaffold + skeleton only.
**Date:** 2026-04-26
**Sibling project:** [TAP](../SPEC.md)

---

## 1. One-line pitch

A localhost OIDC issuer for any host (laptop, VPS, container). Mints workload JWTs signed by a per-host key bound to the strongest crypto the OS exposes (TPM / Secure Enclave / OS keyring / KMS). Plug into anything that speaks OIDC — Infisical, Doppler, Vault, AWS STS, GCP WIF, your own TAP server.

---

## 2. Why this exists

Cloud workloads have OIDC handed to them — GitHub Actions `core.getIDToken()`, GCE metadata server, AWS IRSA, Vercel `VERCEL_OIDC_TOKEN`. Laptops and bare VPS have nothing. The fallback is always `client_id`+`client_secret`, `dp.st.*`, gcloud refresh tokens, or `.env` files — i.e. a long-lived static credential on disk that survives forever if leaked.

tapid is the missing primitive: a tiny daemon that gives every host its own non-extractable signing key and exposes a standards-compliant OIDC issuer over localhost. Any tool that already speaks OIDC works without modification.

**Anti-lock-in:** single Go binary, self-host JWKS as static files, plain Ed25519, no SaaS, no telemetry.

---

## 3. Threat model

**In scope:**
- Stolen disk image (laptop lost, no FDE) — TPM/SE key not in image; daemon useless to attacker.
- Backup leak — same; signing key absent from filesystem.
- Malware exfiltrating files — can't exfil hardware-bound key; can sign while resident, can't take key home.
- Phishing of upstream SSO — device key independent of SSO; attacker registering new device is a flagged event.
- Insider at upstream IdP — no upstream IdP holds the device key.

**Out of scope:**
- Live root on host with active user session — attacker can ask daemon to sign at will. Eviction kills the capability; attacker never extracts the key.
- TPM/SE silicon compromise (rare, hardware-level).
- Hypervisor admin on a VPS with vTPM (different TCB).
- Compromise of the JWKS publishing channel — attacker swapping JWKS reroutes trust. Mitigation: pin JWKS at relying party, transparency log (v0.4+).

**Assumptions:**
- Operator runs daemon as a long-lived process under the user's session.
- `127.0.0.1` is trusted (only the user's processes can hit it).
- JWKS hosting URL is HTTPS and operator-controlled.

---

## 4. Architecture

```
┌──────────────────────────────────────────────┐
│  Host (laptop / VPS / container)             │
│                                              │
│  ┌────────────────────────┐                  │
│  │  tapid daemon          │                  │
│  │                        │                  │
│  │  Key store (tiered):   │                  │
│  │   1. TPM 2.0 / SE       │                 │
│  │   2. OS keyring         │                 │
│  │   3. KMS-wrapped file   │                 │
│  │   4. Passphrase-encrypted│                │
│  │                        │                  │
│  │  HTTP on 127.0.0.1:53682 │                │
│  │   /.well-known/openid-config  (public mirror)│
│  │   /jwks.json                 (public mirror)│
│  │   /token (POST)              (local only)   │
│  │   /healthz                                  │
│  └─────────┬──────────────┘                  │
│            │                                 │
│  ┌─────────▼──────────┐                      │
│  │ your app            │ curl localhost/token│
│  │                     │ → JWT → relying party│
│  └─────────────────────┘                     │
└──────────────────────────────────────────────┘

         JWKS published once at registration to
         a public URL (bucket / GH Pages / your domain).
         Relying parties trust the issuer URL.
```

---

## 5. Key tiers

Daemon detects highest available tier at install. Operator may force with `--key-tier=N`.

| Tier | Backend                                       | OS support                  | Extractable? |
| ---- | --------------------------------------------- | --------------------------- | ------------ |
| 1    | TPM 2.0 / Apple Secure Enclave                | Win/Linux/macOS w/ hardware | No (silicon) |
| 2    | OS keyring (DPAPI / Keychain / Secret Service) | All major OS                | Yes (with user session) |
| 3    | KMS-wrapped file (AWS / GCP / Azure / age)    | Anywhere with KMS access    | Wrap only    |
| 4    | Passphrase-encrypted file                      | Anywhere                    | If passphrase leaks |

Tier of the active key is exposed in JWT claims (`key_tier`) so relying parties can downscope based on it.

---

## 6. HTTP API

```
GET  /.well-known/openid-configuration   OIDC discovery
GET  /jwks.json                           public keys
POST /token                               mint JWT
GET  /healthz                             liveness
```

### 6.1 `POST /token`

Body (form-encoded or JSON):
```
audience=infisical
ttl=600                  optional, default 600, capped at max_ttl
```

Response:
```json
{ "access_token": "eyJ...", "token_type": "Bearer", "expires_in": 600 }
```

### 6.2 Discovery

```json
{
  "issuer": "https://idp.example.com/devices/n4xqz1",
  "jwks_uri": "https://idp.example.com/devices/n4xqz1/jwks.json",
  "id_token_signing_alg_values_supported": ["EdDSA"],
  "response_types_supported": ["id_token"],
  "subject_types_supported": ["public"]
}
```

---

## 7. JWT format

Signed Ed25519 (`alg: EdDSA`). Claims:

```json
{
  "iss": "https://idp.example.com/devices/n4xqz1",
  "sub": "device:n4xqz1",
  "aud": "infisical",
  "iat": 1735000000,
  "exp": 1735000600,
  "jti": "01H...",
  "device_id": "n4xqz1",
  "device_name": "karan-thinkpad",
  "user": "karan@example.com",
  "key_tier": "tpm",
  "posture": {
    "fde": true,
    "os": "windows-11-26200"
  }
}
```

`posture` is opt-in per claim. `jti` is monotonic + random for replay defense.

---

## 8. Configuration

Flags:
- `--addr 127.0.0.1:53682` — bind address
- `--issuer-url https://idp.example.com/devices/n4xqz1` — fully-qualified issuer URL (must match published JWKS location)
- `--key-tier auto|tpm|keyring|kms|passphrase` — force tier
- `--max-ttl 3600` — max JWT lifetime
- `--posture fde,os` — claims to include
- `--state-dir ~/.tapid` — where device_id, encrypted key, registration metadata live

Env:
- `TAPID_KMS=aws-kms://arn:aws:...` — for tier 3
- `TAPID_PASSPHRASE_FILE=/run/secrets/tapid.pass` — for tier 4 headless

---

## 9. Bootstrap

### 9.1 Interactive (laptop)

```
$ tapid init
  → opens browser, GitHub OAuth device flow
  → generates Ed25519 keypair (in TPM/SE if available)
  → writes device metadata to ~/.tapid/device.json
  → prints jwks.json + openid-configuration to ./tapid-publish/
  → tells you to upload that dir to your JWKS host
  → prints the issuer URL to use
$ tapid serve
  → daemon up on 127.0.0.1:53682
```

### 9.2 Headless (VPS)

```
$ tapid init --headless --register-token=$BOOTSTRAP_TOKEN \
             --issuer-url=https://idp.example.com/devices/svc-deployer-1
  → registers without browser
  → publishes JWKS to a configured remote (bucket / git push)
$ tapid serve
```

---

## 10. Implementation stack

- **Go 1.22+** — single static binary, ~5 MB stripped.
- **`crypto/ed25519`** — std lib, no third-party crypto.
- **`net/http`** — std lib, no framework.
- **TPM 2.0:** `github.com/google/go-tpm` + `go-tpm-tools`.
- **macOS Secure Enclave:** `github.com/keys-pub/keys-ext` or cgo bridge to `Security.framework`.
- **OS keyring:** `github.com/zalando/go-keyring`.
- **KMS:** opt-in build tags (`-tags aws,gcp,azure`) so default binary stays slim.
- **YAML:** `github.com/goccy/go-yaml` for config; or just JSON to avoid the dep.

Hard rules:
- No reflection-heavy libraries.
- No JSON web token library (write the EdDSA + base64 ourselves; <100 LOC).
- No web framework.
- All HTTP routes hand-written; total handler LOC < 500.
- `go vet`, `staticcheck`, `govulncheck` clean in CI.

---

## 11. Anti-lock-in

1. JWKS = two static JSON files. Serve from anything.
2. Device key portable (export with passphrase if user wants migration; tier 1 keys are non-portable by design — that's the security property).
3. No central registry required. Hosted registry comes in v0.3 as opt-in.
4. MIT license.
5. JWT format = standard OIDC. Any verifier works.

---

## 12. Roadmap

- **0.1 (this spec)** — tier 2 + 4 only, single device, manual JWKS upload, GitHub OAuth bootstrap, Linux + macOS + Windows.
- **0.2** — tier 1 (TPM, SE), tier 3 (KMS), posture claims, headless `--register-token`.
- **0.3** — hosted registry (`registry.tapid.dev`), multi-device per user, admin CLI.
- **0.4** — RFC 8693 token exchange, audit log streaming, MDM hooks (Jamf/Intune/Kandji), JWKS transparency log.

**Never:** secret storage, user authentication UI, authorization decisions.

---

## 13. Open questions

1. Default port? `53682` (random 16-bit) chosen to avoid common collisions; revisit if conflicts hit.
2. JWT alg — Ed25519 chosen for size + speed. Should we also support RS256 for ancient verifiers? Probably yes by 0.2.
3. Token caching — should daemon cache and reuse a JWT per (audience, ttl) tuple within its validity? Saves CPU; complicates revocation. Default off in 0.1.
4. Process attribution — should `/token` only mint for processes owned by the same user as the daemon? Linux `SO_PEERCRED` makes this trivial; Windows `GetNamedPipeClientProcessId`. Probably yes, on by default.
