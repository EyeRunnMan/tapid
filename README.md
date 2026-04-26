# tapid

A localhost OIDC issuer for laptops and bare VPS. Mints workload JWTs signed by a per-host key bound to the strongest crypto the OS exposes (TPM / Secure Enclave / OS keyring / KMS).

Plug into anything that already speaks OIDC — Infisical, Doppler, Vault, AWS STS, GCP WIF, [TAP](../).

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

## Why

Cloud workloads have native OIDC handed to them (`core.getIDToken` in GH Actions, GCE metadata server, AWS IRSA, `VERCEL_OIDC_TOKEN`). Laptops and bare VPS don't. The fallback is always a long-lived static credential on disk — `client_secret`, `dp.st.*`, gcloud refresh token, `.env`. tapid is the missing primitive.

See [`SPEC.md`](./SPEC.md) for the full design.

## Status

**v0.1 — scaffold only.** Spec done, code not written yet. Read SPEC, file issues, watch for the first tagged release.

## Quick (intended) usage

```bash
# one-time
tapid init
tapid serve &

# from any tool
JWT=$(curl -s localhost:53682/token -d "audience=infisical" | jq -r .access_token)
curl -X POST https://app.infisical.com/api/v1/auth/oidc-auth/login \
  -H "Content-Type: application/json" \
  -d "{\"identityId\":\"...\",\"jwt\":\"$JWT\"}"
```

## License

MIT.
