*Context: this is part of [Guides — Deploy](README.md). Start with the primer if you haven't.*

# HashiCorp Vault Transit — keys never leave Vault

Delegate JWT signing (and optionally data-at-rest encryption) to Vault's Transit secrets engine. Signing key material is created, used, and rotated inside Vault — authserver sends payloads, Vault returns signatures.

## What you'll achieve in 20 minutes

- A Transit signing key + policy + AppRole bound to authserver.
- `signing.key_store: vault_transit` wired into your deployment (compose / systemd / Helm).
- Optional: `data_encryption.driver: vault_transit_encrypt` for refresh-grant / broker-grant rows.

## Prereqs

- Vault 1.12+ — reachable from your authserver host / pods.
- The Transit secrets engine enabled (`vault secrets enable transit`).
- Vault auth method enabled (AppRole recommended; static token only for dev).
- An [already-deployed authserver](README.md) (any target) — this recipe swaps the key store, it does not stand up the AS.
- Glossary context: [Signing key store](../../concepts/glossary.md), [Transit secrets engine](https://developer.hashicorp.com/vault/docs/secrets/transit).

## When to use Vault Transit

| Need | Use |
| --- | --- |
| FIPS / HSM-backed signing | Vault Transit (with HSM backend) |
| Strong segregation of duties — operators must never see private keys | Vault Transit |
| Multi-replica deployment without shared filesystem and without `postgres_key` | Vault Transit |
| Simple single-host or HA-postgres deploys | Stay on `keyfile` or [`postgres_key`](../../reference/configuration.md#config-signing) — Vault Transit adds a runtime dependency and ~2 ms per sign |

## Steps

### 1. Enable the Transit engine

```bash
vault secrets enable transit
```

### 2. Create the signing key

ES256 (default in authserver):

```bash
vault write -f transit/keys/authserver-signing type=ecdsa-p256
```

RS256 (if you must):

```bash
vault write -f transit/keys/authserver-signing type=rsa-2048
```

### 3. Write the policy

```hcl
# authserver-signing-policy.hcl
path "transit/sign/authserver-signing"   { capabilities = ["update"] }
path "transit/verify/authserver-signing" { capabilities = ["update"] }
path "transit/keys/authserver-signing"   { capabilities = ["read"]   }
```

```bash
vault policy write authserver-signing authserver-signing-policy.hcl
```

### 4. Bind authserver to Vault — AppRole (recommended)

```bash
vault auth enable approle
vault write auth/approle/role/authserver \
  token_policies="authserver-signing" \
  token_ttl=1h \
  token_max_ttl=24h

ROLE_ID=$(vault read -field=role_id auth/approle/role/authserver/role-id)
SECRET_ID=$(vault write -field=secret_id -f auth/approle/role/authserver/secret-id)
```

Wire it into authserver — env first (works for any deploy target):

```bash
# Verified against docs/reference/env-vars.md (AUTHPLANE_VAULT_*)
export AUTHPLANE_SIGNING_KEY_STORE=vault_transit
export AUTHPLANE_VAULT_ADDR=https://vault.svc:8200
export AUTHPLANE_VAULT_TRANSIT_MOUNT=transit
export AUTHPLANE_VAULT_TRANSIT_KEY_NAME=authserver-signing
export AUTHPLANE_VAULT_APPROLE_ROLE_ID="$ROLE_ID"
export AUTHPLANE_VAULT_APPROLE_SECRET_ID="$SECRET_ID"
```

YAML equivalent (`signing` section, verified against [`configuration.md#config-signing`](../../reference/configuration.md#config-signing)):

```yaml
signing:
  algorithm: ES256
  key_store: vault_transit
  vault_transit:
    address: https://vault.svc:8200
    mount: transit
    key_name: authserver-signing
    timeout: 10s
    approle:
      role_id: ""        # inject via AUTHPLANE_VAULT_APPROLE_ROLE_ID
      secret_id: ""      # inject via AUTHPLANE_VAULT_APPROLE_SECRET_ID
```

authserver runs a background goroutine that re-authenticates against Vault at half the lease duration (10 s lower bound). Renewal failures log at `WARN` but do not crash; the last issued token is used until it expires.

### 4b. Static token (dev only)

```bash
vault token create -policy=authserver-signing -period=768h
```

```bash
export AUTHPLANE_SIGNING_KEY_STORE=vault_transit
export AUTHPLANE_VAULT_ADDR=https://vault.svc:8200
export AUTHPLANE_VAULT_TOKEN=hvs.your-token
```

Static-token configurations skip the renewal goroutine — the supplied token is used until it expires. Fine for the [`deploy/docker-compose.vault.yml`](../../../deploy/docker-compose.vault.yml) dev stack; not for production.

### 5. Optional — Vault Transit for data encryption

Encrypts `broker_grants` rows (and `postgres_key` blobs if used) without an AES master key on the host:

```bash
vault write -f transit/keys/authserver-data type=aes256-gcm96
```

Reuse the same policy pattern (`encrypt/authserver-data`, `decrypt/authserver-data`). YAML (verified against [`configuration.md#config-data-encryption`](../../reference/configuration.md#config-data-encryption)):

```yaml
data_encryption:
  driver: vault_transit_encrypt
  vault_transit_encrypt:
    address: https://vault.svc:8200
    mount_path: transit
    key_name: authserver-data
    auth_method: approle
    approle:
      role_id_env:   AUTHPLANE_DATA_ENCRYPTION_VAULT_ROLE_ID_ENV
      secret_id_env: AUTHPLANE_DATA_ENCRYPTION_VAULT_SECRET_ID_ENV
```

Env var names verified against [`env-vars.md`](../../reference/env-vars.md).

### 6. Restart the service

systemd: `systemctl restart authserver`. Docker Compose: `docker compose up -d`. Helm: `helm upgrade ... --set vault.signing.enabled=true ...`.

## Verify

```bash
# Authserver should publish JWKS sourced from Vault
curl -fsS https://auth.example.com/.well-known/jwks.json | jq -r '.keys[] | "\(.kid) \(.kty) \(.alg)"'

# Issue a token, then confirm Vault saw a sign call
vault read sys/internal/counters/activity | grep -A2 'transit'   # admin-side; aggregated

# Process the renewal log line in journal / pod logs
journalctl -u authserver -n 50 | grep -iE 'vault|approle'
# Expected: "vault approle re-authenticated" or similar; no "WARN" near boot.
```

## What can go wrong

| Symptom | Likely cause | Fix |
| --- | --- | --- |
| `vault transit: permission denied` on first sign | Token/AppRole missing the `authserver-signing` policy | `vault token lookup` to confirm policies; `vault policy read authserver-signing` to confirm capabilities. |
| `vault transit: key not found` | Wrong `key_name`, or key never created | `vault list transit/keys`; recreate via Step 2. |
| `connection refused` at boot | `signing.vault_transit.address` wrong or Vault unreachable from the AS network | Curl `$VAULT_ADDR/v1/sys/health` from the AS host; check NetworkPolicy / security groups. |
| `Vault is sealed` after Vault restart | Production Vault is sealed by default after restart | Unseal Vault; AppRole renewal will resume automatically. |
| Background `WARN vault renewal failed` log | AppRole lease expired faster than renewal interval, or Vault is unreachable | Bump `token_ttl` on the role; alert on this log line — once the in-flight token expires, signing fails. |
| `data_encryption: missing key_env` | Mixed `vault_transit_encrypt` + AppRole, but role-id env var not set in the running process | Verify the env named in `approle.role_id_env` is exported in the pod / unit. |

## Runbook

- **Rotate the Transit signing key**: `vault write -f transit/keys/authserver-signing/rotate`. authserver picks up the new key version on the next sign (Vault tracks `kid → version` for you). The old version stays available for verification until you `vault write transit/keys/authserver-signing/config min_decryption_version=N`.
- **Rotate AppRole secret**: `vault write -f auth/approle/role/authserver/secret-id` → push the new secret-id to the AS env (Kubernetes Secret rotation + pod restart, or systemd `EnvironmentFile` update + `systemctl restart`). authserver does not hot-reload the secret-id.
- **Disaster recovery**: if Vault is permanently lost, every JWT signed by `vault_transit` is unverifiable. Treat the Vault snapshot as the authority for signing keys; back it up at least daily. Pair with `data_encryption.driver: vault_transit_encrypt` if you want the same posture for refresh-grants.

## See also

- [Configuration](configuration.md) — when to pick Vault vs `keyfile` vs `postgres_key`.
- [Docker Compose](docker-compose.md) — [`deploy/docker-compose.vault.yml`](../../../deploy/docker-compose.vault.yml) runs a dev-mode Vault.
- [Helm](helm.md) — `vault.signing.enabled: true` wires this in.
- [`docs/reference/configuration.md#config-signing`](../../reference/configuration.md#config-signing) and [`#config-data-encryption`](../../reference/configuration.md#config-data-encryption).
