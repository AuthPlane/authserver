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

RS256 (only when `signing.algorithm: RS256` is set):

```bash
vault write -f transit/keys/authserver-signing type=rsa-2048
```

The key type must match `signing.algorithm`: ES256 needs `ecdsa-p256`, RS256
any `rsa-*` type. Vault keeps a key's type across rotations, and writing an
existing key with a different `type` changes nothing. A mismatched key is
refused: the server does not start if it can read the key at boot, and
otherwise no token is issued with it.

**Create the key before the first start.** If it does not exist, the server
tries to create it at startup and again on the first token request, but only a
credential with `update` on `transit/keys/authserver-signing` can, and the
policy in step 3 does not grant that. Until the key exists, every token request
fails with a server error and the JWKS is empty (`{"keys":[]}`).

### 3. Write the policy

```hcl
# authserver-signing-policy.hcl
path "transit/sign/authserver-signing"   { capabilities = ["update"] }
path "transit/keys/authserver-signing"   { capabilities = ["read"]   }
```

This lets authserver sign and read the public keys. It cannot create the key
(create it as in step 2) or rotate it: `POST /admin/keys/rotate` and
`authserver admin key rotate` also need
`path "transit/keys/authserver-signing/rotate" { capabilities = ["update"] }`.
authserver never calls `transit/verify`.

Signing always authenticates with the `signing.vault_transit` token or AppRole
below, on its own Vault client — also when `data_encryption.driver:
vault_transit_encrypt` (step 5) points at the same Vault and mount, so the two
can have separate least-privilege credentials.

**Upgrading from 0.2.2 or earlier with signing and data encryption on the same
Vault:** earlier versions signed through the data-encryption client and ignored
`signing.vault_transit.token` and `signing.vault_transit.approle`. They are now
used, so before upgrading check that this credential can read and sign with the
signing key (the policy above). A wrong AppRole fails the boot; a token without
access starts the server, and every token request then fails.

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

authserver sends an encryption context with every value (for example `signing-key:<kid>`) so that a ciphertext belongs to one row. Vault enforces a context only on a key created with `derived=true`; on the key above it is accepted and ignored, so a ciphertext copied from one row to another of the same kind still decrypts. `aes_master` binds the context in every case.

`vault_transit_encrypt` currently starts only with token authentication: an `auth_method: approle` configuration passes validation, but the server then fails to start with `vault token or approle config is required`.

Reuse the same policy pattern (`encrypt/authserver-data`, `decrypt/authserver-data`). YAML (verified against [`configuration.md#config-data-encryption`](../../reference/configuration.md#config-data-encryption)):

```yaml
data_encryption:
  driver: vault_transit_encrypt
  vault_transit_encrypt:
    address: https://vault.svc:8200
    mount_path: transit
    key_name: authserver-data
    auth_method: token
    token_env: AUTHPLANE_DATA_VAULT_TOKEN   # *name* of the env var that holds the Vault token (your choice)
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
# Expected with AppRole: "vault approle login successful" at boot; no "WARN" near boot.
```

## What can go wrong

| Symptom | Likely cause | Fix |
| --- | --- | --- |
| Token requests fail; the log shows `vault /v1/transit/sign/authserver-signing: status 403` | Token/AppRole missing the `authserver-signing` policy | `vault token lookup` to confirm policies; `vault policy read authserver-signing` to confirm capabilities. |
| `/.well-known/jwks.json` and every token request return 500; the log shows `read transit key: vault /v1/transit/keys/<key_name>: status 403` | `signing.vault_transit.key_name` names a key the policy does not cover (a wrong name) | Set `key_name` to the key the policy grants (`authserver-signing` here); `vault list transit/keys`. |
| `/.well-known/jwks.json` returns `{"keys":[]}` and every token request returns 500; the log shows `create first key: create transit key: vault create key: vault /v1/transit/keys/authserver-signing: status 403` | The key was never created, and the policy (correctly) does not let authserver create it | Create it as in Step 2; the next token request uses it. |
| `POST /admin/keys/rotate` returns 500; the log shows a Vault 403 on `/v1/transit/keys/authserver-signing/rotate` | The policy does not grant rotation | Add `update` on `transit/keys/authserver-signing/rotate` (step 3), or rotate in Vault directly (Runbook). |
| Boot fails with `transit key type does not match signing.algorithm` | The Transit key's type cannot sign for `signing.algorithm` (e.g. an `ecdsa-p256` key with `RS256`) | Follow the remedy the error names: set `signing.algorithm` to the algorithm the key can sign (ES256 for `ecdsa-p256`, RS256 for `rsa-*`), or set `signing.vault_transit.key_name` to a **new** name and create that key as in Step 2 under the new name. Re-running Step 2 with the existing name changes nothing. |
| `connection refused` at boot | `signing.vault_transit.address` wrong or Vault unreachable from the AS network | Curl `$VAULT_ADDR/v1/sys/health` from the AS host; check NetworkPolicy / security groups. |
| `Vault is sealed` after Vault restart | Production Vault is sealed by default after restart | Unseal Vault; AppRole renewal will resume automatically. |
| Background `WARN vault token renewal failed` log | AppRole lease expired faster than renewal interval, or Vault is unreachable | Bump `token_ttl` on the role; alert on this log line — once the in-flight token expires, signing fails. |
| Boot fails with `vault transit encrypt client: vault token or approle config is required` | `data_encryption.vault_transit_encrypt` with `auth_method: approle` (not supported yet), or `token_env` names an unset variable | Use `auth_method: token` and export the variable `token_env` names in the pod / unit. |

## Runbook

- **Rotate the Transit signing key**: prefer `POST /admin/keys/rotate` on the running server (it needs `update` on `transit/keys/authserver-signing/rotate` — see step 3); it returns, and writes to the `key.rotated` audit row, the new `kid`, `authserver-signing-v<version>`. A rotation done in Vault directly (`vault write -f transit/keys/authserver-signing/rotate`) works too: every instance signs with the new version at once, publishes it in its JWKS before the first token it signs with it, and within 60 seconds otherwise (`SIGHUP` makes it immediate). authserver publishes the latest version and the one before it, so a second rotation drops the version two back — and every token it signed. Raising `min_decryption_version` to the latest version removes the previous one from what Vault reports, and so from the JWKS within 60 seconds; tokens it signed then stop verifying.
- **Rotate AppRole secret**: `vault write -f auth/approle/role/authserver/secret-id` → push the new secret-id to the AS env (Kubernetes Secret rotation + pod restart, or systemd `EnvironmentFile` update + `systemctl restart`). authserver does not hot-reload the secret-id.
- **Disaster recovery**: if Vault is permanently lost, every JWT signed by `vault_transit` is unverifiable. Treat the Vault snapshot as the authority for signing keys; back it up at least daily. Pair with `data_encryption.driver: vault_transit_encrypt` if you want the same posture for refresh-grants.

## See also

- [Configuration](configuration.md) — when to pick Vault vs `keyfile` vs `postgres_key`.
- [Docker Compose](docker-compose.md) — [`deploy/docker-compose.vault.yml`](../../../deploy/docker-compose.vault.yml) runs a dev-mode Vault.
- [Helm](helm.md) — `vault.signing.enabled: true` wires this in.
- [`docs/reference/configuration.md#config-signing`](../../reference/configuration.md#config-signing) and [`#config-data-encryption`](../../reference/configuration.md#config-data-encryption).
