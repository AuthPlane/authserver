*Context: this is part of [Guides — Deploy](README.md). Start with the primer if you haven't.*

# Configuration — what to think about before you deploy

> **This is operator prose, not a schema.** For every YAML key, type, default, and env-var, see [`docs/reference/configuration.md`](../../reference/configuration.md) and [`docs/reference/env-vars.md`](../../reference/env-vars.md). This page covers the decisions that matter for production: which storage, which signing-key store, which data-encryption driver, which optional grants, and which secrets you must mint before first boot.

## What you'll achieve in 10 minutes

- Decide on `storage.driver`, `signing.key_store`, and `data_encryption.driver` for your environment.
- Generate the secrets every non-localhost deploy needs.
- Know which feature flags to flip for MCP machine-to-machine integrations.

## Prereqs

- `openssl` (for secret generation).
- A copy of the [Configuration reference](../../reference/configuration.md) and [Env-vars reference](../../reference/env-vars.md) open in another tab.

## How layering works

`authserver serve` resolves config in three layers, highest priority last:

1. **Defaults** — see `DefaultConfig()` in `internal/config/loader.go`.
2. **YAML file** — passed via `--config`.
3. **Environment variables** — `AUTHPLANE_*`, override matching YAML keys.

Env vars are evaluated **after** YAML, which is why we recommend shipping a single YAML file per environment and overriding secrets via env. The full precedence + required-when rules are in [`docs/reference/configuration.md`](../../reference/configuration.md#config-server).

## Decisions you must make before first boot

### 1. Storage driver — single-node or HA?

| Choice | When | YAML | Env |
| --- | --- | --- | --- |
| `sqlite` (default) | Single instance, dev, edge | [`storage.driver: sqlite`](../../reference/configuration.md#config-storage) | [`AUTHPLANE_STORAGE_DRIVER`](../../reference/env-vars.md) |
| `postgres` | Multi-instance / HA | [`storage.driver: postgres`](../../reference/configuration.md#config-storage), set `storage.postgres.dsn` | [`AUTHPLANE_STORAGE_POSTGRES_DSN`](../../reference/env-vars.md) |

SQLite enables WAL by default (`storage.sqlite.wal: true`) so reads do not block. Postgres unlocks LISTEN/NOTIFY-based signing-key propagation across instances when paired with the `postgres_key` signing-key store — see [Key rotation → `postgres_key`](../operate/key-rotation.md#postgres_key-multi-instance-ha).

### 2. Signing key store — disk, DB, or Vault?

| Choice | When | Notes |
| --- | --- | --- |
| `keyfile` (default) | Single host | Keys on disk at `signing.key_path` (default `data/keys`). Back this directory up. |
| `postgres_key` | Multi-instance Postgres | Keys live in Postgres, AES-encrypted with a master key from `signing.postgres_key.encryption_key_env`. Requires `data_encryption.driver: aes_master`. |
| `vault_transit` | Compliance / HSM | Keys never leave Vault. See [HashiCorp Vault Transit](hashicorp-vault-transit.md). |

Full schema: [`signing` reference](../../reference/configuration.md#config-signing).

### 3. Data encryption driver — what protects refresh-grant rows at rest?

Refresh tokens, broker-grant rows, and the `postgres_key` signing-key blobs are encrypted by the configured [`data_encryption`](../../reference/configuration.md#config-data-encryption) driver:

| Driver | When |
| --- | --- |
| `aes_master` | Simplest. Generate a key (`openssl rand -hex 32`) and supply via the env var named in `data_encryption.aes_master.key_env`. |
| `vault_transit_encrypt` | Compliance — encryption keys live in Vault. See [Vault Transit](hashicorp-vault-transit.md). |

If you leave this unset and your driver requires one (Postgres key store, broker grants), boot fails with a `Validate()` error pointing at the missing field.

### 4. Optional grants — flip on what your clients need

Three OAuth grants ship **off** to keep a fresh install minimal. Every machine-to-machine MCP integration needs at least `client_credentials`:

| Flag | Env | Why an operator turns it on |
| --- | --- | --- |
| [`client_credentials.enabled`](../../reference/configuration.md#config-client-credentials) | `AUTHPLANE_CLIENT_CREDENTIALS_ENABLED` | Any service-account / agent identity flow (RFC 6749 §4.4). |
| [`dpop.enabled`](../../reference/configuration.md#config-dpop) | `AUTHPLANE_DPOP_ENABLED` | Sender-constrained tokens (RFC 9449). Recommended once your clients support it. |
| [`token_exchange.enabled`](../../reference/configuration.md#config-token-exchange) | `AUTHPLANE_TOKEN_EXCHANGE_ENABLED` | Delegation, impersonation, Cross-App Access (RFC 8693). |

With a flag off, `POST /oauth/token` returns `unsupported_grant_type` for that grant — even if the client has it in `grant_types`.

## Secrets you must mint

| Secret | Required when | How |
| --- | --- | --- |
| `session.secret` ([`AUTHPLANE_SESSION_SECRET`](../../reference/env-vars.md)) | `server.issuer` is not localhost | `openssl rand -hex 32` (≥ 32 bytes) |
| `admin.api_key` ([`AUTHPLANE_ADMIN_API_KEY`](../../reference/env-vars.md)) | admin enabled and issuer not localhost | `openssl rand -hex 32`. Min 16 chars; obvious defaults (`changeme`, `secret`, `password`, `dev-admin-key`, …) are rejected at boot. |
| `connect.state_secret` | broker-providers / Connect flow | `openssl rand -hex 32`. Min 32 chars. |
| `data_encryption.aes_master.key_env` target | `data_encryption.driver: aes_master` | `openssl rand -hex 32` (exactly 64 hex chars = 256-bit). |

Validation lives in `internal/config/validate.go`; boot fails fast if any required-when slot is empty. See [`env-vars.md`](../../reference/env-vars.md) for the "Required when" column.

## Worked example — a working production YAML

```yaml
server:
  issuer: https://auth.example.com    # Must be HTTPS, no trailing slash
  shutdown_wait: 20s                  # See systemd.md → SIGTERM

storage:
  driver: postgres                    # AUTHPLANE_STORAGE_DRIVER
  postgres:
    dsn: ""                           # Inject via AUTHPLANE_STORAGE_POSTGRES_DSN
    max_conns: 25                     # Tune against replica count × pool size

signing:
  algorithm: ES256
  key_store: postgres_key             # Multi-replica safe; requires data_encryption
  postgres_key:
    encryption_key_env: AUTHPLANE_SIGNING_KEY_ENC

data_encryption:
  driver: aes_master
  aes_master:
    key_env: AUTHPLANE_DATA_ENC_KEY   # Hex 64-char; mint with: openssl rand -hex 32

session:
  secure: true                        # Required for HTTPS issuer
  same_site: lax
  secret: ""                          # Inject via AUTHPLANE_SESSION_SECRET

admin:
  enabled: true
  address: "127.0.0.1:9001"           # Loopback or internal-only
  api_key: ""                         # Inject via AUTHPLANE_ADMIN_API_KEY

client_credentials:
  enabled: true                       # Flip on for machine-to-machine

observability:
  logging: { level: info, format: json }
  metrics: { provider: prometheus, path: /metrics }

server:
  allowed_origins: ["https://app.example.com"]  # Set non-empty or browser MCP clients fail CORS
```

Then run with:

```bash
# Verified against docs/reference/cli.md#cli-serve
export AUTHPLANE_STORAGE_POSTGRES_DSN="postgres://authserver@db/authserver?sslmode=require"
export AUTHPLANE_SESSION_SECRET=$(openssl rand -hex 32)
export AUTHPLANE_ADMIN_API_KEY=$(openssl rand -hex 32)
export AUTHPLANE_SIGNING_KEY_ENC=$(openssl rand -hex 32)
export AUTHPLANE_DATA_ENC_KEY=$(openssl rand -hex 32)
authserver serve --config /etc/authserver/config.yaml
```

## Verify

```bash
# 1. Config loads and listeners come up
curl -fsS http://localhost:9000/health | jq .
#   {"status":"ok"}  — see docs/reference/http-api.md#http-public-health

# 2. Issuer is correct (matches server.issuer)
curl -fsS http://localhost:9000/.well-known/oauth-authorization-server | jq -r .issuer

# 3. Admin auth works
curl -fsS -H "Authorization: Bearer $AUTHPLANE_ADMIN_API_KEY" \
  http://localhost:9001/admin/stats | jq .
```

## What can go wrong

| Symptom | Likely cause | Fix |
| --- | --- | --- |
| Boot fails with `admin.api_key is required` | `server.issuer` is non-localhost and `AUTHPLANE_ADMIN_API_KEY` is empty or <16 chars | `openssl rand -hex 32`, then export. Default blocklist rejects `changeme`/`dev-admin-key`/etc. |
| Boot fails with `session.secret is required` | Same issuer check, missing `AUTHPLANE_SESSION_SECRET` | Mint a 32-byte secret; min 32 chars. |
| `unsupported_grant_type` for `client_credentials` | Feature flag still default-off | Set [`client_credentials.enabled: true`](../../reference/configuration.md#config-client-credentials) or `AUTHPLANE_CLIENT_CREDENTIALS_ENABLED=true`. |
| Browser MCP clients fail with CORS errors | `server.allowed_origins` is empty (logs a startup `WARN`) | Set [`AUTHPLANE_SERVER_ALLOWED_ORIGINS`](../../reference/env-vars.md) to your app origin (or `*` for dev). |
| All tokens rejected by the MCP resource | `resources[].uri` does not exactly match the resource's PRM `resource` field | Audience is exact-string-matched; align both byte-for-byte. See [Connect MCP Server](../integrate/connect-mcp-server.md#resource-uri-mismatch). |
| `data_encryption: missing key_env` at boot | Driver is `aes_master` but referenced env var unset | Generate 64-hex key and export via the env var named in `data_encryption.aes_master.key_env`. |

## See also

- [`docs/reference/configuration.md`](../../reference/configuration.md) — full YAML schema (generated).
- [`docs/reference/env-vars.md`](../../reference/env-vars.md) — every `AUTHPLANE_*` env var, defaults, required-when.
- [HashiCorp Vault Transit](hashicorp-vault-transit.md) — signing keys and data-at-rest via Vault.
- [Operate → Key rotation](../operate/key-rotation.md) — day-2 rotation policy.
