# Key rotation — rotate ES256/RS256 signing keys without downtime
*Context: this is part of [Guides — Operate](README.md). Start with the primer if you haven't.*

Every JWT the AS emits is signed by a private key whose public twin lives in the JWKS document at `/.well-known/jwks.json`. This recipe rotates that key without invalidating outstanding tokens. The rotated key stays in the JWKS so existing access tokens still verify; new tokens are signed with the fresh `kid`.

## What you'll achieve in 5 minutes

- Rotate the active signing key on any storage backend (keyfile, `postgres_key`, Vault Transit).
- Propagate the new JWKS without breaking in-flight tokens.
- Verify rotation in the audit log and the JWKS endpoint.

## Prereqs

- `authserver admin` CLI on `$PATH` (or `kubectl exec` / `docker compose exec` equivalent).
- A working `signing.*` config — see [`signing` keys in configuration.md](../../reference/configuration.md) (`signing.key_store`, `signing.key_path`, `signing.vault_transit.*`, `signing.postgres_key.*`).
- For multi-instance: a shared key store (`postgres_key` or `vault_transit`). Keyfile is single-instance only.

## Steps

### 1. Inspect the current key set

```bash
authserver admin key list
# → docs/reference/cli.md#cli-admin-key-list
```

Note the active `kid`. Verify it matches the `kid` header on a sample issued JWT.

### 2. Rotate

```bash
authserver admin key rotate
# → docs/reference/cli.md#cli-admin-key-rotate
```

A fresh key pair is generated, becomes the active signer immediately, and the previous key remains in JWKS for verification. The audit log records `key.rotated` (canonical: `internal/domain/audit/entity.go:39`) and the metric `authserver_key_rotation_total` increments by one (canonical: `internal/observability/metrics.go:210`).

In Docker:

```bash
docker compose exec authserver /authserver admin key rotate
```

In Kubernetes — see [systemd / k8s signing-key propagation](../deploy/systemd.md#signing-key-rotation):

```bash
kubectl -n authplane exec deploy/authserver -- /authserver admin key rotate
```

### 3. Propagate to resource servers

JWKS-consuming verifiers (your MCP servers, SDKs, gateways) cache the document. Recommended TTL: 5 minutes. After rotation:

- New JWTs use the new `kid` immediately.
- Verifiers refresh JWKS within their TTL and pick up both keys.
- If a verifier sees an unknown `kid`, it should re-fetch JWKS before rejecting the token.

The SDK token verifier ships this re-fetch-on-unknown-kid behaviour by default.

### 4. Retire the old key

Wait for the longest outstanding token to expire (default access-token TTL is 15 min; see [`dcr.default_token_expiry`](../../reference/configuration.md) — `15m`). Refresh tokens are opaque (not JWTs) so they do not depend on the signing key. After expiry, the previous key can be dropped from JWKS in the next rotation cycle.

## Verify

```bash
# New kid present and active
authserver admin key list
# JWKS has both keys
curl -s http://localhost:9000/.well-known/jwks.json | jq '.keys[].kid'
# Audit row landed
curl -s "http://localhost:9001/admin/audit?action=key.rotated&limit=5" \
  -H "Authorization: Bearer $AUTHPLANE_ADMIN_API_KEY" | jq '.events[] | {created_at, detail}'
```

## Storage backends

### Keyfile (default, single-instance)

```yaml
signing:
  algorithm: ES256
  key_store: keyfile
  key_path: /var/lib/authplane/keys
```

- `current.pem` — active key (private + public).
- `rotated-<timestamp>.pem` — previous keys retained for verification.
- File mode 0600 owned by the `authserver` user. Anyone who can read these files can forge tokens.
- Back up the directory; without it, JWKS history is lost and outstanding tokens will fail verification.
- In Docker, mount a named volume at `key_path` or rotation state is lost on container restart.

### `postgres_key` (multi-instance HA)

```yaml
signing:
  algorithm: ES256
  key_store: postgres_key
```

Keys are encrypted at rest using the configured `data_encryption` driver (AES master key or Vault Transit envelope) and stored in PostgreSQL. All instances share the same key. Requires `storage.driver: postgres`.

### `vault_transit` (maximum security)

```yaml
signing:
  algorithm: ES256
  key_store: vault_transit
  vault_transit:
    address: https://vault:8200
    key_name: authserver-signing
    approle:
      role_id: "..."
      secret_id: "..."
```

The private key **never leaves Vault**. The AS sends the digest to Vault and gets a signature back. Use AppRole in production (auto-renew); token auth is fine for dev. See [Deploy → HashiCorp Vault Transit](../deploy/hashicorp-vault-transit.md).

## Algorithm selection

| Algorithm | Key type | Signature size | Note |
|---|---|---|---|
| **ES256** | ECDSA P-256 | 64 B | **Default.** Compact tokens, fast verify. |
| RS256 | RSA 2048+ | 256 B | Only when policy requires RSA. |

The AS rejects RSA keys below 2048 bits at generation, `alg=none`, all HMAC algorithms, and any `jwk` header carrying private-key material.

## What can go wrong

| Symptom | Likely cause | Fix |
|---|---|---|
| Resource server rejects tokens with `unknown kid` after rotation | Verifier cache is stale | Wait one cache TTL (default 5 min) or trigger a refresh; the SDK verifier re-fetches on unknown kid automatically. |
| All tokens fail to verify after rotation | Verifier accepts only one `kid`; or the verifier's JWKS cache was overwritten with a stale snapshot | Confirm `/.well-known/jwks.json` returns both keys; force the verifier to refresh; check it isn't pinning a single `kid`. |
| Lost `current.pem` after Docker restart | No persistent volume mounted at `key_path` | Mount a named volume; restore from backup if possible. |
| `authserver` won't start: "signing key not found" | Empty or unreadable `key_path` | Check directory perms; on first start the AS auto-generates a key, so a permission failure is the only reason an existing directory fails. |
| Vault Transit signing fails (`403`) | Vault token expired or policy too narrow | Re-issue token; policy must include `transit/sign/<key_name>` and `transit/verify/<key_name>`. |
| Multi-instance: rotation visible on instance A, not B | Instance B still on `keyfile` (single-instance) | Migrate to `postgres_key` or `vault_transit` before going multi-instance — keyfile cannot be shared. |

## Runbook

| Trigger | Action | Operator window |
|---|---|---|
| Calendar (every ≤ 90 days) | `admin key rotate` | Business hours |
| Suspected key compromise | `admin key rotate` + force-logout affected users + revoke affected client secrets | < 15 min from detection |
| Algorithm migration (RS256 → ES256 or vice versa) | Update `signing.algorithm`, restart, then `admin key rotate` | Maintenance window |
| Storage backend migration (keyfile → postgres_key/vault_transit) | Export keys, update config, restart, verify JWKS still serves both kids | Maintenance window |

See [Incident runbook → Signing-key compromise](incident-runbook.md#incident-signing-key-compromise) for the full IR variant.

## See also

- [Deploy → systemd: signing key rotation](../deploy/systemd.md#signing-key-rotation) — propagation across systemd units.
- [Deploy → HashiCorp Vault Transit](../deploy/hashicorp-vault-transit.md) — Vault setup end-to-end.
- [Concepts → Tokens and claims](../../concepts/tokens-and-claims.md) — what the `kid` header is for.
- [Token design (operator view)](token-design-internals.md) — what the AS emits and the verification path.
