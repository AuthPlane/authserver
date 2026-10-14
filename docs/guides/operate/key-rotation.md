# Key rotation — rotate ES256/RS256 signing keys without downtime
*Context: this is part of [Guides — Operate](README.md). Start with the primer if you haven't.*

Every JWT the AS emits is signed by a private key whose public twin lives in the JWKS document at `/.well-known/jwks.json`. This recipe rotates that key without invalidating outstanding tokens. The rotated key stays in the JWKS as the **previous** key so existing access tokens still verify; new tokens are signed with the fresh `kid`.

> **Read before rotating.** The AS keeps exactly **one** previous key. A second rotation drops the key before it from the JWKS, and every token that key signed stops verifying — including at this server's own introspection. Never rotate twice within the longest access-token lifetime you issue (15 minutes by default for user tokens from the authorization-code and refresh grants; one hour by default for client credentials, token exchange and XAA) unless that is what you intend.

## What you'll achieve in 5 minutes

- Rotate the active signing key on any storage backend (keyfile, `postgres_key`, Vault Transit), with the caveats per backend below.
- Propagate the new JWKS without breaking in-flight tokens.
- Verify rotation in the audit log and the JWKS endpoint.

## Prereqs

- The admin API key (`AUTHPLANE_ADMIN_API_KEY`) and access to the admin listener (`:9001`), for a rotation through the admin API.
- Or the `authserver admin` CLI on `$PATH` (or `kubectl exec` / `docker compose exec` equivalent), run with the same `--config` file the server is started with. The key commands refuse to run without one unless `AUTHPLANE_SIGNING_KEY_STORE` or `AUTHPLANE_SIGNING_KEY_PATH` is set, as the Docker Compose stacks do. The host-install examples below use the [systemd guide](../deploy/systemd.md)'s layout (`/etc/authserver/config.yaml`, secrets in `/etc/authserver/secrets.env`, service user `authserver`); substitute yours.
- A working `signing.*` config — see [`signing` keys in configuration.md](../../reference/configuration.md) (`signing.key_store`, `signing.key_path`, `signing.vault_transit.*`).
- For multi-instance: a shared key store (`postgres_key` or `vault_transit`). Keyfile is single-instance only.

## Steps

### 1. Inspect the current key set

```bash
curl -s http://localhost:9001/admin/keys -H "Authorization: Bearer $AUTHPLANE_ADMIN_API_KEY"
# or, on a host install (see step 2):   → docs/reference/cli.md#cli-admin-key-list
sudo -u authserver sh -c 'set -a; . /etc/authserver/secrets.env; exec /usr/local/bin/authserver admin key list --config /etc/authserver/config.yaml'
```

In Docker or Kubernetes, use the `exec` forms under step 2 with `list` in place of `rotate`.

Note the active `kid`. Verify it matches the `kid` header on a sample issued JWT.

### 2. Rotate

**Through the admin API of the running server** — preferred, because it is the only path that writes an audit row and moves the rotation metric:

```bash
curl -s -X POST http://localhost:9001/admin/keys/rotate \
  -H "Authorization: Bearer $AUTHPLANE_ADMIN_API_KEY"
# → docs/reference/http-api.md#http-admin-keys-rotate
```

The response carries the new key's `kid` as the key store holds it (on `vault_transit`, `<key_name>-v<version>`). The audit log records `key.rotated` with the same `kid` (canonical: `ActionKeyRotated` in `internal/domain/audit/entity.go`), and the metric `authserver_key_rotation_total` increments (canonical: `KeyRotationTotal` in `internal/observability/metrics.go`; on `postgres_key` it currently increments by two per rotation). On `vault_transit` the call needs `update` on `transit/keys/<key_name>/rotate`; without it the call fails with a server error.

**From the CLI.** On a host install (the [systemd guide](../deploy/systemd.md#signing-key-rotation) layout), run the CLI as the service user and with the server's secrets: they live only in the `EnvironmentFile`, and without `AUTHPLANE_SESSION_SECRET` and `AUTHPLANE_ADMIN_API_KEY` the CLI refuses to load a configuration whose issuer is not localhost. Run as root, it would also write `keyfile` key files the `authserver` user cannot read.

```bash
# → docs/reference/cli.md#cli-admin-key-rotate
sudo -u authserver sh -c 'set -a; . /etc/authserver/secrets.env; exec /usr/local/bin/authserver admin key rotate --config /etc/authserver/config.yaml'
```

In Docker — the [quickstart](../../start/02-quickstart-docker.md) container, or a [Compose stack](../deploy/docker-compose.md) from the repo root, in the shell that ran `up` (Compose re-checks the file's required variables on `exec`; substitute your stack's file):

```bash
docker exec authserver /authserver admin key rotate --config /config.yaml
docker compose -f deploy/docker-compose.sqlite.yml exec authserver /authserver admin key rotate
```

A container started with no config file and no signing variables (the README's `docker run … serve`) keeps its key in the built-in default store; name that store explicitly:

```bash
docker exec -e AUTHPLANE_SIGNING_KEY_STORE=keyfile <container> /authserver admin key rotate
```

In Kubernetes:

```bash
kubectl -n authplane exec deploy/authplane -- /authserver admin key rotate --config /etc/authplane/config.yaml
```

The image ships the binary at `/authserver`. Pass the config file the server was started with — the Helm chart starts it with `--config /etc/authplane/config.yaml`; for your own manifests use the path in the Deployment's `args`. Without `--config` (or `AUTHPLANE_SIGNING_KEY_STORE` / `AUTHPLANE_SIGNING_KEY_PATH` in the environment, as the Docker Compose stacks set) the command refuses to run, because unless the server itself runs on the built-in defaults it would rotate a default key store the server never reads. The first line of output names the key store it acted on; check it before relying on the rotation. A CLI rotation writes no `key.rotated` audit row and moves no metric.

**How the running server picks the rotation up.** The CLI is a separate process, and a rotation can also happen in Vault directly or on another instance. Each server instance serves the JWKS from a cached document that expires after 60 seconds, and before it signs a token with a key that is not in that document it reloads the document from the key store. So:

- No instance signs a token with a key its own JWKS does not carry.
- An instance that has not signed with the new key yet publishes it when its cached document expires — within 60 seconds of the rotation. `GET /admin/keys` on that instance reads the same cached document.
- `SIGHUP` reloads the document at once (see [systemd → Signing-key reload](../deploy/systemd.md#signing-key-reload-sighup)).

With **more than one instance** behind one URL, a resource server that fetches the JWKS from an instance that has not yet published the new key can reject a token another instance signed with it, for up to 60 seconds after the rotation. On `postgres_key` this does not normally happen: every instance is told through Postgres `LISTEN/NOTIFY`, and drops its cached signing key and reloads its JWKS when the notification arrives. An instance whose listener connection was down reloads both when it reconnects; until then its cached signing key expires after 60 seconds, so it signs with the key that was current before the rotation — the previous key, still published — for at most that long. On `vault_transit` nothing tells the other instances; they rely on the 60-second expiry, or a `SIGHUP`.

### 3. Propagate to resource servers

JWKS-consuming verifiers (your MCP servers, SDKs, gateways) cache the document. The JWKS endpoint sends `Cache-Control: public, max-age=3600`, so a verifier or shared cache that honours the header may keep the old document for up to an hour. Re-fetching on an unknown `kid` is what makes rotation work before that. After rotation:

- New JWTs use the new `kid` immediately.
- Verifiers refresh JWKS within their TTL and pick up both keys.
- If a verifier sees an unknown `kid`, it should re-fetch JWKS before rejecting the token.

The SDK token verifier ships this re-fetch-on-unknown-kid behaviour by default.

### 4. Retire the old key

The previous key stays in the JWKS — and is accepted by this server — until the **next** rotation removes it. There is no command that removes a single key. Before the next rotation, wait for the longest outstanding access token to expire: 15 minutes by default for user tokens from the authorization-code and refresh grants ([`dcr.default_token_expiry`](../../reference/configuration.md)), one hour by default for client credentials, token exchange and XAA. Refresh tokens are opaque (not JWTs), so they do not depend on the signing key.

## Verify

```bash
# New kid present and active (up to 60 s after a rotation the server did not perform itself — see step 2)
curl -s http://localhost:9001/admin/keys -H "Authorization: Bearer $AUTHPLANE_ADMIN_API_KEY"
# JWKS has both keys
curl -s http://localhost:9000/.well-known/jwks.json | jq '.keys[].kid'
# Audit row landed (rotations through the admin API only)
curl -s "http://localhost:9001/admin/audit?action=key.rotated&limit=5" \
  -H "Authorization: Bearer $AUTHPLANE_ADMIN_API_KEY" | jq '.[] | {created_at, detail}'
```

## Storage backends

The server creates the first signing key at startup if the key store holds none. If the key store does not answer within 10 seconds, the server starts anyway, logs `signing key not ready at startup`, and the first token request creates the key. Creating the first key never replaces or rotates one: requests that race to create it all end up with the same stored key — across instances on `postgres_key` and `vault_transit`, and within one host on `keyfile`. The public JWKS endpoint never creates a key; until one exists it serves `{"keys":[]}`. Neither does `authserver admin key list`.

### Keyfile (default, single-instance)

```yaml
signing:
  algorithm: ES256
  key_store: keyfile
  key_path: /var/lib/authplane/keys
```

- `current.pem`, `current.kid`, `current.alg` — the active key (PKCS#8, unencrypted on disk) and its id and algorithm.
- `previous.pem`, `previous.kid`, `previous.alg` — the one previous key, kept for verification until the next rotation.
- `.lock` — the lock file that serializes readers and writers.
- Key files are written with mode 0600, and a key directory the server creates gets 0700; the server does not change the mode of a directory that already exists. Anyone who can read these files can forge tokens.
- Every file is written to a temporary file, synced, and renamed into place, in an order that never leaves the current key missing. Reads and writes take a lock on `.lock`, which also covers `authserver admin key rotate` run on the same host or in the same container. A crash in the middle of a rotation never makes the server create a new key, and leaves keys every outstanding token still verifies against; temporary files it leaves behind are removed the next time the store is opened. The one exception is a rotation that changes the algorithm, below.
- If the current key cannot be used — a companion file is missing, the PEM does not parse, or the key type does not match `current.alg` (a crash during an algorithm change, an older version or a manual edit can leave this) — it fails to load: token requests fail with a server error, the log shows `unusable signing key files`, and the JWKS keeps publishing the previous key. The next rotation replaces the unusable key and keeps the previous one.
- Back up the directory; without it, JWKS history is lost and outstanding tokens will fail verification.
- In Docker, mount a named volume at `key_path` or the key is lost on container restart, and every outstanding token with it.
- **Single instance only.** Two instances on the file store each generate their own key, and a token verifies only against the instance that issued it; the lock does not coordinate processes on different hosts. On Kubernetes the Helm chart refuses to render `keyfile` without persistence when `replicaCount > 1` or `autoscaling.enabled`, warns when it runs on a persistent volume with more than one replica, and warns on a single replica without persistence that every pod restart replaces the key. Enable persistence and run one replica, or use `postgres_key` or `vault_transit`.

### `postgres_key` (multi-instance HA)

```yaml
signing:
  algorithm: ES256
  key_store: postgres_key
```

Keys are encrypted at rest using the configured `data_encryption` driver (AES master key or Vault Transit envelope) and stored in PostgreSQL. All instances share the same key. Requires `storage.driver: postgres`. A rotation demotes the current key to previous and deletes every other retired key, in one transaction. If the `data_encryption` key changes and the old one is not configured as a decrypt-only fallback (`data_encryption.aes_master.old_key_env`), the stored signing keys can no longer be decrypted and every token request fails.

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

- **Create the Transit key before first start**, with the type `signing.algorithm` needs (`ecdsa-p256` for ES256, `rsa-*` for RS256). The server creates a missing key itself only if its Vault credential has `update` on `transit/keys/<key_name>`, which the guide's policy does not grant.
- The `kid` is `<key_name>-v<version>`. The JWKS carries the latest version as current and the version before it as previous, unless that version is below the key's `min_decryption_version`.
- Signing always uses the `signing.vault_transit` credential, on its own Vault client, even when `data_encryption.driver: vault_transit_encrypt` points at the same Vault.

## Algorithm selection

| Algorithm | Key type | Signature size | Note |
|---|---|---|---|
| **ES256** | ECDSA P-256 | 64 B | **Default.** Compact tokens, fast verify. |
| RS256 | RSA 2048 | 256 B | Only when policy requires RSA. |

Keys the AS generates are P-256 (ES256) or RSA-2048 (RS256). When verifying, the AS accepts only ES256 and RS256, selects the key by `kid`, and refuses `alg=none`, every HMAC algorithm, and any key carried in the token header. A key loaded from the file store must match its algorithm (an EC key for ES256, an RSA key for RS256) but is not checked for size. On `vault_transit` the key's type is fixed when it is created and kept across rotations; a key whose type does not match `signing.algorithm` is refused.

## What can go wrong

| Symptom | Likely cause | Fix |
|---|---|---|
| Resource server rejects tokens with `unknown kid` after rotation | Verifier cache is stale | Trigger a refresh or restart the verifier; a cache that honours the JWKS `Cache-Control` keeps the old document up to an hour. The SDK verifier re-fetches on unknown kid automatically. |
| Same, for up to a minute, with several instances | The verifier's re-fetch reached an instance that has not published the new key yet (see step 2) | Wait 60 seconds, or send `SIGHUP` to every instance after a rotation. |
| All tokens fail to verify after rotation | Verifier accepts only one `kid`; or the verifier's JWKS cache was overwritten with a stale snapshot | Confirm `/.well-known/jwks.json` returns both keys; force the verifier to refresh; check it isn't pinning a single `kid`. |
| Tokens from before a rotation stopped verifying | A second rotation dropped the key that signed them | Only one previous key is kept; space rotations by at least the longest token lifetime. |
| Lost `current.pem` after Docker restart | No persistent volume mounted at `key_path` | Mount a named volume; restore from backup if possible. |
| `admin key rotate` / `admin key list` fails with `no --config file was given` or `config file … does not exist` | The CLI was run without the server's configuration | Pass `--config` with the server's configuration file. |
| Token requests fail with a server error; the log shows `unusable signing key files` (`keyfile`) | The current key's files are inconsistent or do not match `current.alg` | Rotate (`POST /admin/keys/rotate` or `admin key rotate`): the rotation replaces the unusable key and keeps the previous one. |
| `/.well-known/jwks.json` returns `{"keys":[]}` | No key exists yet: the key store was unreachable at startup and no token has been requested since | Check the startup log for `signing key not ready at startup`; fix the key store; the next token request creates the key. |
| Vault Transit signing fails (`403`) | Vault token expired or policy too narrow | Re-issue token. The AS needs `update` on `transit/sign/<key_name>` and `read` on `transit/keys/<key_name>`; rotating through the AS also needs `update` on `transit/keys/<key_name>/rotate`. It does not call `transit/verify`. |
| Multi-instance: rotation visible on instance A, not B | Instance B still on `keyfile` (single-instance) | Migrate to `postgres_key` or `vault_transit` before going multi-instance — keyfile cannot be shared. |

## Runbook

| Trigger | Action | Operator window |
|---|---|---|
| Calendar (every ≤ 90 days) | `POST /admin/keys/rotate` on the running server (or `admin key rotate` with the server's configuration — see step 2) | Business hours |
| Suspected key compromise | Rotate **twice** — see [Incident runbook](incident-runbook.md#incident-signing-key-compromise). One rotation leaves the compromised key trusted | < 15 min from detection |
| Algorithm migration (RS256 → ES256 or vice versa) | Update `signing.algorithm`, restart, then rotate. Works on `keyfile` and `postgres_key`; not on `vault_transit`, where a rotation keeps the Transit key's type and a key of the other type is refused | Maintenance window |
| Storage backend migration (keyfile → postgres_key/vault_transit) | There is no key export. The new store starts with a new key and no previous one, so every outstanding token stops verifying: migrate in a window at least as long as the longest token lifetime, or accept re-authentication | Maintenance window |

See [Incident runbook → Signing-key compromise](incident-runbook.md#incident-signing-key-compromise) for the full IR variant.

## See also

- [Deploy → systemd: signing-key reload](../deploy/systemd.md#signing-key-reload-sighup) — `SIGHUP` on a host install.
- [Deploy → HashiCorp Vault Transit](../deploy/hashicorp-vault-transit.md) — Vault setup end-to-end.
- [Concepts → Tokens and claims](../../concepts/tokens-and-claims.md) — what the `kid` header is for.
- [Token design (operator view)](token-design-internals.md) — what the AS emits and the verification path.
