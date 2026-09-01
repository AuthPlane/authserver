# Admin CLI — your day-2 driver
*Context: this is part of [Guides — Operate](README.md). Start with the primer if you haven't.*

The `authserver admin …` CLI is the scripted operator surface. It shares its service layer with the Admin REST API and the embedded UI, so every mutation emits the same audit row regardless of which surface drove it. This page is recipe-shaped — each task points at the exact CLI subcommand and its anchor in [`docs/reference/cli.md`](../../reference/cli.md). For the HTTP route catalog, see [`docs/reference/http-api.md`](../../reference/http-api.md).

## What you'll achieve in 15 minutes

- Bind the admin API key in your shell.
- Run one mutation in every major resource family: clients, users, resources, providers, fronting links, grants, issuances, keys.
- Read the audit log to confirm the mutation landed.

## Prereqs

- An authserver instance reachable at `http://localhost:9001` (substitute your `admin.address`).
- `admin.api_key` set in YAML or via env. See [`AUTHPLANE_ADMIN_API_KEY`](../../reference/env-vars.md).
- `authserver` binary on `$PATH` (or `docker compose exec authserver /authserver …`).

```bash
export AUTHPLANE_ADMIN_API_KEY="$(your-secret-tool get authplane/admin)"
```

---

## Recipe: clients

Create, list, suspend, revoke, rotate. CLI catalog: [`authserver admin client`](../../reference/cli.md#cli-admin-client).

```bash
# Create a confidential client; the secret prints once
authserver admin client create --name "billing-svc" \
  --grant-types client_credentials \
  --auth-method client_secret_basic \
  --scope "billing.read"
# → docs/reference/cli.md#cli-admin-client-create

# List, filter by status
authserver admin client list --status active
# → docs/reference/cli.md#cli-admin-client-list

# Rotate the secret (returns the new secret once)
authserver admin client rotate-secret --id $CLIENT_ID
# → docs/reference/cli.md#cli-admin-client-rotate-secret

# Hard-delete with active issuances (forensic only; prefer suspend)
authserver admin client delete --id $CLIENT_ID --force
```

**Verify**: `authserver admin client list` no longer shows the deleted row; the audit log carries `client.deleted` (canonical: `internal/domain/audit/entity.go:87`).

---

## Recipe: users

Create, list, disable, force-logout. CLI catalog: [`authserver admin user`](../../reference/cli.md#cli-admin-user).

```bash
authserver admin user create --email ops@example.com --password "$(openssl rand -hex 16)" \
  --name "Ops Bot" --role admin
# → docs/reference/cli.md#cli-admin-user-create

# Revoke every token family this user owns; prints the family count
authserver admin user force-logout --id $USER_ID
# → docs/reference/cli.md#cli-admin-user-force-logout
```

**Verify**: `audit_events` row with action `user.force_logout` (canonical: `internal/domain/audit/entity.go:93`).

---

## Recipe: resources (Mint + Broker)

Resources are the unified entry point for both Mint-backed (AS-minted JWTs) and Broker-backed (upstream vended tokens) targets. CLI catalog: [`authserver admin resource`](../../reference/cli.md#cli-admin-resource).

```bash
# Register a Mint resource; --scopes is repeatable name|upstream|description
authserver admin resource create --slug my-mcp --backend-kind mint \
  --uri http://mcp:3000/ --display-name "My MCP" \
  --scopes 'mcp:echo||Echo a message'
# → docs/reference/cli.md#cli-admin-resource-create

# Register a Broker resource against an upstream provider
authserver admin resource create --slug github-repo --backend-kind broker \
  --uri https://api.github.com --broker-provider github \
  --scopes 'repo|repo|GitHub repo read/write'

# Patch one field (PATCH semantics — omitted flags untouched)
authserver admin resource update --id $RES_ID --display-name "New name"
# → docs/reference/cli.md#cli-admin-resource-update
```

The `uri` is **audience-bound** — a one-character mismatch with the MCP's Protected Resource Metadata silently breaks every token. See [Connect an MCP Server → Resource URI mismatch](../integrate/connect-mcp-server.md#resource-uri-mismatch).

### Runtime client-id allowlist

Atomic add/remove on `policy.runtime.client_ids` — the N:N linkage between OAuth clients and the resources they may **act as** at `/oauth/token` (e.g. for `client_credentials`).

```bash
authserver admin resource runtime-client list --slug my-mcp
authserver admin resource runtime-client add  --slug my-mcp --client-id $CLIENT_ID
authserver admin resource runtime-client remove --slug my-mcp --client-id $CLIENT_ID
# → docs/reference/cli.md#cli-admin-resource-runtime-client
```

Both are idempotent. See [Runtime client binding](../integrate/runtime-client-binding.md) for the full walk-through.

---

## Recipe: broker providers

Manage upstream OAuth / API-key / service-account vendors. CLI catalog: [`authserver admin provider`](../../reference/cli.md#cli-admin-provider).

```bash
# config-data is a path to a JSON file (≤ 1 MB)
authserver admin provider create --slug github --display-name "GitHub" \
  --protocol oauth --config-data ./github-provider.json
# → docs/reference/cli.md#cli-admin-provider-create

# Delete returns 409 if any resource still references the provider
authserver admin provider delete --id $PROV_ID
```

`github-provider.json` carries `client_secret_ref` (the **name** of the env var holding the secret) — never the secret value itself.

---

## Recipe: fronting links

Operator-declared `(source, target)` pairs that authorize a fronted-path exchange against the target when the subject token was minted for the source. Used by the MCP-Gateway-as-Broker topology. CLI catalog: [`authserver admin fronting`](../../reference/cli.md#cli-admin-fronting).

```bash
# Compact scope-map: source:target[+target2],source2:target3
authserver admin fronting create --source gateway-mcp --target github-repo \
  --scope-map 'read:repo+org,write:repo' --dry-run
# → docs/reference/cli.md#cli-admin-fronting-create

authserver admin fronting list --source gateway-mcp
```

`--dry-run` validates against the service layer (cycle detection, scope coverage) without persisting — wire this into CI. See [Topologies → MCP Gateway (Broker)](../../topologies/mcp-gateway-broker.md).

---

## Recipe: grants admin (consent + broker)

Read and revoke individual `consent_grants` and `broker_grants` rows. CLI catalog: [`authserver admin grant`](../../reference/cli.md#cli-admin-grant).

```bash
# Returns active AND revoked rows (full history)
authserver admin grant list-user-grants --user $USER_ID
# → docs/reference/cli.md#cli-admin-grant-list-user-grants

# Cascades onto live Mint issuances for (user, client, resource)
authserver admin grant revoke-consent --id $GRANT_ID
# → docs/reference/cli.md#cli-admin-grant-revoke-consent

# Forensic-only — already-vended upstream tokens are not AS-revocable
authserver admin grant revoke-broker --id $GRANT_ID
```

The consent-revoke cascade and the revocation are not atomic; the audit row records `cascade=failed` if the issuance cascade fails. Alert on that.

---

## Recipe: issuance admin

Inspect and revoke individual minted tokens. CLI catalog: [`authserver admin issuance`](../../reference/cli.md#cli-admin-issuance).

```bash
# At least one of --user / --client / --resource / --jti is required
authserver admin issuance list --user $USER_ID --since 24h --limit 500
# → docs/reference/cli.md#cli-admin-issuance-list

authserver admin issuance revoke --id $ISSUANCE_ID
# → docs/reference/cli.md#cli-admin-issuance-revoke
```

`--since` accepts Go durations plus `d` / `w` suffixes (default 24h, max 30d). `revoke` is idempotent. Emits `issuance.revoked_admin` (canonical: `internal/domain/audit/entity.go:150`).

---

## Recipe: signing keys

CLI catalog: [`authserver admin key`](../../reference/cli.md#cli-admin-key).

```bash
authserver admin key list           # current + retained
authserver admin key rotate         # new kid, old kid stays for verify
# → docs/reference/cli.md#cli-admin-key-rotate
```

`rotate` emits `key.rotated` and increments `authserver_key_rotation_total`. The full multi-instance procedure lives in [Key rotation](key-rotation.md).

---

## Recipe: audit query (CLI-equivalent)

There is **no `authserver admin audit` CLI subcommand**. Query the REST endpoint with `curl`. HTTP route: [`GET /admin/audit`](../../reference/http-api.md#http-admin-audit-list).

```bash
# Token issuances in the last hour
curl -fsS "http://localhost:9001/admin/audit?action=token.issued&since=$(date -u -v-1H '+%Y-%m-%dT%H:%M:%SZ')" \
  -H "Authorization: Bearer $AUTHPLANE_ADMIN_API_KEY" | jq '.events[] | {created_at, actor_id, client_id, detail}'
```

Full forensic query catalog lives in [Audit & forensics](audit-and-forensics.md).

---

## Recipe: DCR mode

CLI catalog: [`authserver admin dcr`](../../reference/cli.md#cli-admin-dcr).

```bash
authserver admin dcr get
authserver admin dcr set --mode admin_only      # or open / approved_redirects
# → docs/reference/cli.md#cli-admin-dcr-set
```

`dcr set` persists; live updates without restart go through `PATCH /admin/settings/dcr`.

---

## Verify (every recipe)

After any mutation:

1. Confirm the resource state: re-run the corresponding `list` / `get`.
2. Confirm the audit row: `GET /admin/audit?action=<expected-action>&limit=5`.
3. (Production) confirm the metric: e.g. `authserver_active_clients` after `client.deleted`. Canonical names in `internal/observability/metrics.go`.

---

## What can go wrong

| Symptom | Likely cause | Fix |
|---|---|---|
| `401 Unauthorized` on every call | Wrong / missing API key | Check `AUTHPLANE_ADMIN_API_KEY` matches `admin.api_key`. |
| `409 Conflict` on `resource create` | Slug already exists; YAML-seeded row | Pick a new slug, or `update` the existing row. |
| `409 Conflict` on `provider delete` | A resource still references the provider | Delete the dependent resources first. |
| `400 Bad Request` on `runtime-client add` | Referenced `client_id` does not exist | Create the client first. |
| `revoke-consent` succeeds but tokens still work | Cascade onto live Mint issuances failed; row revoked, in-flight tokens linger until `exp` | Check the audit `detail` for `cascade=failed`; revoke individual issuances with `admin issuance revoke`. |
| `429 Too Many Requests` | Admin rate limit hit | Back off; tune `admin.requests_per_second` in [`docs/reference/configuration.md`](../../reference/configuration.md). |

---

## Runbook

| Day-2 task | Recipe | Frequency |
|---|---|---|
| Rotate one client secret | `admin client rotate-secret` | On suspected client-credential leak |
| Suspend then revoke a misbehaving client | `admin client …` + suspend → revoke | Incident response |
| Force-logout a compromised user | `admin user force-logout` | Within 5 min of detection |
| Rotate signing keys | `admin key rotate` | Scheduled (≤ 90 days) or on key-compromise |
| Audit a specific user's grants | `admin grant list-user-grants` | Per support ticket / GDPR request |
| Revoke a single token | `admin issuance revoke` | Forensic |

---

## See also

- [Admin UI tour](admin-ui-tour.md) — same operations, click-driven.
- [Audit & forensics](audit-and-forensics.md) — read the trail you just produced.
- [Incident runbook](incident-runbook.md) — when something is on fire.
- [`docs/reference/cli.md`](../../reference/cli.md) — generated reference for every flag.
- [`docs/reference/http-api.md`](../../reference/http-api.md) — generated reference for every route.
