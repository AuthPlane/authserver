# Test XAA End-to-End with the Okta `xaa.dev` Playground

*Context: this is part of [Guides — Federation](README.md). Start with the primer if you haven't.*

**Audience:** Builder or Operator who wants to prove the full XAA path works before going through a real Okta or Entra ID tenant. The public [`xaa.dev`](https://xaa.dev) playground signs real ID-JAG assertions using Okta's stack — when Authplane accepts one and mints an access token, every code path is exercised: JWKS fetch, `typ`/`iss`/`aud`/`jti` validation, subject mapping, policy enforcement, scope intersection, resource check, and `at+jwt` issuance with the `act` chain.

This recipe does **not** require an Okta tenant.

## What you'll achieve in 30 minutes

- ngrok pointed at your local Authplane, so `xaa.dev` can reach it over HTTPS.
- Authplane configured with XAA, a registered trusted IdP (`idp.xaa.dev`), a client, a policy, and a resource.
- `xaa.dev`'s "Run XAA flow" button completing through step 3 (JWT Bearer Grant → access_token from your authserver).

## Prereqs

- Authplane in this repo runnable locally: `go run ./cmd/authserver serve`.
- [ngrok](https://ngrok.com) (free tier is fine) — `xaa.dev` must reach you over HTTPS.
- `openssl`, `curl`, `jq`, Python 3.
- Concept context: [glossary — XAA](../../concepts/glossary.md#glossary-xaa), [glossary — act-claim](../../concepts/glossary.md#glossary-act-claim). For policy/mapping background, see [Enterprise-Managed Authorization (XAA)](enterprise-managed-auth-xaa.md).

## Flow overview

```
┌─────────┐   1. login   ┌────────────┐  2. token-exchange  ┌────────────┐
│  user   │─────────────▶│ idp.xaa.dev│────────────────────▶│ idp.xaa.dev│
│ browser │              │  (OIDC IdP)│                     │ (/token)   │
└─────────┘◀─ id_token ──└────────────┘◀── id-jag ──────────└────────────┘
                                                                   │
                       3. jwt-bearer grant (id-jag + client creds) │
                                                                   ▼
                                                         ┌────────────────┐
                                                         │  authserver    │
                                                         │ (your machine, │
                                                         │   via ngrok)   │
                                                         └────────────────┘
                                                                   │
                                       ── access_token (at+jwt) ──┘
```

Step **3** is the one we're testing — Authplane consumes the id-jag and mints the access token.

## Steps

### 1. Start ngrok and capture the public URL

```bash
ngrok http 9000 > /tmp/ngrok.log 2>&1 &
until curl -s http://127.0.0.1:4040/api/tunnels | grep -q public_url; do sleep 1; done
PUBLIC_URL=$(curl -s http://127.0.0.1:4040/api/tunnels \
  | python3 -c "import json,sys;print(next(t['public_url'] for t in json.load(sys.stdin)['tunnels'] if t['public_url'].startswith('https')))")
echo "$PUBLIC_URL"
```

Keep this URL — the free tier rotates it on every restart.

### 2. Generate secrets and prepare config

```bash
ADMIN_KEY=$(openssl rand -hex 24)
SESSION_SECRET=$(openssl rand -hex 32)
ENC_KEY=$(openssl rand -hex 32)
```

Write `/tmp/authserver-xaa.yaml` with the essentials (full template at the end of this recipe):

- `server.issuer` = your ngrok URL.
- `server.allowed_origins` includes `https://xaa.dev` and `https://app.xaa.dev` (CORS — xaa.dev's browser code reads `/oauth/token` responses).
- `session.secret` set; `session.secure: true` (required when issuer ≠ localhost).
- `xaa.enabled: true`.
- `dpop.enabled: true` (downstream token-exchange uses it; harmless here).

### 3. Start authserver

```bash
# Verified against docs/reference/cli.md#cli-serve
AUTHPLANE_ENCRYPTION_KEY="$ENC_KEY" \
  go run ./cmd/authserver serve --config /tmp/authserver-xaa.yaml \
  > /tmp/authserver.log 2>&1 &
```

Verify discovery is reachable and advertises jwt-bearer:

```bash
# Verified against docs/reference/http-api.md#http-public-well-known-oauth-authorization-server
curl -s $PUBLIC_URL/.well-known/oauth-authorization-server \
  | jq '{issuer, grant_types_supported}'
# Expect: issuer == $PUBLIC_URL and grant_types_supported contains
#   "urn:ietf:params:oauth:grant-type:jwt-bearer".
```

### 4. Register `idp.xaa.dev` as a trusted IdP

```bash
# Verified against docs/reference/http-api.md#http-admin-idps-create
IDP_ID=$(curl -s -X POST http://localhost:9001/admin/idps \
  -H "Authorization: Bearer $ADMIN_KEY" -H "Content-Type: application/json" \
  -d '{"name":"xaa-dev","issuer":"https://idp.xaa.dev","jwks_uri":"https://idp.xaa.dev/jwks"}' \
  | jq -r .id)
echo "$IDP_ID"
```

### 5. Register a client via DCR

xaa.dev authenticates with `client_secret_post`. Use Dynamic Client Registration:

```bash
# Verified against docs/reference/http-api.md#http-public-oauth-register
DCR=$(curl -s -X POST http://localhost:9000/oauth/register \
  -H "Content-Type: application/json" \
  -d '{
    "client_name":"xaa-test",
    "token_endpoint_auth_method":"client_secret_post",
    "grant_types":["urn:ietf:params:oauth:grant-type:jwt-bearer"],
    "redirect_uris":[]
  }')
CLIENT_ID=$(echo "$DCR" | jq -r .client_id)
CLIENT_SECRET=$(echo "$DCR" | jq -r .client_secret)
```

DCR does not set `scope` by default — and the jwt-bearer handler computes `effectiveScopes = intersect(clientScopes, assertionScopes, requestScopes)`, so an empty client scope yields `invalid_scope` at runtime. Patch the client:

```bash
# Verified against docs/reference/http-api.md#http-admin-clients-id-update
curl -s -X PATCH http://localhost:9001/admin/clients/$CLIENT_ID \
  -H "Authorization: Bearer $ADMIN_KEY" -H "Content-Type: application/json" \
  -d '{"scope":"read write openid profile email"}'
```

### 6. Create an XAA policy

```bash
# Verified against docs/reference/http-api.md#http-admin-xaa-policies-create
curl -s -X POST http://localhost:9001/admin/xaa/policies \
  -H "Authorization: Bearer $ADMIN_KEY" -H "Content-Type: application/json" \
  -d "{
    \"name\":\"xaa-test-policy\",
    \"idp_id\":\"$IDP_ID\",
    \"client_ids\":[\"$CLIENT_ID\"],
    \"scopes\":[\"read\",\"write\",\"openid\",\"profile\",\"email\"]
  }"
```

Field names are exactly `client_ids` and `scopes` (not `allowed_*`). Unknown fields are silently dropped.

### 7. Register a resource server

The id-jag from xaa.dev carries a `resource` claim equal to your issuer URL. The jwt-bearer handler resolves the resource via the unified registry — unregistered = `invalid_resource`.

```bash
# Verified against docs/reference/http-api.md#http-admin-resources-create
curl -s -X POST http://localhost:9001/admin/resources \
  -H "Authorization: Bearer $ADMIN_KEY" -H "Content-Type: application/json" \
  -d "{
    \"slug\":\"xaa-test-rs\",
    \"display_name\":\"xaa test rs\",
    \"uri\":\"$PUBLIC_URL\",
    \"backend_kind\":\"mint\",
    \"scopes\":[{\"name\":\"read\"},{\"name\":\"write\"}],
    \"policy\":{\"exchange\":{\"allowed_client_ids\":[\"$CLIENT_ID\"]}}
  }"
```

### 8. Register a custom resource on `xaa.dev`

1. Open `https://xaa.dev/developer/test-resource` → **Register custom resource**.
2. **Basic info** — Resource Type: REST API; Resource Identifier URL: your ngrok URL (no trailing slash).
3. **Auth Server** — choose **Use My Own Auth Server**.
   - Token Endpoint: `<PUBLIC_URL>/oauth/token`
   - Auth Server URL: `<PUBLIC_URL>`
   - Target Client ID / Secret: from step 5.
4. **Scopes & Config** — add `read` and `write`. Health Check: `<PUBLIC_URL>/health` → click **Check** → expect green. API Endpoints: `GET /health`, no scope.
5. **Review** → **Register**.

### 9. Run the flow

Click **Run XAA flow** on xaa.dev. You should see four steps complete:

1. Login → id_token from idp.xaa.dev
2. Token Exchange → id-jag (typ `oauth-id-jag+jwt`, aud = your issuer)
3. **JWT Bearer Grant → access_token from your authserver** ← this is the assertion
4. API call → `GET /health` with the Bearer token

## Verify

```bash
# Verified against docs/reference/http-api.md#http-public-oauth-introspect
ACCESS_TOKEN=$(jq -r .access_token /tmp/last-token.json 2>/dev/null || echo "<paste from xaa.dev step 3>")
curl -s -X POST $PUBLIC_URL/oauth/introspect \
  -d "token=$ACCESS_TOKEN" \
  -d "client_id=$CLIENT_ID" -d "client_secret=$CLIENT_SECRET" | jq '{active, sub, act, scope}'
# Expect:
#   "active": true,
#   "sub": "https://idp.xaa.dev:<idp-subject>",
#   "act": { "sub": "https://idp.xaa.dev" },
#   "scope": "read write"
```

`act.sub` carries the delegation chain back to the IdP — the audit signal the resource server should key on.

### Step 4 may fail — that's fine

The browser-side `GET /health` with `Authorization: Bearer …` may report `TypeError: Failed to fetch`. Authplane scopes CORS to `/oauth/*`, discovery, and revoke on purpose (`api/shared/security.go:50`); `/health` is not a browser endpoint. To make step 4 green, terminate Bearer tokens in a real resource server — Authplane's role here ends at step 3.

## What can go wrong

| `reason=` (from `/tmp/authserver.log`) | Root cause | Fix |
|----------------------------------------|------------|-----|
| `invalid_scope` | Client has empty `scope` | Patch client with allowed scope list (step 5 patch). |
| `invalid_resource` | No resource server registered for the id-jag's `resource` claim | Register the resource (step 7) with `uri == $PUBLIC_URL`. |
| `replay` | Same `jti` reused (you re-clicked too fast) | Re-run the flow; jti is single-use. |
| `client_mismatch` | `client_id` claim in id-jag ≠ authenticated client | Ensure target client_id on xaa.dev equals the DCR-registered `client_id` from step 5. |
| `untrusted_issuer` | IdP not registered, or issuer URL mismatch | Confirm step 4's `issuer` is exactly `https://idp.xaa.dev`. |
| CORS preflight failure at `/oauth/token` | `server.allowed_origins` missing | Add `https://xaa.dev` and `https://app.xaa.dev`. |
| ngrok URL changed mid-flow | Free-tier ngrok rotates on restart | Re-write the config with the new `PUBLIC_URL`, restart authserver, re-register the resource on xaa.dev. |

## Inspecting what happened

- ngrok UI at `http://127.0.0.1:4040` — every inbound request with full body.
- `/tmp/authserver.log` — structured JSON, including `audit jwt_bearer.denied reason=…` lines.

## Reference config

```yaml
server: { issuer: "<PUBLIC_URL>", address: ":9000", allowed_origins: ["https://xaa.dev", "https://app.xaa.dev"] }
storage: { driver: sqlite, sqlite: { path: "/tmp/xaa-authserver.db", wal: true } }
signing: { algorithm: ES256, key_path: "/tmp/xaa-authserver-keys" }
dcr: { mode: open, rate_limit: 10, rate_limit_burst: 20, default_token_expiry: 24h, default_refresh_expiry: 168h }
session: { cookie_name: session, max_age: 24h, secret: "<SESSION_SECRET>", secure: true, same_site: lax }
admin: { enabled: true, address: ":9001", api_key: "<ADMIN_KEY>" }
data_encryption: { driver: aes_master, aes_master: { key_env: AUTHPLANE_ENCRYPTION_KEY } }
dpop: { enabled: true, proof_lifetime: 60s, nonce_ttl: 60s }
token_exchange: { enabled: true, allow_self_exchange: true, max_chain_depth: 4, token_expiry: 1h }
xaa: { enabled: true, token_expiry: 1h, max_assertion_age: 5m, require_resource: false, subject_mode: auto_map, jwks_cache_ttl: 1h }
```

## See also

- [Enterprise-Managed Authorization (XAA)](enterprise-managed-auth-xaa.md) — production-shaped policy / subject-mapping recipe.
- [JWT Bearer grant](jwt-bearer-grant.md) — the wire grant being tested.
- [xaa.dev docs — Bring Your Own Resource](https://xaa.dev/docs/byor-overview)
- [Okta — Set up AI agent token exchange](https://developer.okta.com/docs/guides/ai-agent-token-exchange/-/main/) — for swapping the IdP to a real Okta tenant.
- [Reference → Flow 13 — JWT Bearer / XAA](../../reference/flows.md)
