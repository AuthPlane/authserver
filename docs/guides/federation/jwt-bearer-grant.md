# JWT Bearer Grant — Mint an Authplane Token from an Upstream IdP Assertion

*Context: this is part of [Guides — Federation](README.md). Start with the primer if you haven't.*

**Audience:** Builder of a backend service that already holds a signed identity assertion from an upstream IdP and needs to exchange it for an Authplane access token — no browser, no interactive login. This is the wire-level building block that [Enterprise-Managed Authorization (XAA)](enterprise-managed-auth-xaa.md) is built on. If you want the full policy/mapping workflow, start there instead.

## What you'll achieve in 10 minutes

- A registered Authplane client that accepts `grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer`.
- One trusted IdP registered so Authplane will fetch its JWKS and verify assertion signatures.
- A working `POST /oauth/token` call that returns an `at+jwt` access token.

## Prereqs

- Authplane authserver running with `xaa.enabled: true`. The jwt-bearer endpoint is gated by `cfg.XAA.Enabled` (DI wires the handler iff XAA is on — `cmd/authserver/serve.go:430`). With XAA off, `POST /oauth/token` with `grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer` returns `unsupported_grant_type`. There is **no** separate `AUTHPLANE_JWT_BEARER_ENABLED` env var.
- An admin API key (`admin.api_key`).
- An upstream IdP that can sign assertions you control or can request — Okta, Entra ID, Auth0, an internal CA, or for testing the public [`idp.xaa.dev`](https://xaa.dev) playground.
- Concept context: [glossary — JWT Bearer](../../concepts/glossary.md#glossary-jwt-bearer), [glossary — XAA](../../concepts/glossary.md#glossary-xaa), [Delegation and agent chains](../../concepts/delegation-and-agent-chains.md).

## Steps

### 1. Enable XAA

```yaml
# Verified against docs/reference/configuration.md#config-xaa
xaa:
  enabled: true
  token_expiry: 1h         # access-token TTL
  max_assertion_age: 5m    # max age of the IdP assertion (iat → now)
  subject_mode: auto_map   # or "strict" — see XAA recipe
  require_resource: false
  jwks_cache_ttl: 1h
```

There is no env-var override for these fields — verified against [`docs/reference/env-vars.md`](../../reference/env-vars.md). Configure via YAML only.

### 2. Register the trusted IdP

```bash
# Verified against docs/reference/http-api.md#http-admin-idps-create
curl -s -X POST http://localhost:9001/admin/idps \
  -H "Authorization: Bearer $ADMIN_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Acme Corp Okta",
    "issuer": "https://acme.okta.com",
    "jwks_uri": "https://acme.okta.com/.well-known/jwks.json",
    "audience": "https://auth.example.com"
  }' | jq .
# Save .id from response — this is $IDP_ID.
```

`jwks_uri` is auto-discovered from `{issuer}/.well-known/openid-configuration` if omitted. `audience` defaults to your `server.issuer`.

### 3. Register an Authplane client with the jwt-bearer grant

```bash
# Verified against docs/reference/http-api.md#http-admin-clients-create
curl -s -X POST http://localhost:9001/admin/clients \
  -H "Authorization: Bearer $ADMIN_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "client_name": "enterprise-backend",
    "grant_types": ["urn:ietf:params:oauth:grant-type:jwt-bearer"],
    "token_endpoint_auth_method": "client_secret_post",
    "scope": "tools/query tools/execute"
  }' | jq .
# Save .client_id and .client_secret from response.
```

**Important:** the `scope` field is mandatory if you want the client to obtain any scope at all. The handler computes `effectiveScope = intersect(clientScopes, assertionScopes, requestScope)` (`internal/services/jwt_bearer.go:238-261`); an empty client scope set produces `invalid_scope` at runtime no matter what the assertion or request asks for.

### 4. Mint the assertion at the IdP

The assertion is a JWT signed by the IdP. Required shape (verified against `internal/services/jwt_bearer.go` and the ID-JAG validator in `internal/crypto`):

| Field | Location | Required | Value |
|-------|----------|----------|-------|
| `typ` | header | yes | `oauth-id-jag+jwt` |
| `alg` | header | yes | ES256, RS256, or PS256 |
| `iss` | payload | yes | Must equal the registered IdP's `issuer` |
| `sub` | payload | yes | User identity at the IdP |
| `aud` | payload | yes | Authplane's `server.issuer` URL |
| `exp` | payload | yes | ≤ `max_assertion_age` from now |
| `iat` | payload | yes | Issued-at |
| `jti` | payload | yes | Unique — single-use replay prevention |
| `client_id` | payload | yes | Must match the Authplane client_id in step 3 |
| `scope` | payload | no | Space-separated; acts as an upper bound on issued scope |
| `resource` | payload | no | RFC 8707 target resource URI |

How you produce this assertion depends on your IdP — Okta and Entra ID expose ID-JAG via their cross-app-access products; for internal services you can sign with a JWKS-published key you control.

### 5. Exchange the assertion at the token endpoint

```bash
# Verified against docs/reference/http-api.md#http-public-oauth-token
curl -s -X POST http://localhost:9000/oauth/token \
  -d "grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer" \
  -d "assertion=$ID_JAG_JWT" \
  -d "client_id=$CLIENT_ID" \
  -d "client_secret=$CLIENT_SECRET" \
  -d "scope=tools/query" \
  -d "resource=https://mcp.example.com"
```

Successful response:

```json
{
  "access_token": "eyJ...",
  "token_type": "Bearer",
  "expires_in": 3600,
  "scope": "tools/query"
}
```

No `refresh_token` is issued — the handler does not return one for jwt-bearer (`api/public/oauth/handlers.go:327`). Get a new assertion when the access token expires.

## Verify

```bash
# Verified against docs/reference/http-api.md#http-public-oauth-introspect
curl -s -X POST http://localhost:9000/oauth/introspect \
  -d "token=$ACCESS_TOKEN" \
  -d "client_id=$CLIENT_ID" \
  -d "client_secret=$CLIENT_SECRET" | jq .
# Expect: { "active": true, "scope": "tools/query", "client_id": "…",
#           "sub": "<idp-issuer>:<idp-sub>", "act": {"sub": "<idp-issuer>"}, … }
```

The `act.sub` claim carries the delegation chain back to the IdP — this is the audit signal a resource server should key on. See [Concepts → Delegation and agent chains](../../concepts/delegation-and-agent-chains.md).

## What can go wrong

Denial reasons from `internal/services/jwt_bearer.go` (logged as audit events `jwt_bearer.denied reason=…`):

| Symptom / `reason=` | Likely cause | Fix |
|---------------------|--------------|-----|
| `unsupported_grant_type` from `/oauth/token` | XAA disabled — `xaa.enabled` not true, so the handler is nil-gated (`api/public/oauth/handlers.go:292`) | Set `xaa.enabled: true` in YAML, restart. |
| `invalid_client` | Bad `client_id`/`client_secret`, or `token_endpoint_auth_method` mismatch | Verify the registered method matches how you authenticate (`client_secret_post` vs `client_secret_basic`). |
| `unauthorized_client` | Client is registered but `grant_types` does not include `urn:ietf:params:oauth:grant-type:jwt-bearer` | Patch the client to add the grant. |
| `invalid_assertion` / `untrusted_issuer` | Assertion `iss` does not match any registered IdP, or header missing | Confirm the IdP `issuer` registered in step 2 exactly equals the assertion's `iss` (including trailing slash). |
| `replay` | The same `jti` was used twice | Mint a fresh assertion with a unique `jti` — they are single-use. |
| `client_mismatch` | Assertion `client_id` claim does not equal the authenticated `client_id` | Set the assertion `client_id` to the Authplane client_id from step 3. |
| `invalid_scope` | Intersection of (client scope, assertion scope, request scope) is empty | Patch the client's `scope` to include the requested scope. The client scope is the ceiling for the empty case. |
| `invalid_resource` | The `resource` claim/parameter is not registered in Authplane, or assertion and request resources disagree | Register the resource (`POST /admin/resources`) or align the assertion to the registered URI. |
| `jwks_fetch_failed` | Authplane can't reach the IdP's JWKS URI | Confirm network reachability; force refresh via `POST /admin/idps/{id}/refresh-keys`. |
| `assertion expired` / `clock skew` | `exp` past, or `iat` older than `max_assertion_age` | Reduce assertion lifetime to a few minutes; sync clocks. |

## See also

- [Enterprise-Managed Authorization (XAA)](enterprise-managed-auth-xaa.md) — adds the policy engine, subject mapping, and audit chain on top of this grant.
- [Test XAA end-to-end with Okta playground](xaa-with-okta.md) — reproducible runnable example using `xaa.dev`.
- [Token Exchange grant](../upstream-providers/token-exchange-grant.md) — for narrowing or delegating an existing Authplane token.
- [Reference → Flow 13 — JWT Bearer / XAA](../../reference/flows.md)
- [Concepts → Delegation and agent chains](../../concepts/delegation-and-agent-chains.md) — what `act` means and why it matters.
