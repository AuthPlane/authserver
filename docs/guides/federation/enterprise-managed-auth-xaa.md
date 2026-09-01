# Enterprise-Managed Authorization (XAA) — Per-IdP Policy, Subject Mapping, Audit Chains

*Context: this is part of [Guides — Federation](README.md). Start with the primer if you haven't.*

**Audience:** Operator + Builder rolling out RFC 7523 JWT Bearer at scale for a corporate IdP (Okta, Microsoft Entra ID, Auth0). This recipe layers the AuthPlane XAA workflow — per-IdP policy, subject mapping, audited `act` delegation chains — on top of the raw [JWT Bearer grant](jwt-bearer-grant.md).

## What you'll achieve in 20 minutes

- A trusted IdP registered and JWKS-cached, with a named policy that constrains which clients, scopes, and resources its assertions can mint.
- Subject mapping mode chosen (`auto_map` for JIT, `strict` for explicit allowlist).
- A working assertion-to-token exchange that emits an `at+jwt` with an `act` chain back to the IdP.

## Prereqs

- Authplane authserver running with `xaa.enabled: true` and an admin API key. See [JWT Bearer grant](jwt-bearer-grant.md) for the underlying wire setup.
- One or more corporate IdPs that can sign ID-JAG assertions (`typ=oauth-id-jag+jwt`). For Okta/Entra ID this is their Cross-App Access feature; for internal services it's any signer with a JWKS endpoint.
- Concept context: [glossary — XAA](../../concepts/glossary.md#glossary-xaa), [glossary — act-claim](../../concepts/glossary.md#glossary-act-claim), [Identity and federation](../../concepts/identity-and-federation.md), [Delegation and agent chains](../../concepts/delegation-and-agent-chains.md).

## Steps

### 1. Configure XAA

```yaml
# Verified against docs/reference/configuration.md#config-xaa
xaa:
  enabled: true
  token_expiry: 1h
  max_assertion_age: 5m
  require_resource: false      # set true to reject exchanges that name no resource
  subject_mode: auto_map       # or "strict"
  jwks_cache_ttl: 1h
```

No env-var overrides exist for `xaa.*` — YAML only (verified against [`docs/reference/env-vars.md`](../../reference/env-vars.md)).

### 2. Register each trusted IdP

```bash
# Verified against docs/reference/http-api.md#http-admin-idps-create
curl -s -X POST http://localhost:9001/admin/idps \
  -H "Authorization: Bearer $ADMIN_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Acme Okta (prod)",
    "issuer": "https://acme.okta.com",
    "jwks_uri": "https://acme.okta.com/.well-known/jwks.json",
    "audience": "https://auth.example.com"
  }' | jq -r .id
# → IDP_ID
```

`jwks_uri` is auto-discovered from `{issuer}/.well-known/openid-configuration` if omitted; `audience` defaults to your `server.issuer`. List and manage IdPs:

```bash
# Verified against docs/reference/http-api.md#http-admin-idps-list
curl -s http://localhost:9001/admin/idps -H "Authorization: Bearer $ADMIN_API_KEY" | jq .

# Force refresh cached JWKS (after IdP key rotation)
# Verified against docs/reference/http-api.md#http-admin-idps-id-refresh-keys
curl -s -X POST http://localhost:9001/admin/idps/$IDP_ID/refresh-keys \
  -H "Authorization: Bearer $ADMIN_API_KEY"

# Disable an IdP without deleting (sets enabled: false)
# Verified against docs/reference/http-api.md#http-admin-idps-id-update
curl -s -X PUT http://localhost:9001/admin/idps/$IDP_ID \
  -H "Authorization: Bearer $ADMIN_API_KEY" -H "Content-Type: application/json" \
  -d '{"enabled": false}'
```

### 3. Define an XAA policy

A policy narrows what assertions from a given IdP can mint. The effective scope at token time is the **intersection** of (client scope, assertion scope, request scope, policy scope). The policy's `scopes` is the operator's hard ceiling, independent of the IdP's claim.

```bash
# Verified against docs/reference/http-api.md#http-admin-xaa-policies-create
curl -s -X POST http://localhost:9001/admin/xaa/policies \
  -H "Authorization: Bearer $ADMIN_API_KEY" \
  -H "Content-Type: application/json" \
  -d "{
    \"name\": \"acme-prod-agents\",
    \"idp_id\": \"$IDP_ID\",
    \"client_ids\": [\"mcp-agent-prod\"],
    \"scopes\": [\"tools/query\", \"tools/execute\"],
    \"resources\": [\"https://mcp.example.com\"]
  }" | jq .
```

| Field | Required | Behavior |
|-------|----------|----------|
| `name` | yes | Human-readable label |
| `idp_id` | yes | Which trusted IdP this policy applies to |
| `client_ids` | no | If set, restricts to these client IDs. Empty = all clients. |
| `scopes` | no | Maximum scope ceiling for this IdP+client combo. Empty = no additional narrowing. |
| `resources` | no | Allowed resource URIs. Empty = any resource registered in Authplane. |

The admin API silently drops unknown fields. Field names are exactly `client_ids`, `scopes`, `resources` (not `allowed_*`).

### 4. Choose a subject mode

The `sub` claim on the issued access token depends on `xaa.subject_mode` and whether a mapping exists:

- **`auto_map`** (default) — any subject from a trusted IdP is accepted. Token `sub` defaults to `{issuer}:{idp_subject}`. If an explicit mapping exists, it overrides.
- **`strict`** — only subjects with an explicit mapping are accepted. Unmapped subjects get `access_denied`.

Create an explicit mapping (works in both modes):

```bash
# Verified against docs/reference/http-api.md#http-admin-xaa-subject-mappings-create
curl -s -X POST http://localhost:9001/admin/xaa/subject-mappings \
  -H "Authorization: Bearer $ADMIN_API_KEY" \
  -H "Content-Type: application/json" \
  -d "{
    \"idp_id\": \"$IDP_ID\",
    \"idp_subject\": \"alice@acme.com\",
    \"local_user_id\": \"usr_local_alice\"
  }" | jq .
```

When a mapping exists, the token's `sub` is set to `local_user_id` instead of the federated `{issuer}:{idp_subject}` format.

### 5. Register the client and resource

Same as in the [JWT Bearer grant](jwt-bearer-grant.md#3-register-an-authplane-client-with-the-jwt-bearer-grant) recipe. The client needs the jwt-bearer grant type and a non-empty `scope`; the resource URI must be registered via `POST /admin/resources` if the assertion or request will carry a `resource` parameter.

### 6. Exchange the assertion

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

For the assertion's required JWT shape (`typ=oauth-id-jag+jwt`, claims, expiry rules), see [JWT Bearer grant — Step 4](jwt-bearer-grant.md#4-mint-the-assertion-at-the-idp).

### 7. (Optional) DPoP-bind the issued token

Include a `DPoP` header on the token request and the issued token will have `token_type: DPoP` and a `cnf.jkt` claim binding it to the client's key:

```bash
# Verified against docs/reference/http-api.md#http-public-oauth-token (DPoP header)
curl -s -X POST http://localhost:9000/oauth/token \
  -H "DPoP: $DPOP_PROOF" \
  -d "grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer" \
  -d "assertion=$ID_JAG_JWT" \
  -d "client_id=$CLIENT_ID" \
  -d "client_secret=$CLIENT_SECRET" \
  -d "scope=tools/query"
```

## Verify

```bash
# Verified against docs/reference/http-api.md#http-public-oauth-introspect
curl -s -X POST http://localhost:9000/oauth/introspect \
  -d "token=$ACCESS_TOKEN" \
  -d "client_id=$CLIENT_ID" \
  -d "client_secret=$CLIENT_SECRET" | jq '{active, sub, act, scope, client_id}'
# Expect:
# {
#   "active": true,
#   "sub": "https://acme.okta.com:alice@acme.com",   // or local user id if mapped
#   "act": { "sub": "https://acme.okta.com" },        // delegation chain back to IdP
#   "scope": "tools/query",
#   "client_id": "mcp-agent-prod"
# }
```

The `act.sub` claim is the auditable XAA signal — a resource server should log it on every request. See [`glossary-act-claim`](../../concepts/glossary.md#glossary-act-claim).

## What can go wrong

Denial reasons emitted by `internal/services/jwt_bearer.go` and the XAA policy engine — surfaced as `audit jwt_bearer.denied reason=…` log lines and OAuth error responses.

| Symptom / `reason=` | Likely cause | Fix |
|---------------------|--------------|-----|
| `unsupported_grant_type` | `xaa.enabled` is false; handler not wired | Set `xaa.enabled: true` and restart. |
| `untrusted_issuer` | Assertion `iss` does not match any `POST /admin/idps` entry | Re-check the issuer URL on both sides — trailing slashes count. |
| `idp_disabled` | IdP is registered but `enabled=false` | `PUT /admin/idps/{id}` with `{"enabled": true}`. |
| `jwks_fetch_failed` | Authplane cannot fetch the IdP's JWKS URI (network, DNS, TLS) | Verify reachability; force refresh with `POST /admin/idps/{id}/refresh-keys`. |
| `replay` | Same `jti` reused | jti is single-use; mint a new assertion. |
| `client_mismatch` | Assertion's `client_id` claim ≠ authenticated client | Align them. |
| `invalid_scope` | Intersection of client/assertion/request/policy scopes is empty | Patch the client's `scope`, widen the policy `scopes`, or narrow the request. |
| `invalid_resource` | Resource not registered, or assertion/request resources disagree | Register the resource (`POST /admin/resources`); align the `resource` claim. An unregistered resource is detected after the `jti` is consumed, so the retry needs a fresh assertion. |
| `resource_required` | `xaa.require_resource: true` and neither the assertion nor the request named a resource. Returned as `400 invalid_target`. | Send `resource=<registered URI>` on the token request, or mint the assertion with a `resource` claim. The refused assertion is not spent; resend it with the resource added. |
| `policy_denied` | XAA policy did not match (wrong `client_id`, resource, or all scopes filtered out) | List policies (`GET /admin/xaa/policies?idp_id=...`); confirm one matches the (idp, client, scope, resource) tuple. |
| `access_denied` in `strict` mode | No subject mapping exists for the IdP's subject | Create an explicit mapping (Step 4) or switch `subject_mode: auto_map`. |

## Managing policies, mappings, IdPs

```bash
# List policies for a given IdP — verified against docs/reference/http-api.md#http-admin-xaa-policies-list
curl -s "http://localhost:9001/admin/xaa/policies?idp_id=$IDP_ID" \
  -H "Authorization: Bearer $ADMIN_API_KEY" | jq .

# Update a policy — verified against docs/reference/http-api.md#http-admin-xaa-policies-id-update
curl -s -X PUT http://localhost:9001/admin/xaa/policies/$POLICY_ID \
  -H "Authorization: Bearer $ADMIN_API_KEY" -H "Content-Type: application/json" \
  -d '{"scopes": ["tools/query"], "enabled": false}'

# List subject mappings — verified against docs/reference/http-api.md#http-admin-xaa-subject-mappings-list
curl -s "http://localhost:9001/admin/xaa/subject-mappings?idp_id=$IDP_ID" \
  -H "Authorization: Bearer $ADMIN_API_KEY" | jq .

# Delete a mapping — verified against docs/reference/http-api.md#http-admin-xaa-subject-mappings-id-delete
curl -s -X DELETE http://localhost:9001/admin/xaa/subject-mappings/$MAPPING_ID \
  -H "Authorization: Bearer $ADMIN_API_KEY"
```

## Discovery

When XAA is enabled, the AS metadata at `/.well-known/oauth-authorization-server` advertises `urn:ietf:params:oauth:grant-type:jwt-bearer` in `grant_types_supported`. Confirm:

```bash
# Verified against docs/reference/http-api.md#http-public-well-known-oauth-authorization-server
curl -s https://auth.example.com/.well-known/oauth-authorization-server \
  | jq '.grant_types_supported | map(select(contains("jwt-bearer")))'
# Expect: [ "urn:ietf:params:oauth:grant-type:jwt-bearer" ]
```

## See also

- [Test XAA end-to-end with Okta playground](xaa-with-okta.md) — runnable walkthrough against `xaa.dev`. (Example pending tier-04 broker for an in-repo runnable.)
- [JWT Bearer grant](jwt-bearer-grant.md) — the underlying wire grant without policy or mapping.
- [Reference → Flow 13 — JWT Bearer / XAA](../../reference/flows.md)
- [Topology → Enterprise XAA](../../topologies/enterprise-xaa.md) — production deployment shape.
- [Concepts → Delegation and agent chains](../../concepts/delegation-and-agent-chains.md) — `act` semantics.
