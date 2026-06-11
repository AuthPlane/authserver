# Token Exchange grant — Authplane operator recipe

*Context: part of [Guides — Upstream Providers](README.md). The Token Exchange grant (RFC 8693) is the wire mechanism behind brokered upstream vends and agent-to-agent delegation. For the brokered-vend recipe end-to-end, see [Connecting upstream providers](connecting-providers.md). For the concept (delegation chains, impersonation vs delegation), see [Delegation and agent chains](../../concepts/delegation-and-agent-chains.md).*

## What you'll achieve in ~15 minutes

- Enable `grant_type=urn:ietf:params:oauth:grant-type:token-exchange` on the token endpoint
- Tune the operator-facing knobs: `max_chain_depth`, `token_expiry`, `allow_self_exchange`
- Pick the right exchange shape for your scenario — brokered vend, agent-to-agent delegation, scope narrowing, or service-account-user (bot pattern)
- Diagnose the most common rejection codes

## Prereqs

- Authplane running with [encryption-at-rest configured](../deploy/configuration.md) — required even for non-broker exchanges because broker grants are part of the same `data_encryption` perimeter.
- An admin API key (`AUTHPLANE_ADMIN_API_KEY`) — see [Operate → Admin CLI & API](../operate/admin-cli.md).
- Concept context: [Token Exchange](../../concepts/glossary.md#glossary-token-exchange), [`act` claim](../../concepts/glossary.md#glossary-act-claim), [Broker backend](../../concepts/glossary.md#glossary-broker-backend), [Mint backend](../../concepts/glossary.md#glossary-mint-backend).

## Step 1: Enable the grant globally

```yaml
token_exchange:
  enabled: true
  max_chain_depth: 4
  token_expiry: 1h
  allow_self_exchange: false   # set true only if a client must narrow its own tokens
```

| Field | Type | Required | Meaning |
|---|---|---|---|
| `enabled` | bool | yes | When `false`, every exchange returns `unsupported_grant_type`. |
| `max_chain_depth` | int (1–10) | yes (when enabled) | Max nesting of the [`act`](../../concepts/glossary.md#glossary-act-claim) chain. Start at 3–4; raise only on demand. |
| `token_expiry` | duration | yes (when enabled) | Lifetime of exchanged tokens. Keep short (`15m`–`1h`). |
| `allow_self_exchange` | bool | no (default `false`) | Lets a client exchange a token it itself was issued for one with narrower scope. |

Equivalent env vars: `AUTHPLANE_TOKEN_EXCHANGE_ENABLED`, `AUTHPLANE_TOKEN_EXCHANGE_MAX_CHAIN_DEPTH`, `AUTHPLANE_TOKEN_EXCHANGE_TOKEN_EXPIRY`, `AUTHPLANE_TOKEN_EXCHANGE_ALLOW_SELF_EXCHANGE`. See [`docs/reference/env-vars.md`](../../reference/env-vars.md).

## Step 2: Register the acting client with the token-exchange grant type

Confidential client only — public clients cannot perform token exchange. Verified against [`POST /oauth/register`](../../reference/http-api.md#http-public-oauth-register):

```bash
curl -X POST http://localhost:9000/oauth/register \
  -H "Content-Type: application/json" \
  -d '{
    "client_name": "MCP Server (prod)",
    "redirect_uris": ["http://localhost:9999/callback"],
    "grant_types": ["urn:ietf:params:oauth:grant-type:token-exchange"],
    "token_endpoint_auth_method": "client_secret_post"
  }'
```

If you already registered the client, add the grant type with `PATCH /admin/clients/{id}` ([anchor](../../reference/http-api.md#http-admin-clients-id-update)) or `authserver admin client update --grant-types …` ([anchor](../../reference/cli.md#cli-admin-client-update)).

## Step 3: Gate the resource with `policy.exchange.allowed_client_ids`

Per-resource ACL. Empty list means "any consented client may exchange against this resource". Set it explicitly to lock down which acting clients can vend each resource. Verified against [`POST /admin/resources/{slug}/policy/exchange/allowed-clients`](../../reference/http-api.md#http-admin-resources-slug-policy-exchange-allowed-clients-create):

```bash
curl -X POST "http://localhost:9001/admin/resources/github/policy/exchange/allowed-clients" \
  -H "Authorization: Bearer $AUTHPLANE_ADMIN_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{ "client_id": "mcp-server-prod" }'
```

> Order of evaluation when an exchange arrives: (1) self-exchange — if `allow_self_exchange: true` AND the acting `client_id` equals the subject token's `client_id`, allow. (2) `may_act` claim — if the subject token carries `may_act.sub=<acting client_id>` (set by the original issuer), allow. (3) `policy.exchange.allowed_client_ids` — empty or contains the acting client. For Broker resources, the three-bound consent check (`consent_grants` + `broker_grants`) is then applied. If none of (1)/(2)/(3) pass, the response is `access_denied`.

## Scenario A — Brokered vend (MCP server gets a user's upstream token)

This is the most common shape. The MCP server forwards the user's AS-issued access token as `subject_token` and names a Broker resource as `resource=<slug>`. The AS returns the **actual upstream provider token** (e.g. `gho_…`), not an AS-signed JWT. End-to-end recipe is in [Connecting upstream providers](connecting-providers.md); the wire call is verified against [`POST /oauth/token`](../../reference/http-api.md#http-public-oauth-token):

```bash
curl -X POST http://localhost:9000/oauth/token \
  -d "grant_type=urn:ietf:params:oauth:grant-type:token-exchange" \
  -d "subject_token=$USER_ACCESS_TOKEN" \
  -d "subject_token_type=urn:ietf:params:oauth:token-type:access_token" \
  -d "resource=github" \
  -d "scope=repo" \
  -d "client_id=mcp-server-prod" \
  -d "client_secret=$MCP_SERVER_SECRET"
```

## Scenario B — Orchestrator delegates to a sub-agent

The orchestrator has its own token (typically from `client_credentials`). A sub-agent exchanges it for a narrower one, attaching its own credentials as the actor. The result carries `sub=orchestrator`, `client_id=sub-agent-a`, and an [`act`](../../concepts/glossary.md#glossary-act-claim) chain. Verified against [`POST /oauth/token`](../../reference/http-api.md#http-public-oauth-token):

```bash
curl -X POST http://localhost:9000/oauth/token \
  -d "grant_type=urn:ietf:params:oauth:grant-type:token-exchange" \
  -d "subject_token=$ORCHESTRATOR_TOKEN" \
  -d "subject_token_type=urn:ietf:params:oauth:token-type:access_token" \
  -d "actor_token=$SUB_AGENT_TOKEN" \
  -d "actor_token_type=urn:ietf:params:oauth:token-type:access_token" \
  -d "scope=mcp:echo" \
  -d "client_id=sub-agent-a" \
  -d "client_secret=$SUB_AGENT_SECRET"
```

The new outermost `act` hop is stamped with `sub=<acting client_id>` and `actor_type=agent` (if the acting client has `is_agent=true`, otherwise `service`). Inner hops pass through unchanged. Per RFC 8693 §4.1 ¶6, **only the outermost** `act` is authoritative for access-control — inner hops are informational.

Gate this resource with `policy.exchange.allowed_client_ids: ["sub-agent-a"]` so only the intended sub-agent can act.

## Scenario C — Self-exchange (scope narrowing)

A client narrows its own token's scope (e.g. peel off `mcp:admin` before passing the token deeper). Requires `allow_self_exchange: true`.

```bash
curl -X POST http://localhost:9000/oauth/token \
  -d "grant_type=urn:ietf:params:oauth:grant-type:token-exchange" \
  -d "subject_token=$BROAD_TOKEN" \
  -d "subject_token_type=urn:ietf:params:oauth:token-type:access_token" \
  -d "scope=mcp:echo" \
  -d "client_id=$MY_CLIENT_ID" \
  -d "client_secret=$MY_CLIENT_SECRET"
```

The exchanged token's scopes must be a **subset of** (or equal to) the subject token's scopes. Omitting `scope` inherits the full scope set. There is no path to widen scope — that's by design.

## Scenario D — Bot / background service needs upstream-provider access

Naive approach (have the bot present its own `client_credentials` token as `subject_token` against `resource=github`) **does not work and is intentional**. `broker_grants` are keyed on `user_id`; a machine token's `sub` is the bot's `client_id`. The exchange fails with `invalid_grant` regardless of `allow_self_exchange`.

The supported pattern is **service-account user**:

1. Create the service-account user. Verified against [`POST /admin/users`](../../reference/http-api.md#http-admin-users-create):

   ```bash
   curl -X POST http://localhost:9001/admin/users \
     -H "Authorization: Bearer $AUTHPLANE_ADMIN_API_KEY" \
     -H "Content-Type: application/json" \
     -d '{
       "username": "bot-prod",
       "email": "bot-prod@svc.example.com",
       "display_name": "Production deploy bot"
     }'
   ```

   Save the returned `id` — that's the `sub` the bot's tokens will carry.

2. Connect the upstream provider once **as that user**: sign in as `bot-prod` and run `/connect/github?resource=github` exactly like a human would. The `broker_grants` row is now keyed `(user_id=<bot-prod id>, broker_provider_id=github)`.

3. Pick how the bot obtains a user-scoped token:
   - **JWT bearer (recommended)** — a trusted IdP signs a short-lived JWT asserting `sub=<bot-prod id>`; the bot trades it at `/oauth/token` with `grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer`. See [`docs/guides/federation/enterprise-managed-auth-xaa.md`](../federation/enterprise-managed-auth-xaa.md) for assertion construction.
   - **Stored refresh token** — perform `authorization_code` once at deploy time as `bot-prod`; persist the refresh token in the bot's secret store; rotate on the normal cadence. Simpler operationally; the refresh token is a long-lived credential.

4. At runtime the bot calls `/oauth/token` twice — first to get a user-scoped token for `bot-prod`, then to exchange that for the upstream token exactly as in Scenario A.

Revoke with one call: `DELETE /admin/grants/broker/{id}` ([anchor](../../reference/http-api.md#http-admin-grants-broker-id-delete)) or disable the user via `PATCH /admin/users/{id}/disable` ([anchor](../../reference/http-api.md#http-admin-users-id-disable)).

> **RFC 8693 §1.3:** distinguishes *delegation* (actor ≠ subject) from *impersonation* (actor = subject). Authplane supports delegation natively. True impersonation onto a broker grant is not supported by design — the service-account-user pattern is the clean ownership model.

## Verify

After enabling, confirm the grant type is advertised. Verified against [`GET /.well-known/oauth-authorization-server`](../../reference/http-api.md#http-public-well-known-oauth-authorization-server):

```bash
curl -s http://localhost:9000/.well-known/oauth-authorization-server \
  | jq '.grant_types_supported'
```

The list should include `"urn:ietf:params:oauth:grant-type:token-exchange"`.

For Scenario B/C tokens, decode the response and inspect the `act` claim — each hop should be a JSON object with `sub` and `actor_type` (`agent` or `service`).

## What can go wrong

| Symptom | Likely cause | Fix |
|---|---|---|
| `unsupported_grant_type` | Token Exchange is disabled, or the requesting client wasn't registered with the grant type | Set `token_exchange.enabled: true`. Add `"urn:ietf:params:oauth:grant-type:token-exchange"` to the client's `grant_types` (see step 2). |
| `unauthorized_client` | Client exists but doesn't have token-exchange in its `grant_types` | `PATCH /admin/clients/{id}` ([anchor](../../reference/http-api.md#http-admin-clients-id-update)) to add the grant type. |
| `access_denied` | Acting client not allowed for the target resource (Scenario A/B), or all three policy checks failed | Add the acting client to `policy.exchange.allowed_client_ids` (step 3), or leave the list empty to allow any consented client. |
| `invalid_target` | `resource=<slug>` doesn't match a registered resource, or the slug is a Broker resource whose `broker_provider_slug` isn't registered | `GET /admin/resources` ([anchor](../../reference/http-api.md#http-admin-resources-list)) — confirm the slug and the provider link. |
| `invalid_scope` | Requested scope isn't in the subject token's scope (for Mint exchanges), or isn't declared on the resource (for Broker) | You can only narrow scopes, never widen them. For Broker, edit the resource's `scopes[]` catalog. |
| `invalid_grant` | Subject token is expired or revoked; or a bot's `client_credentials` token was used against a Broker resource (Scenario D footgun) | User must re-authenticate. For the bot footgun, switch to the service-account-user pattern (Scenario D). |
| `consent_required` | A required grant is missing. For Broker, one of the three bounds failed; Mint exchanges return this too when no `consent_grants` row covers the requested scopes. See the [Connecting upstream providers troubleshooting table](connecting-providers.md#what-can-go-wrong) and [Broker vs Mint](../../concepts/broker-vs-mint.md) for the `cause=consent_missing` vs `cause=scope_insufficient` split | Open the returned `consent_url`; the AS picks `/connect/{provider}` or `/authorize?resource=...` automatically. |
| `chain_too_deep` | Delegation chain exceeds `max_chain_depth` | Raise the cap, or restructure the topology to fewer hops. |
| `invalid_request: vault vending does not support delegation — omit actor_token` | Passed `actor_token` against a Broker resource | Drop `actor_token` from broker exchanges; delegation is for Mint resources. |

## Security checklist

- All upstream refresh-grants are encrypted at rest (AES-256-GCM or HashiCorp Vault Transit). See [Deploy → HashiCorp Vault Transit](../deploy/hashicorp-vault-transit.md).
- Client authentication is mandatory — only confidential clients (`client_secret`) may exchange. A stolen user token alone is useless without the acting client's credentials.
- Three-bound consent ensures Broker vends only succeed when both the user (consent + broker grant) and the operator (per-resource policy) have authorized the action.
- Subject tokens are checked for revocation before every exchange.
- Scope escalation is impossible — exchanged tokens are always a subset of the subject token's scopes (or, for Broker, of `broker_grants.scopes_granted`).
- Every issuance is logged in `issuances` (with `dpop_jkt` when DPoP is in use). Inspect via [`GET /admin/issuances`](../../reference/http-api.md#http-admin-issuances-list).

## DPoP propagation

When [DPoP (RFC 9449)](../../concepts/glossary.md#glossary-dpop) is enabled:

- If the requesting client presents a new DPoP proof, the exchanged token is bound to that proof's public key.
- If no DPoP proof is presented but the subject token has a `cnf.jkt` binding, it propagates to the exchanged token.
- Otherwise the token is a plain Bearer.

## See also

- [Connecting upstream providers](connecting-providers.md) — end-to-end brokered-vend recipe
- [Concept: Delegation and agent chains](../../concepts/delegation-and-agent-chains.md)
- [Concept: Broker vs Mint](../../concepts/broker-vs-mint.md)
- [Reference: token endpoint](../../reference/http-api.md#http-public-oauth-token)
- [Reference: resource policy admin endpoints](../../reference/http-api.md#http-admin-resources-slug-policy-exchange-allowed-clients-create)
