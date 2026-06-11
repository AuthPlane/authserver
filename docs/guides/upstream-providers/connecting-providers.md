# Connecting upstream providers — Authplane upstream OAuth recipe

*Context: part of [Guides — Upstream Providers](README.md). Start with the primer if you haven't.*

## What you'll achieve in ~30 minutes

- Register an OAuth app at the upstream provider (GitHub, Google, Slack, Notion, Linear, Atlassian, or any generic OAuth 2.0 IdP)
- Configure Authplane with the upstream's `client_id` / `client_secret` and endpoint URLs
- Expose the provider through a [Broker resource](../../concepts/glossary.md#glossary-broker-backend) with a scope catalog
- Trigger the per-user consent flow once via `/connect/{provider}`
- Vend fresh upstream tokens to your MCP server via [RFC 8693 Token Exchange](../../concepts/glossary.md#glossary-token-exchange)

## Prereqs

- Authplane running with `data_encryption.driver` set — `aes_master` or `vault_transit_encrypt`. See [Deploy → Configuration](../deploy/configuration.md) and [Deploy → HashiCorp Vault Transit](../deploy/hashicorp-vault-transit.md).
- `token_exchange.enabled: true` (or `AUTHPLANE_TOKEN_EXCHANGE_ENABLED=true`).
- An admin API key (`AUTHPLANE_ADMIN_API_KEY`) — see [Operate → Admin CLI & API](../operate/admin-cli.md).
- A user account at the upstream provider with permission to create an OAuth app.
- Concept context: [Broker backend](../../concepts/glossary.md#glossary-broker-backend), [Consent](../../concepts/glossary.md#glossary-consent), [Three-bound check](../../concepts/threat-model.md).

## Step 1: Create the OAuth app at the upstream provider

Each provider has its own developer console. Create an OAuth app and set the **callback URL** to:

```
https://<your-authplane>/connect/<provider-slug>/callback
```

| Provider | Console URL | Default slug | Required scope examples |
|---|---|---|---|
| GitHub | `https://github.com/settings/developers` → OAuth Apps → New | `github` | `repo`, `read:user`, `read:org` |
| Google | `https://console.cloud.google.com/apis/credentials` → Create credentials → OAuth client ID | `google` | `https://www.googleapis.com/auth/calendar.readonly`, `openid email` |
| Slack | `https://api.slack.com/apps` → Create New App | `slack` | `chat:write`, `channels:read` |
| Notion | `https://www.notion.so/my-integrations` → New integration → OAuth public | `notion` | `read_content`, `update_content` |
| Linear | `https://linear.app/settings/api/applications` → Create new | `linear` | `read`, `write` |
| Atlassian | `https://developer.atlassian.com/console/myapps/` → Create → OAuth 2.0 (3LO) | `atlassian` | `read:jira-work`, `write:jira-work`, `offline_access` |
| Custom | Provider's OAuth 2.0 docs (must support `authorization_code` + `refresh_token`) | your choice | — |

Save the `client_id` and `client_secret` returned by the provider.

> Slack uses a wrapped response shape — set `response_format: slack` in the Authplane config (step 2). Google requires `extra_auth_params.access_type=offline` to receive a refresh token. Atlassian requires `offline_access` in the scope list.

## Step 2: Register the upstream provider in Authplane

Put the secret in an environment variable (the AS reads it by name; the value never appears in config files):

```bash
export CONNECTOR_GITHUB_SECRET="<client secret from step 1>"
```

Register the provider. Verified against [`POST /admin/broker-providers`](../../reference/http-api.md#http-admin-broker-providers-create):

```bash
curl -X POST http://localhost:9001/admin/broker-providers \
  -H "Authorization: Bearer $AUTHPLANE_ADMIN_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "slug": "github",
    "display_name": "GitHub",
    "protocol": "oauth",
    "config_data": {
      "client_id": "<from step 1>",
      "client_secret_env": "CONNECTOR_GITHUB_SECRET",
      "authorize_url": "https://github.com/login/oauth/authorize",
      "token_url": "https://github.com/login/oauth/access_token"
    }
  }'
```

Provider-specific deltas to the `config_data` block:

| Provider | `authorize_url` | `token_url` | Extra fields |
|---|---|---|---|
| GitHub | `https://github.com/login/oauth/authorize` | `https://github.com/login/oauth/access_token` | — |
| Google | `https://accounts.google.com/o/oauth2/v2/auth` | `https://oauth2.googleapis.com/token` | `"extra_auth_params": {"access_type": "offline", "prompt": "consent"}` |
| Slack | `https://slack.com/oauth/v2/authorize` | `https://slack.com/api/oauth.v2.access` | `"response_format": "slack"` |
| Notion | `https://api.notion.com/v1/oauth/authorize` | `https://api.notion.com/v1/oauth/token` | — |
| Linear | `https://linear.app/oauth/authorize` | `https://api.linear.app/oauth/token` | — |
| Atlassian | `https://auth.atlassian.com/authorize` | `https://auth.atlassian.com/oauth/token` | `"extra_auth_params": {"audience": "api.atlassian.com", "prompt": "consent"}` |

CLI equivalent — verified against [`authserver admin provider create`](../../reference/cli.md#cli-admin-provider-create):

```bash
authserver admin provider create \
  --slug github \
  --protocol oauth \
  --config-data '{"client_id":"...","client_secret_env":"CONNECTOR_GITHUB_SECRET","authorize_url":"...","token_url":"..."}'
```

> Already-seeded providers from YAML: `broker_providers:` in YAML is **only** applied when no provider with that slug exists. Subsequent edits in YAML do not propagate — update via `PATCH /admin/broker-providers/{id}` (verified against [http-admin-broker-providers-id-update](../../reference/http-api.md#http-admin-broker-providers-id-update)) or the Admin UI.

## Step 3: Expose the provider through a Broker resource

A [resource](../../concepts/glossary.md#glossary-resource) names the fine-grained scopes the AS may vend to MCP servers and the upstream scopes each maps to. Verified against [`POST /admin/resources`](../../reference/http-api.md#http-admin-resources-create):

```bash
curl -X POST http://localhost:9001/admin/resources \
  -H "Authorization: Bearer $AUTHPLANE_ADMIN_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "slug": "github",
    "backend_kind": "broker",
    "broker_provider_slug": "github",
    "scopes": [
      { "name": "repo",      "upstream": "repo" },
      { "name": "read:user", "upstream": "read:user" }
    ],
    "policy": {
      "exchange": {
        "allowed_client_ids": ["mcp-server-prod"]
      }
    }
  }'
```

- `scopes[].name` is the AS-side scope your MCP server requests (`scope=repo`).
- `scopes[].upstream` is the actual upstream scope(s) the AS sends to GitHub on consent and uses for the bound check.
- `policy.exchange.allowed_client_ids` gates which MCP-server clients may vend this resource. Empty list = any consented client.

> **Fronting an existing Mint resource:** if you already have a Mint resource (your MCP server's own AS-issued tokens) and want to add an upstream brokered side to it without changing the slug, register a separate Broker resource and link it via [`POST /admin/fronting`](../../reference/http-api.md#http-admin-fronting-create). See [Topologies → Folded resource](../../topologies/folded-resource.md).

## Step 4: Trigger the user consent flow

Direct the user's browser to [`GET /connect/{provider}`](../../reference/http-api.md#http-public-connect-provider) with a `return_url` in your `connect.allowed_return_urls`:

```
GET /connect/github?resource=github&return_url=https://app.example.com/connected
```

What happens:

1. AS redirects the browser to GitHub's authorize page with HMAC-signed state.
2. User approves the scopes at GitHub.
3. GitHub redirects to `/connect/github/callback` (verified against [http-public-connect-provider-callback](../../reference/http-api.md#http-public-connect-provider-callback)).
4. AS exchanges the code, encrypts the refresh-grant, writes a `broker_grants` row keyed `(user_id, broker_provider_id)`, and redirects to `return_url`.

Verify the grant landed — verified against [`GET /admin/users/{id}/grants`](../../reference/http-api.md#http-admin-users-id-grants-list):

```bash
curl -H "Authorization: Bearer $AUTHPLANE_ADMIN_API_KEY" \
  http://localhost:9001/admin/users/<user-id>/grants
```

## Step 5: Vend a fresh upstream access token via RFC 8693

From your MCP server. Verified against [`POST /oauth/token`](../../reference/http-api.md#http-public-oauth-token) with `grant_type=urn:ietf:params:oauth:grant-type:token-exchange`:

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

Response — the user's actual GitHub access token (not an AS-signed JWT, since `backend_kind=broker`):

```json
{
  "access_token": "gho_xxxxxxxxxxxx",
  "issued_token_type": "urn:ietf:params:oauth:token-type:access_token",
  "token_type": "Bearer",
  "expires_in": 3600,
  "scope": "repo"
}
```

The AS performs three checks before responding (the [three-bound check](../../concepts/threat-model.md)):

- requested scopes ⊆ `consent_grants.scopes` for `(user, agent, resource)`
- requested scopes ⊆ `broker_grants.scopes_granted` for `(user, broker_provider)`
- acting client ∈ `policy.exchange.allowed_client_ids` (or list is empty)

If the upstream access token has expired, the AS refreshes transparently using the encrypted refresh-grant.

## Verify

Use the vended token against the real upstream API:

```bash
curl -H "Authorization: Bearer gho_xxxxxxxxxxxx" https://api.github.com/user
```

A 200 with the user's GitHub profile confirms the round-trip. For Slack, hit `https://slack.com/api/auth.test`. For Google, hit `https://www.googleapis.com/oauth2/v3/userinfo`.

## What can go wrong

| Symptom | Likely cause | Fix |
|---|---|---|
| `consent_required` with `cause=consent_missing`, `consent_url` points at `/connect/{provider}` | No `broker_grants` row for this `(user, provider)` — the user hasn't run the Connect flow, or the upstream revoked the refresh-grant | Direct the user to `consent_url`; after they return, retry the exchange. Confirm with `GET /admin/users/{id}/grants` ([anchor](../../reference/http-api.md#http-admin-users-id-grants-list)). |
| `consent_required` with `cause=scope_insufficient`, `consent_url` points at `/connect/{provider}` | Upstream granted a strict subset of the requested scopes (bound E) | Have the user re-run `/connect/{provider}` to widen scopes. For Google, also ensure `extra_auth_params.access_type=offline` so the refresh-grant persists. |
| `consent_required` with `cause=consent_missing`, `consent_url` points at `/authorize?resource=...` | The agent never got per-resource consent (bound B) — the MCP server hasn't run a standard OAuth 2.1 authorize flow against this AS for `resource=<slug>` | Have the agent redirect through `/authorize` with `resource=<slug>` and the needed scopes. |
| `invalid_target` on the token call | `resource=<slug>` doesn't match a registered resource, or the slug points at a Broker resource whose `broker_provider_slug` isn't registered | `GET /admin/resources` ([anchor](../../reference/http-api.md#http-admin-resources-list)) — confirm the slug and that `broker_provider_slug` resolves. |
| `access_denied` on the token call | Acting client not in `policy.exchange.allowed_client_ids` for the target resource | Add the client via [`POST /admin/resources/{slug}/policy/exchange/allowed-clients`](../../reference/http-api.md#http-admin-resources-slug-policy-exchange-allowed-clients-create) (or leave the list empty to allow any consented client). |
| `unsupported_grant_type` | Token Exchange disabled, or MCP client wasn't registered with the token-exchange grant | Set `token_exchange.enabled: true` (or `AUTHPLANE_TOKEN_EXCHANGE_ENABLED=true`). Re-register the client with `"grant_types": ["urn:ietf:params:oauth:grant-type:token-exchange"]` via [`POST /oauth/register`](../../reference/http-api.md#http-public-oauth-register). |
| `unauthorized_client` | Client exists but doesn't have token-exchange in its `grant_types` | `PATCH /admin/clients/{id}` ([anchor](../../reference/http-api.md#http-admin-clients-id-update)) to add the grant type. |
| `invalid_grant` | The user's `subject_token` is expired or revoked | User must re-authenticate. If the upstream rejected the refresh-grant (e.g. user revoked GitHub access), the AS surfaces this as `consent_required` with `cause=consent_missing` — direct the user back to `/connect/{provider}`. |

## Disconnecting and revoking

| Operation | Endpoint | Anchor |
|---|---|---|
| User lists their own connected providers | `GET /connections` | [http-public-connections](../../reference/http-api.md#http-public-connections) |
| User disconnects a single provider | `DELETE /connections/{provider}` | [http-public-connections-provider-delete](../../reference/http-api.md#http-public-connections-provider-delete) |
| Operator lists a user's grants | `GET /admin/users/{id}/grants` | [http-admin-users-id-grants-list](../../reference/http-api.md#http-admin-users-id-grants-list) |
| Operator revokes one broker grant | `DELETE /admin/grants/broker/{id}` | [http-admin-grants-broker-id-delete](../../reference/http-api.md#http-admin-grants-broker-id-delete) |
| Operator revokes one consent grant | `DELETE /admin/grants/consent/{id}` | [http-admin-grants-consent-id-delete](../../reference/http-api.md#http-admin-grants-consent-id-delete) |

## See also

- [Concept: Broker vs Mint](../../concepts/broker-vs-mint.md)
- [Token Exchange grant recipe](token-exchange-grant.md) — operator configuration knobs (`max_chain_depth`, `allow_self_exchange`, service-account-user pattern)
- [Reference: token endpoint](../../reference/http-api.md#http-public-oauth-token)
- [Reference: broker-providers admin endpoints](../../reference/http-api.md#http-admin-broker-providers-create)
- [Reference: `broker_providers` config schema](../../reference/configuration.md)
- [Threat model — three-bound consent](../../concepts/threat-model.md)
