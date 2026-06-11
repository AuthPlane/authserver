# Client Credentials Grant — mint machine-to-machine tokens

*Context: this is part of [Guides — Integrate](README.md). Start with the primer if you haven't.*

**Audience:** Builders / operators standing up machine-to-machine auth — a backend worker, CI job, monitoring agent, or any service that needs to call an MCP server as itself, with no user in the loop.

## What you'll achieve in 10 minutes

- `client_credentials` enabled on Authplane
- A confidential OAuth client registered with `--grant-types client_credentials`
- A successful `access_token` minted via `POST /oauth/token`
- The token accepted by your MCP server with the correct `aud` and `scope`

For a deeper architectural picture, see [Concepts → Delegation & agent chains](../../concepts/delegation-and-agent-chains.md). This recipe is operator-shaped.

## Prereqs

- Authplane running on `http://localhost:9000` (public) / `http://localhost:9001` (admin), with `AUTHPLANE_ADMIN_API_KEY` exported.
- An MCP server registered as a [Mint Resource](../../concepts/glossary.md#glossary-mint-backend) (see [Connect an MCP Server](connect-mcp-server.md)).
- Concept context: [Client credentials grant](../../concepts/glossary.md#glossary-client-credentials-grant), [Access token](../../concepts/glossary.md#glossary-access-token), [Resource indicator](../../concepts/glossary.md#glossary-resource-indicator), [Scope](../../concepts/glossary.md#glossary-scope).

## When NOT to use this

- A user is involved and should authorize what the service does → use the authorization code flow.
- A service needs to act *on behalf of a user* (e.g., use the user's GitHub token) → use [Token Exchange](../upstream-providers/token-exchange-grant.md).
- A bot needs its own upstream-provider access → register a service-account user and follow the service-account pattern in [Token Exchange](../upstream-providers/token-exchange-grant.md). Self-impersonating a `client_credentials` token onto a broker grant is not supported.

## Steps

### 1. Enable the grant on Authplane

It's off by default. Set both env vars and restart:

```bash
# Variables verified against docs/reference/env-vars.md
export AUTHPLANE_CLIENT_CREDENTIALS_ENABLED=true
export AUTHPLANE_CLIENT_CREDENTIALS_TOKEN_EXPIRY=1h
```

Or in YAML — see [`docs/reference/configuration.md#client_credentials`](../../reference/configuration.md#config-client-credentials):

```yaml
client_credentials:
  enabled: true
  token_expiry: 1h
```

**Recommendation:** keep `token_expiry` short (15m-1h). Machine clients re-authenticate instantly, so there's no UX cost. There is no refresh token for this grant — by design.

### 2. Register the client

The client needs `grant_types=client_credentials` and at least one scope. Pick `--auth-method client_secret_post` (or `client_secret_basic`) — `none` is for public clients and won't work here.

```bash
# Command verified against docs/reference/cli.md#cli-admin-client-create
authserver admin client create \
  --name backend-worker \
  --grant-types client_credentials \
  --auth-method client_secret_post \
  --scope "mcp:echo mcp:query_database"
```

The response prints the `client_id` and `client_secret`. **Store the secret in a secret manager now — it is bcrypt-hashed on disk and never returned again.**

Equivalent admin API:

```bash
# Wire shape verified against docs/reference/http-api.md#http-admin-clients-create
curl -sS -X POST http://localhost:9001/admin/clients \
  -H "Authorization: Bearer $AUTHPLANE_ADMIN_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "client_name": "backend-worker",
    "grant_types": ["client_credentials"],
    "token_endpoint_auth_method": "client_secret_post",
    "scope": "mcp:echo mcp:query_database"
  }'
```

### 3. Mint a token

Always include `resource=` — this sets the JWT `aud` to the MCP server you intend to call. Without it, the token's `aud` defaults to the issuer and your MCP server will reject it.

```bash
# Wire shape verified against docs/reference/http-api.md#http-public-oauth-token
curl -sS -X POST http://localhost:9000/oauth/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=client_credentials" \
  -d "client_id=$CLIENT_ID" \
  -d "client_secret=$CLIENT_SECRET" \
  -d "resource=http://localhost:8080/mcp" \
  -d "scope=mcp:echo"
```

Response:

```json
{
  "access_token": "eyJhbGciOiJFUzI1Ni…",
  "token_type": "Bearer",
  "expires_in": 3600,
  "scope": "mcp:echo"
}
```

### 4. Call the MCP server

```bash
curl -sS -X POST http://localhost:8080/mcp \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"echo","arguments":{"message":"hi"}}}'
```

When the token expires, request a fresh one. There is no refresh token: the client re-authenticates with its secret. This keeps the blast radius small if a token leaks.

## Token shape

Machine tokens are JWTs (RFC 9068). The defining difference from user tokens: `sub == client_id`, because there is no user.

```json
{
  "iss": "http://localhost:9000",
  "sub": "<client_id>",
  "aud": ["http://localhost:8080/mcp"],
  "client_id": "<client_id>",
  "scope": "mcp:echo",
  "jti": "<unique-id>",
  "iat": 1709300000,
  "exp": 1709303600
}
```

## Scope resolution

| Request includes `scope`? | Outcome |
|---|---|
| Yes, all requested scopes are in the client's registered set | Token gets exactly the requested scopes |
| Yes, but some requested scopes are NOT in the registered set | Request fails with `invalid_scope` |
| No | Token gets ALL the client's registered scopes |

Always request only what you need — a stolen token with fewer scopes does less damage.

## Verify

```bash
# Wire shape verified against docs/reference/http-api.md#http-public-oauth-introspect
curl -sS -X POST http://localhost:9000/oauth/introspect \
  -d "token=$ACCESS_TOKEN" \
  -d "client_id=$CLIENT_ID" \
  -d "client_secret=$CLIENT_SECRET" | jq .
# Expect: {"active": true, "scope": "mcp:echo", "client_id": "...", "aud": ["..."], ...}
```

Decode the JWT payload to confirm `aud`, `scope`, and `sub`:

```bash
echo "$ACCESS_TOKEN" | cut -d. -f2 | base64 -d 2>/dev/null | jq '{iss,sub,aud,scope}'
```

## What can go wrong

| Symptom | Likely cause | Fix |
|---|---|---|
| `unsupported_grant_type` | `client_credentials.enabled: false` on the server | Set `AUTHPLANE_CLIENT_CREDENTIALS_ENABLED=true` and restart ([env-vars.md](../../reference/env-vars.md)) |
| `unauthorized_client` | Client's `grant_types` doesn't include `client_credentials` | Recreate with `--grant-types client_credentials` or update via admin API |
| `invalid_client` | Wrong `client_id` or `client_secret`, or `--auth-method` was `none` | Re-check both values (case-sensitive); register with `--auth-method client_secret_post` or `client_secret_basic` |
| `invalid_scope` | Requested scope not in the client's registered set | List scopes: `authserver admin client list`; update with `authserver admin client update --id <id> --scope '...'` |
| Token mints fine but MCP server rejects with audience mismatch | Missing or wrong `resource=` on the token request | Add `-d "resource=<canonical-uri>"` matching the Resource's `--uri` byte-for-byte |
| Stolen `client_secret` | Logs, env-var dumps, leaked Docker images | (1) `PATCH /admin/clients/{id}/suspend`, (2) `POST /oauth/revoke` for live tokens, (3) `authserver admin client rotate-secret --id <id>` ([cli.md#cli-admin-client-rotate-secret](../../reference/cli.md#cli-admin-client-rotate-secret)), (4) audit logs |

## Revocation

Revoke an active token immediately:

```bash
# Wire shape verified against docs/reference/http-api.md#http-public-oauth-revoke
curl -sS -X POST http://localhost:9000/oauth/revoke \
  -d "token=$ACCESS_TOKEN" \
  -d "client_id=$CLIENT_ID" \
  -d "client_secret=$CLIENT_SECRET"
```

After revocation the token returns `"active": false` on introspection and is rejected by token exchange.

## DPoP binding (optional)

If DPoP is enabled on Authplane, the client can include a `DPoP` proof header on the token request. The resulting token gets `token_type: DPoP` and a `cnf.jkt` claim binding it to the client's keypair — a stolen DPoP-bound token is useless without the private key. See [DPoP concept](../../concepts/dpop-and-proof-of-possession.md) and the [Auth Client SDK guide](sdk-auth-client.md#5-optional-sender-constrain-with-dpop) for the agent-side code.

## See also

- **Runnable proof:** [`examples/go/02-agent-basic/README.md`](../../../examples/go/02-agent-basic/README.md), [`examples/typescript/02-agent-basic/README.md`](../../../examples/typescript/02-agent-basic/README.md), [`examples/python/02-agent-basic/README.md`](../../../examples/python/02-agent-basic/README.md)
- [Auth Client SDK guide](sdk-auth-client.md) — language-specific SDK that wraps this flow
- [Connect an MCP Server guide](connect-mcp-server.md) — the server side
- [Concepts → Tokens & claims](../../concepts/tokens-and-claims.md)
- [Reference → CLI (`authserver admin client create`)](../../reference/cli.md#cli-admin-client-create)
- [Reference → `POST /oauth/token`](../../reference/http-api.md#http-public-oauth-token)
- [Reference → `client_credentials` config](../../reference/configuration.md#config-client-credentials)
