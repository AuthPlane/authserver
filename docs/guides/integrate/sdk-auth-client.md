# Auth Client SDK — agent-side recipe for acquiring tokens

*Context: this is part of [Guides — Integrate](README.md). Start with the primer if you haven't.*

**Audience:** Builders writing an MCP **client** (agent or backend service) in Go, TypeScript, or Python that needs to acquire an Authplane access token and call a protected MCP tool.

> The canonical SDKs are published packages: [go-sdk](https://github.com/authplane/go-sdk) on the Go module proxy, [ts-sdk](https://github.com/authplane/ts-sdk) as `@authplane/sdk` / `@authplane/mcp` / `@authplane/fastmcp` on npm, and [python-sdk](https://github.com/authplane/python-sdk) as `authplane-sdk` + `authplane-fastmcp` on PyPI.

## What you'll achieve in 10 minutes

- An `AuthplaneClient` configured with your `client_id` / `client_secret`
- A `client_credentials` access token bound to a specific Resource
- A successful MCP `tools/call` against a protected endpoint
- (Optionally) [DPoP](../../concepts/glossary.md#glossary-dpop) sender-constraint, or [Token Exchange](../../concepts/glossary.md#glossary-token-exchange) for delegation

## Prereqs

- Authplane running, with `client_credentials` enabled (see [Client Credentials grant](client-credentials-grant.md)).
- A confidential OAuth client registered. If you don't have one, follow steps 1-2 of [Client Credentials grant](client-credentials-grant.md) first.
- An MCP server reachable at a known Resource URI (see [Connect an MCP Server](connect-mcp-server.md)).
- Concept context: [Client credentials grant](../../concepts/glossary.md#glossary-client-credentials-grant), [Resource indicator](../../concepts/glossary.md#glossary-resource-indicator), [DPoP](../../concepts/glossary.md#glossary-dpop), [Token exchange](../../concepts/glossary.md#glossary-token-exchange).

## When to use which method

| Scenario | Method | Notes |
|---|---|---|
| Backend or CI calling an MCP server as itself | `clientCredentials()` | No user context, no consent screen |
| Agent acting on behalf of a user | `tokenExchange()` (with subject + actor) | RFC 8693; subject token represents the user |
| Narrowing a token's scope before forwarding | `tokenExchange()` (subject only) | Self-exchange to a tighter scope |
| Sender-constrain tokens against theft | Add `withDPoP(signer)` to any of the above | Resulting tokens require the same key on every resource call |
| Live "is this token still good?" check | `introspect()` | RFC 7662 |
| Force-invalidate a leaked token | `revoke()` | RFC 7009 |

For browser-based user login (authorization code flow), use the OAuth endpoints directly — this SDK is for machine-to-machine and delegation patterns.

## Steps

### 1. Install the SDK

**Go:** `go get github.com/authplane/go-sdk`
**TypeScript:** `npm install @authplane/sdk`
**Python:** `pip install authplane-sdk`

### 2. Configure the client

**Go:**

```go
import "github.com/authplane/go-sdk/authplane"

client := authplane.NewClient(authplane.Config{
    IssuerURL:    "http://localhost:9000",
    ClientID:     os.Getenv("AUTHPLANE_CLIENT_ID"),
    ClientSecret: os.Getenv("AUTHPLANE_CLIENT_SECRET"),
})
```

**TypeScript:**

```typescript
import { AuthplaneClient } from "@authplane/sdk";

const client = new AuthplaneClient({
  issuerUrl: "http://localhost:9000",
  clientId: process.env.AUTHPLANE_CLIENT_ID!,
  clientSecret: process.env.AUTHPLANE_CLIENT_SECRET!,
});
```

**Python:**

```python
from authplane import AuthplaneClient

client = AuthplaneClient(
    issuer_url="http://localhost:9000",
    client_id=os.environ["AUTHPLANE_CLIENT_ID"],
    client_secret=os.environ["AUTHPLANE_CLIENT_SECRET"],
)
```

### 3. Acquire a client-credentials token

Bind the token to the Resource you intend to call with the `resource` parameter — this is what sets the JWT's `aud` claim so the MCP server accepts it.

**Go:**

```go
token, err := client.ClientCredentials(ctx, authplane.TokenRequest{
    Resource: "http://localhost:8080/mcp",
    Scope:    "mcp:echo",
})
```

**TypeScript:**

```typescript
const token = await client.clientCredentials({
  resource: "http://localhost:8080/mcp",
  scope: "mcp:echo",
});
```

**Python:**

```python
token = await client.client_credentials(
    resource="http://localhost:8080/mcp",
    scope="mcp:echo",
)
```

### 4. Call the protected MCP tool

Attach the token in the `Authorization` header and send a normal MCP JSON-RPC request:

```bash
# Wire shape verified against docs/reference/http-api.md#http-public-oauth-token
curl -sS -X POST http://localhost:8080/mcp \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"echo","arguments":{"message":"hi"}}}'
```

### 5. (Optional) Sender-constrain with DPoP

Resource theft is the most common token-loss mode in MCP. DPoP binds the token to a key only your agent holds.

**Go:**

```go
signer, _ := authplane.NewDPoPSigner(authplane.ES256)
client := authplane.NewClient(authplane.Config{
    IssuerURL: "http://localhost:9000",
    ClientID: id, ClientSecret: secret,
    DPoP: signer,
})
// All subsequent tokens are DPoP-bound; the client auto-attaches a proof on each call.
```

The same `signer` must be used on every call to the resource server — that's what proves possession.

### 6. (Optional) Exchange for a delegated token

When an agent operates on behalf of a user, exchange the user's token (subject) plus the agent's token (actor) for a delegated token:

**Go:**

```go
delegated, err := client.TokenExchange(ctx, authplane.ExchangeRequest{
    SubjectToken: userToken,
    ActorToken:   agentToken,
    Resource:     "http://localhost:8080/mcp",
    Scope:        "mcp:echo",
})
```

See [Concepts → Delegation & agent chains](../../concepts/delegation-and-agent-chains.md) for what the `act` claim chain looks like in the resulting token.

## Verify

The token should have `aud` matching your Resource URI:

```bash
echo "$ACCESS_TOKEN" | cut -d. -f2 | base64 -d 2>/dev/null | jq .
# Expect: { "iss": "http://localhost:9000", "aud": ["http://localhost:8080/mcp"], "scope": "mcp:echo", … }
```

And an introspection should report it active:

```bash
# Wire shape verified against docs/reference/http-api.md#http-public-oauth-introspect
curl -sS -X POST http://localhost:9000/oauth/introspect \
  -d "token=$ACCESS_TOKEN" \
  -d "client_id=$AUTHPLANE_CLIENT_ID" \
  -d "client_secret=$AUTHPLANE_CLIENT_SECRET" | jq .active
# Expect: true
```

## What can go wrong

| Symptom | Likely cause | Fix |
|---|---|---|
| `invalid_scope` on token request | Requested a scope not in the client's registered set | Re-register or update the client with the scope: `authserver admin client update --id <id> --scope 'mcp:echo'` ([cli.md#cli-admin-client-update](../../reference/cli.md#cli-admin-client-update)) |
| `unauthorized_client` | The client's `grant_types` doesn't include `client_credentials` | Recreate with `--grant-types client_credentials` ([cli.md#cli-admin-client-create](../../reference/cli.md#cli-admin-client-create)) |
| `unsupported_grant_type` | `client_credentials.enabled: false` on the server | Set `AUTHPLANE_CLIENT_CREDENTIALS_ENABLED=true` ([env-vars.md](../../reference/env-vars.md)) and restart |
| Token mints fine but MCP server rejects with audience mismatch | The `resource=` form parameter did not match the MCP server's PRM `resource` string byte-for-byte | Make the agent read the PRM document first and echo its `resource` value verbatim (see [Connect an MCP Server § What can go wrong](connect-mcp-server.md#what-can-go-wrong)) |
| DPoP-bound token works once then fails | DPoP nonce required but agent didn't echo the `DPoP-Nonce` server response header on the next proof | Honor `WWW-Authenticate: DPoP error="use_dpop_nonce"` and include the nonce on retries (the SDK does this automatically) |

## See also

- **Runnable proof:** [`examples/go/02-agent-basic/README.md`](../../../examples/go/02-agent-basic/README.md), [`examples/typescript/02-agent-basic/README.md`](../../../examples/typescript/02-agent-basic/README.md), [`examples/python/02-agent-basic/README.md`](../../../examples/python/02-agent-basic/README.md)
- [Client Credentials grant recipe](client-credentials-grant.md) — register the client, mint the token
- [Resource Server SDK guide](sdk-resource-server.md) — the server side
- [Concepts → DPoP](../../concepts/dpop-and-proof-of-possession.md)
- [Reference → `POST /oauth/token`](../../reference/http-api.md#http-public-oauth-token)
