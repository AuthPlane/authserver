# Tier 03 — MCP server + agent with DPoP + per-tool scopes (Go)

<!-- loccount:begin -->
**Auth-specific code: 15 lines · Total example: 132 lines · SDK: go-sdk v0.1.1**
<!-- loccount:end -->

A paired Go MCP server and agent that demonstrate two raised guard rails on
top of tier 01 / tier 02:

1. **DPoP — sender-constrained tokens (RFC 9449).** The agent generates an
   ephemeral ES256 key, asks the AS to mint a `client_credentials` access
   token bound to that key (`cnf.jkt`), and signs a fresh DPoP proof JWT for
   every outbound call. A stolen access token alone is useless without the
   private key.
2. **Per-tool scope enforcement.** The MCP server declares two tools — `echo`
   requires `mcp:echo`, `add_numbers` requires `mcp:add` — and each tool
   handler calls `claims.RequireScope(...)` before doing any work. A token
   that holds one scope but not the other can call exactly one of the tools.

Everything you need for both guard rails fits inside fifteen lines spread
across `server/main.go` and `agent/main.go`; the rest is plain MCP and HTTP
plumbing.

## What you'll learn

- How to enable outbound DPoP in the Go SDK with
  `authplane.NewDPoPKeyMaterial` + `authplane.WithDPoP(km)` so the SDK
  attaches a `DPoP:` proof to every token request automatically
- How to generate a per-request proof JWT for downstream calls with
  `client.DPoPSigner().GenerateProof(method, url, &DPoPProofOptions{AccessToken: ...})`
  and send it under `Authorization: DPoP <token>` (RFC 9449 §7.1)
- How to enforce per-tool scope inside MCP tool handlers with
  `authplanemcp.ClaimsFromContext(ctx).RequireScope("scope-name")`

| | |
|---|---|
| **Time to run** | ~2 minutes (first build is ~90s, subsequent runs are seconds) |
| **Prereqs** | Docker 24+, `docker compose`, `go 1.25+`, `curl`, `jq` |
| **SDK** | `github.com/authplane/go-sdk/{mcp,core}` v0.1.1 (Go module proxy) |
| **MCP framework** | `github.com/modelcontextprotocol/go-sdk v1.4.1` |
| **DPoP algorithm** | ES256 (ECDSA P-256). RS256 is also supported via `authplane.NewDPoPKeyMaterial(jose.RS256)`. |
| **Pairs with** | [Tier 02 — Basic agent (Go)](../02-agent-basic/) — same client-credentials flow, but Bearer-only. This tier upgrades it to DPoP. |

## Run it in 3 commands

```bash
cp .env.example .env
make run
make verify   # no-op today — see callout above
```

`make run` builds the MCP server image and brings up authserver + mcp-server
via `docker-compose.yml`. `make verify` registers the Resource + client,
authorizes the client AS the Resource, then runs the agent (`go run ./agent`)
and asserts both tools returned their expected payloads.

## Step by step

The `make verify` script automates every step below; the bullets here
describe what's happening so you can reproduce the flow by hand.

> If you want to run the curl examples manually instead of via `make verify`,
> first load the env vars and capture client credentials as you go:
>
> ```bash
> set -a; source .env; set +a   # exports AUTHPLANE_ADMIN_API_KEY etc.
> ```

1. **Confirm the AS came up with DPoP enabled.** The discovery document
   advertises the supported DPoP signing algorithms when
   `AUTHPLANE_DPOP_ENABLED=true` ([`docs/reference/env-vars.md`](../../../docs/reference/env-vars.md)):

   ```bash
   curl -fsS http://localhost:9000/.well-known/oauth-authorization-server \
     | jq '.dpop_signing_alg_values_supported'
   ```

   Expect `["ES256", "RS256"]` (or whichever set the AS is configured with).
   The Protected Resource Metadata at
   `/.well-known/oauth-protected-resource/mcp` also advertises the same set.

2. **Register a Mint Resource with both scopes.** The Resource URI is the
   audience the MCP server requires; the two scopes match the per-tool
   guards in `server/main.go`. See
   [`docs/reference/http-api.md#http-admin-resources-create`](../../../docs/reference/http-api.md#http-admin-resources-create):

   ```bash
   curl -sS -X POST http://localhost:9001/admin/resources \
     -H "Authorization: Bearer $AUTHPLANE_ADMIN_API_KEY" \
     -H "Content-Type: application/json" \
     -d '{
       "slug": "demo-mcp-tier03",
       "uri": "http://localhost:8080/mcp",
       "backend_kind": "mint",
       "display_name": "Demo MCP Tier 03",
       "scopes": [
         {"name": "mcp:echo", "description": "echo tool"},
         {"name": "mcp:add",  "description": "add_numbers tool"}
       ]
     }'
   ```

   The same Resource can be created via the CLI inside the container
   ([`docs/reference/cli.md#cli-admin-resource-create`](../../../docs/reference/cli.md#cli-admin-resource-create)):

   ```bash
   docker compose exec authserver /authserver admin resource create \
     --slug demo-mcp-tier03 \
     --uri http://localhost:8080/mcp \
     --backend-kind mint \
     --display-name "Demo MCP Tier 03" \
     --scopes 'mcp:echo||echo tool' \
     --scopes 'mcp:add||add_numbers tool'
   ```

3. **Register an OAuth client** with `grant_types=[client_credentials]` and
   both scopes
   ([`docs/reference/http-api.md#http-admin-clients-create`](../../../docs/reference/http-api.md#http-admin-clients-create)
   /
   [`docs/reference/cli.md#cli-admin-client-create`](../../../docs/reference/cli.md#cli-admin-client-create)):

   ```bash
   curl -sS -X POST http://localhost:9001/admin/clients \
     -H "Authorization: Bearer $AUTHPLANE_ADMIN_API_KEY" \
     -H "Content-Type: application/json" \
     -d '{
       "client_name": "demo-mcp-tier03-agent",
       "grant_types": ["client_credentials"],
       "token_endpoint_auth_method": "client_secret_basic",
       "scope": "mcp:echo mcp:add"
     }'
   ```

   The response carries `client_id` and `client_secret`. The secret is shown
   once.

4. **(Reference) Mint a DPoP-bound token by hand.** The SDK does this for
   you internally — when `authplane.WithDPoP(km)` is set, the client attaches
   the `DPoP:` header to every `/oauth/token` request and re-tries with the
   server-issued nonce if the AS responds with
   `WWW-Authenticate: DPoP error="use_dpop_nonce"`
   ([`docs/reference/http-api.md#http-public-oauth-token`](../../../docs/reference/http-api.md#http-public-oauth-token)).
   The curl-by-hand form is below for reference; you don't need to write the
   proof JWT yourself in Go.

   ```bash
   # `DPOP_PROOF` is a base64url-encoded JWS — generating one by hand is
   # left as an exercise; the SDK does it via authplane.DPoPSigner.GenerateProof.
   curl -sS -X POST http://localhost:9000/oauth/token \
     -u "$CLIENT_ID:$CLIENT_SECRET" \
     -H "DPoP: $DPOP_PROOF" \
     -d "grant_type=client_credentials" \
     -d "scope=mcp:echo mcp:add" \
     --data-urlencode "resource=http://localhost:8080/mcp"
   ```

   The response includes `access_token`, `token_type=DPoP`, `expires_in`, and
   `scope`. The token's `cnf.jkt` claim holds the agent's DPoP key
   thumbprint.

5. **Run the agent.** With `AUTHPLANE_CLIENT_ID` / `AUTHPLANE_CLIENT_SECRET`
   in `.env`:

   ```bash
   set -a; source .env; set +a
   go run ./agent
   ```

   The agent calls both tools. The output looks like:

   ```text
   echo: {"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"hello from tier-03 agent"}], ...}}
   add_numbers: {"jsonrpc":"2.0","id":2,"result":{"content":[{"type":"text","text":"5"}], ...}}
   ```

   Drop the `DPoP:` header (or replace the access token with a bearer-only
   one) and the MCP server returns 401 — proof that DPoP is wired through
   the full pipeline.

## Before / After

The tier-02 agent attaches a plain bearer token to its MCP call. The
tier-03 agent generates DPoP key material at startup, enables outbound
DPoP on the client, and signs a fresh proof for the MCP request itself:

```diff
- client, _ := authplane.NewClient(ctx, os.Getenv("AUTHPLANE_ISSUER"),
-     authplane.WithClientCredentials(id, secret))
+ km, _ := authplane.NewDPoPKeyMaterial(jose.ES256)
+ client, _ := authplane.NewClient(ctx, os.Getenv("AUTHPLANE_ISSUER"),
+     authplane.WithClientCredentials(id, secret),
+     authplane.WithDPoP(km))
  tok, _ := client.ClientCredentials(ctx, []string{"mcp:echo", "mcp:add"}, []string{resource})
+ proof, _ := client.DPoPSigner().GenerateProof("POST", mcpURL,
+     &authplane.DPoPProofOptions{AccessToken: tok.AccessToken})

- req.Header.Set("Authorization", "Bearer "+tok.AccessToken)
+ req.Header.Set("Authorization", "DPoP "+tok.AccessToken)
+ req.Header.Set("DPoP", proof)
```

And the tier-01 MCP server hands every authenticated request to one tool;
the tier-03 server gates each tool on its own scope:

```diff
- mcp.AddTool(server, &mcp.Tool{Name: "echo"}, func(ctx, _, args) (...) {
-     return &mcp.CallToolResult{...}, nil, nil
- })
+ mcp.AddTool(server, &mcp.Tool{Name: "echo"}, func(ctx, _, args) (...) {
+     if err := requireScope(ctx, "mcp:echo"); err != nil { return nil, nil, err }
+     return &mcp.CallToolResult{...}, nil, nil
+ })
+ mcp.AddTool(server, &mcp.Tool{Name: "add_numbers"}, func(ctx, _, args) (...) {
+     if err := requireScope(ctx, "mcp:add"); err != nil { return nil, nil, err }
+     return &mcp.CallToolResult{...}, nil, nil
+ })
```

The auth-specific lines live inside the `// authplane:begin` /
`// authplane:end` markers in [`server/main.go`](./server/main.go) and
[`agent/main.go`](./agent/main.go). Run
`go run ./tools/loccount examples/go/03-mcp-server-dpop-scopes` from the
repo root to see the count.

## What's happening

**On the AS:** with `AUTHPLANE_DPOP_ENABLED=true`
([`docs/reference/env-vars.md`](../../../docs/reference/env-vars.md) line 45),
the token endpoint requires a valid `DPoP` proof header on every
`/oauth/token` request and binds the issued token to the proof's key via
`cnf.jkt`. If the AS demands a nonce (`AUTHPLANE_DPOP_REQUIRE_NONCE`), it
replies with `WWW-Authenticate: DPoP error="use_dpop_nonce"` and a
`DPoP-Nonce:` header; the SDK auto-retries with the supplied nonce
attached to the next proof. The example does not turn on
`AUTHPLANE_DPOP_REQUIRE_NONCE`, but the SDK is ready for it.

**On the agent:**
`authplane.NewDPoPKeyMaterial` generates an ephemeral ES256 key pair.
`authplane.WithDPoP(km)` enables outbound DPoP on the client (see the
`go-sdk` package README on the Go module proxy for the full recipe and
supported algorithms). Every `/oauth/token` call now carries a `DPoP:`
proof JWT and the issued token's `cnf.jkt` matches the key's thumbprint.
For the downstream call to the MCP server, the agent calls
`client.DPoPSigner().GenerateProof` — `htm`/`htu` covers the method and
URL, `ath` is the SHA-256 hash of the access token, and the JWT header
carries the public JWK so the verifier can check the thumbprint against
`cnf.jkt`. The `Authorization` scheme is `DPoP` (not `Bearer`) per
RFC 9449 §7.1.

**On the MCP server:**
`authplanemcp.NewAdapter` discovers AS metadata and warms the JWKS
cache; `AuthMiddleware` validates each inbound token (signature,
audience, expiry) and injects `*verifier.VerifiedClaims` into the
request context. The middleware is intentionally permissive on scopes
so MCP `initialize` and protocol messages succeed; each tool handler
calls `ClaimsFromContext` and `claims.RequireScope` so an under-scoped
token fails on the per-tool boundary with a clear
`ErrInsufficientScope`, which MCP surfaces as `isError: true`.

> **DPoP-bound verification note.** The MCP adapter's `AuthMiddleware` uses
> `auth.RequireBearerToken` from the MCP Go SDK, which is Bearer-only — it
> validates the JWT but does not re-verify the DPoP proof against the
> request URL/method. The token's `cnf.jkt` claim is still visible to every
> handler via `ClaimsFromContext(ctx).DPoPThumbprint()`. To enforce DPoP at
> the middleware layer (htu/htm/ath checks + replay protection), bypass
> `AuthMiddleware` for that route and call
> `adapter.Resource().VerifyToken(ctx, token, resource.WithDPoP(dpopCtx))`
> directly. The `go-sdk/mcp` and `go-sdk/http` package READMEs (on the
> Go module proxy) cover the full recipe.
> This example keeps the MVP shape (middleware + JWT validation +
> sender-constrained tokens via `cnf.jkt`); the bypass route is the next
> level of strictness when the resource server itself must reject a
> proofless token.

## Next

[Tier 04 — MCP server fronting a Broker (Go)](../04-broker-upstream/)
keeps the DPoP foundation and adds RFC 8693 token exchange with
`ConsentRequiredError` → `mcp.URLElicitationRequiredError` mapping.

## Use a locally-built authserver image

To build the AS from this checkout rather than pulling
`authplane/authserver:latest`, follow the **LOCAL BUILD ESCAPE
HATCH** comment block in
[`../../_shared/docker-compose.authserver.yml`](../../_shared/docker-compose.authserver.yml).
Mirror the change in this example's `docker-compose.yml` (which inlines
the same service definition) — replace the `image:` line with the
`build:` block shown in the shared file.
