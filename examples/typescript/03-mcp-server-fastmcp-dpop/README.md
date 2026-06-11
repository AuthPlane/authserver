# Tier 03 — FastMCP server + agent with DPoP (TypeScript)

<!-- loccount:begin -->
**Auth-specific code: 16 lines · Total example: 127 lines · SDK: ts-sdk 0.2.0**
<!-- loccount:end -->

A FastMCP TypeScript server protected by Authplane-issued, DPoP-bound JWTs
(RFC 9449), paired with an agent that holds the bound key and presents a
fresh DPoP proof on every outbound MCP request. Two scoped tools (`echo`
requiring `mcp:echo`, `add_numbers` requiring `mcp:add`) demonstrate per-tool
scope enforcement via FastMCP's `requireScopes` helper. Everything needed
to wire DPoP + per-tool scopes fits inside `// authplane:begin`/`end`
markers across `server.ts` and `agent.ts` so the [`tools/loccount`](../../../tools/loccount/README.md)
gate can audit the combined LOC budget for this tier.

## What you'll learn

- How to switch the TypeScript example track from Express + the MCP TS SDK
  (tiers 01/02) to **FastMCP for TypeScript** with the
  `@authplane/fastmcp` adapter
- How to enable inbound DPoP on the server via `inboundDPoP: { required: true }`
  so the FastMCP `authenticate` callback rejects any bearer-only token and
  any proof whose JWK thumbprint does not match `cnf.jkt`
- How to gate individual tools on individual scopes with FastMCP's
  `requireScopes` helper — independent of the global `requiredScopes` on
  `authplaneFastMcpAuth`
- How to acquire a DPoP-bound `client_credentials` token from Authplane and
  attach a fresh `DPoP` proof to every outbound MCP request using the
  `@authplane/sdk` `DPoPProvider`

| | |
|---|---|
| **Time to run** | ~2 minutes (first build is ~90s, subsequent runs are seconds) |
| **Prereqs** | Docker 24+, `docker compose`, `curl`, `jq`, Node.js 22+ (only if you run outside Docker) |
| **SDK** | `@authplane/sdk` + `@authplane/fastmcp` 0.2.0 (npm) |
| **MCP framework** | [`fastmcp` for TypeScript](https://github.com/punkpeye/fastmcp) — the TS track switches from Express + MCP TS SDK at tier 03 |

## Run it in 3 commands

```bash
cp .env.example .env
make run
make verify
```

`make run` builds the MCP server image and brings up both services
(authserver on `:9000` / `:9001`, MCP server on `:8080`). `make verify`
registers the Resource (with both scopes) and OAuth client, then runs the
agent as a one-shot container. The agent generates a DPoP keypair, mints a
DPoP-bound token, and calls both tools. `make clean` tears everything down
and removes the `.env` file the run target created.

## Step by step

The `make verify` script automates every step below; the bullets here
describe what's happening so you can reproduce the flow by hand.

> If you want to run the curl examples manually instead of via `make verify`,
> first load the env vars and capture client credentials as you go:
>
> ```bash
> set -a; source .env; set +a   # exports AUTHPLANE_ADMIN_API_KEY etc.
> ```
>
> Step 3 emits `client_id` and `client_secret` in its response; assign each
> to a shell variable (`CLIENT_ID=...`, `CLIENT_SECRET=...`) before steps 4
> and 5 use them.

1. **Start authserver + MCP server.** `make run` brings both up. The
   AS-side `AUTHPLANE_DPOP_ENABLED=true` env var (see
   [`docs/reference/env-vars.md`](../../../docs/reference/env-vars.md))
   enables RFC 9449 issuance and proof verification at the token endpoint.
   Wait for the AS discovery endpoint to return 200:

   ```bash
   curl -fsS http://localhost:9000/.well-known/oauth-authorization-server
   ```

2. **Register a Mint Resource with both scopes.** The Resource URI must
   match the JWT audience the FastMCP server will expect (the
   `AUTHPLANE_RESOURCE` env var). The default in this example is
   `http://localhost:8080/mcp`.

   ```bash
   curl -sS -X POST http://localhost:9001/admin/resources \
     -H "Authorization: Bearer $AUTHPLANE_ADMIN_API_KEY" \
     -H "Content-Type: application/json" \
     -d '{
       "slug": "demo-mcp-tier03",
       "uri": "http://localhost:8080/mcp",
       "backend_kind": "mint",
       "display_name": "Demo FastMCP DPoP",
       "scopes": [
         {"name": "mcp:echo", "description": "echo tool"},
         {"name": "mcp:add",  "description": "add_numbers tool"}
       ]
     }'
   ```

   See [`docs/reference/http-api.md#http-admin-resources-create`](../../../docs/reference/http-api.md#http-admin-resources-create)
   for the canonical DTO. The same Resource can be created via the CLI
   inside the container — see
   [`docs/reference/cli.md#cli-admin-resource-create`](../../../docs/reference/cli.md#cli-admin-resource-create);
   pipe-delimited `'name|upstream|description'` tuples are the wire syntax
   for `--scopes`.

3. **Register an OAuth client with both scopes.** A `client_credentials`
   machine client needs the matching grant type, a confidential auth
   method, and the union of scopes the agent will request.

   ```bash
   curl -sS -X POST http://localhost:9001/admin/clients \
     -H "Authorization: Bearer $AUTHPLANE_ADMIN_API_KEY" \
     -H "Content-Type: application/json" \
     -d '{
       "client_name": "demo-fastmcp-dpop-client",
       "grant_types": ["client_credentials"],
       "token_endpoint_auth_method": "client_secret_basic",
       "scope": "mcp:echo mcp:add"
     }'
   ```

   The response carries `client_id` and `client_secret`. The secret is
   shown once.

4. **Run the agent.** The agent generates an ES256 keypair, hands the
   public key to Authplane's `DPoPProvider`, and asks the SDK for a
   `client_credentials` token. The SDK signs the token request with a
   DPoP proof; the AS binds the issued JWT to the proof's `jkt` via
   `cnf.jkt`. See
   [`docs/reference/http-api.md#http-public-oauth-token`](../../../docs/reference/http-api.md#http-public-oauth-token).
   The agent then creates one fresh DPoP proof per MCP request and sends
   the bearer with the `DPoP` scheme.

   ```bash
   docker compose run --rm \
     -e AUTHPLANE_ISSUER=http://authserver:9000 \
     -e AUTHPLANE_RESOURCE=http://localhost:8080/mcp \
     -e AUTHPLANE_CLIENT_ID="$CLIENT_ID" \
     -e AUTHPLANE_CLIENT_SECRET="$CLIENT_SECRET" \
     -e MCP_URL=http://mcp-server:8080/mcp \
     agent
   ```

   Expected output: three `[agent] ... OK` lines — `initialize`, `echo`,
   `add_numbers`. Without the `DPoP` header (or with a proof signed by a
   different key than the token's `cnf.jkt`) the FastMCP server returns
   HTTP 401 — proof that DPoP enforcement is active.

## Before / After

A plain FastMCP TS server with no auth:

```diff
- const server = new FastMCP({ name: "demo-server", version: "1.0.0" });
- server.addTool({
-   name: "echo",
-   parameters: z.object({ text: z.string() }),
-   execute: async ({ text }) => ({ content: [{ type: "text", text }] }),
- });
```

The same server with Authplane DPoP + per-tool scopes:

```diff
+ const auth = await authplaneFastMcpAuth({
+   issuer: process.env.AUTHPLANE_ISSUER!, resource: process.env.AUTHPLANE_RESOURCE!,
+   scopes: ["mcp:echo", "mcp:add"], inboundDPoP: { required: true }, devMode: true,
+ });
- const server = new FastMCP({ name: "demo-server", version: "1.0.0" });
+ const server = new FastMCP<AuthplaneFastMcpSession>({
+   name: "demo-server", version: "1.0.0",
+   authenticate: auth.authenticate, oauth: auth.oauth,
+ });
  server.addTool({
    name: "echo",
    parameters: z.object({ text: z.string() }),
+   canAccess: requireScopes("mcp:echo"),
    execute: async ({ text }) => ({ content: [{ type: "text", text }] }),
  });
```

The full auth-specific footprint lives inside the `// authplane:begin` /
`// authplane:end` markers in [`server.ts`](./server.ts) and
[`agent.ts`](./agent.ts). Run `go run ./tools/loccount examples/typescript/03-mcp-server-fastmcp-dpop`
from the repo root to see the combined count.

## What's happening

`authplaneFastMcpAuth({ inboundDPoP: { required: true } })` performs RFC
8414 AS metadata discovery against `issuer`, fetches the JWKS, and returns
a FastMCP `authenticate` callback plus an RFC 9728 Protected Resource
Metadata config — both injected directly into the `FastMCP` constructor.
Every inbound MCP request runs through the callback, which:

1. Extracts the bearer (or `DPoP`) token from `Authorization`.
2. Verifies signature, audience, and expiry against the AS's JWKS.
3. Reads the `DPoP` request header, reconstructs the request `htu`, and
   verifies the proof's signature key matches the token's `cnf.jkt`
   thumbprint (RFC 9449 §7.1).
4. Enforces replay protection via an in-memory `jti` set (the per-resource
   default — supply a Redis-backed `replayStore` for multi-process
   deployments).
5. Attaches the verified session (`clientId`, `scopes`, `claims`) to the
   request so FastMCP can dispatch to the tool.

The per-tool `canAccess: requireScopes(...)` predicate is then evaluated
by FastMCP before each tool call — a token with `mcp:echo` but not
`mcp:add` can invoke `echo` but not `add_numbers`, even though the global
`authenticate` accepted it. This is the **smallest possible** authorization
split: one scope per tool, declared on the same line as the tool.

On the agent side, the SDK's `DPoPProvider` owns the keypair end-to-end.
At token-acquisition time it signs a DPoP proof on the `POST /oauth/token`
request, which causes the AS to mint a `cnf.jkt`-bound JWT. Each MCP
request then gets a fresh proof via `dpop.createProof({...})` — the proof
binds the request method + URL + access-token hash to the same key, so a
stolen token cannot be replayed from another host without the matching
private key. Audience binding (`aud`) protects against cross-resource
reuse; DPoP binding protects against cross-host reuse — the two
together implement the RFC 9449 threat model end to end.

## Use a locally-built authserver image

To build the AS from this checkout rather than pulling
`authplane/authserver:latest`, follow the **LOCAL BUILD ESCAPE
HATCH** comment block in
[`../../_shared/docker-compose.authserver.yml`](../../_shared/docker-compose.authserver.yml).
Mirror the change in this example's `docker-compose.yml` (which inlines
the same service definition) — replace the `image:` line with the
`build:` block shown in the shared file.
