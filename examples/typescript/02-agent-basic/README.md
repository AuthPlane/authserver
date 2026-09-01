# Tier 02 — Calling another resource from your MCP server (TypeScript)

<!-- loccount:begin -->
**Auth-specific code: 5 lines · Total example: 56 lines · SDK: ts-sdk 0.3.0**
<!-- loccount:end -->

When your MCP server needs to call another resource — another Mint MCP
server, an admin service, any backend that trusts Authplane — it
acquires a token via the `@authplane/sdk` Auth Client. This example
isolates that outbound OAuth call so you can see what the SDK does:
build a client, request a `client_credentials` token, present it on the
call. In your real MCP server, this code lives inside the tool handler
that needs to talk to the other resource.

> **Pairs with tier 01.** Tier 01 plays "the resource being called" —
> its authserver (`:9000` / `:9001`) and MCP server (`:8080`) must be
> running before `make verify` here. Bring it up first with `make run`
> in [`../01-mcp-server-basic/`](../01-mcp-server-basic/).
>
> The standalone `agent.ts` shape is purely for readability: in
> production the same SDK calls live inside an MCP server's tool
> handler, not in a sibling process.

## What you'll learn

- How to acquire a `client_credentials` access token from Authplane using
  the `@authplane/sdk` `AuthplaneClient`
- How to bind the issued token to a specific
  [Resource](../../../docs/concepts/glossary.md#glossary-resource) via the
  `resource=` parameter so the JWT `aud` claim matches the server you're
  calling
- How to attach the bearer token to an MCP JSON-RPC request and parse the
  streamable-http response
- How the agent side of a machine-to-machine MCP flow stays tiny when the
  SDK owns metadata discovery, token caching, and the circuit breaker

| | |
|---|---|
| **Time to run** | ~2 minutes (after tier 01 is already up) |
| **Prereqs** | Docker 24+, `docker compose`, `curl`, `jq`, Node.js 22+ (only if you run outside Docker), tier 01 running |
| **SDK** | `@authplane/sdk` 0.3.0 (npm) |
| **Runtime** | Node.js 22 + `tsx`, plain `fetch` against the MCP streamable-http transport |

## Run it in 3 commands

```bash
cp .env.example .env
make run
make verify
```

`make run` builds the agent's container image but does not start any
long-running service — the agent is a one-shot client. `make verify`
waits for tier 01 to be up, registers an OAuth client + Mint resource
against the tier-01 authserver, then runs the agent container once. The
agent mints a token and calls the tier-01 `echo` tool. `make clean`
tears down anything `docker compose` brought up and removes the `.env`
file the run target created.

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
> and 5 use them. Step 5 hands those credentials to the agent, which mints
> the access token itself inside the SDK — you never need to see the raw
> token to verify the flow works.

1. **Bring up tier 01.** This example is a pure client — the authserver
   and MCP server live in the tier-01 compose project.

   ```bash
   cd ../01-mcp-server-basic
   make run
   curl -fsS http://localhost:9000/.well-known/oauth-authorization-server
   ```

2. **Register a Mint Resource.** The Resource URI must match the JWT
   audience the tier-01 MCP server expects (`AUTHPLANE_RESOURCE`,
   defaulting to `http://localhost:8080/mcp`).

   ```bash
   curl -sS -X POST http://localhost:9001/admin/resources \
     -H "Authorization: Bearer $AUTHPLANE_ADMIN_API_KEY" \
     -H "Content-Type: application/json" \
     -d '{
       "slug": "demo-mcp",
       "uri": "http://localhost:8080/mcp",
       "backend_kind": "mint",
       "display_name": "Demo MCP",
       "scopes": [{"name": "mcp:echo", "description": "echo tool"}]
     }'
   ```

   The same Resource can be created via the CLI inside the tier-01
   authserver container. The canonical path is `admin resource create`
   (see
   [`docs/reference/cli.md#cli-admin-resource-create`](../../../docs/reference/cli.md#cli-admin-resource-create)):

   ```bash
   docker compose -f ../01-mcp-server-basic/docker-compose.yml exec authserver \
     /authserver admin resource create \
       --slug demo-mcp \
       --uri http://localhost:8080/mcp \
       --backend-kind mint \
       --display-name "Demo MCP" \
       --scopes 'mcp:echo||echo tool'
   ```

   Note the pipe-delimited `'name|upstream|description'` tuple syntax —
   the double-empty middle is intentional for Mint scopes (no upstream
   mapping). If the resource already exists from a prior tier-01 run,
   the AS returns 409 and `verify.sh` continues.

3. **Register an OAuth client for the agent.** A `client_credentials`
   machine client needs the matching grant type and a confidential auth
   method.

   ```bash
   curl -sS -X POST http://localhost:9001/admin/clients \
     -H "Authorization: Bearer $AUTHPLANE_ADMIN_API_KEY" \
     -H "Content-Type: application/json" \
     -d '{
       "client_name": "demo-agent-ts",
       "grant_types": ["client_credentials"],
       "token_endpoint_auth_method": "client_secret_basic",
       "scope": "mcp:echo"
     }'
   ```

   The response carries `client_id` and `client_secret`. The secret is
   shown once — capture it into `CLIENT_ID` / `CLIENT_SECRET`.

4. **Run the agent.** Export the captured credentials and invoke the
   agent — `@authplane/sdk` performs RFC 8414 discovery, requests a
   `client_credentials` token at `POST /oauth/token`, and the agent then
   POSTs an authenticated JSON-RPC `tools/call` to the MCP server.

   The agent container joins tier-01's compose network so it can resolve
   the service hostnames directly. The SDK enforces that the discovered
   issuer matches the configured one, so use the same
   `http://authserver:9000` value tier 01's AS was bootstrapped with —
   not `http://localhost:9000`.

   ```bash
   docker compose run --rm \
     -e AUTHPLANE_ISSUER=http://authserver:9000 \
     -e AUTHPLANE_RESOURCE=http://localhost:8080/mcp \
     -e AUTHPLANE_CLIENT_ID="$CLIENT_ID" \
     -e AUTHPLANE_CLIENT_SECRET="$CLIENT_SECRET" \
     -e MCP_URL=http://mcp-server:8080/mcp \
     agent
   ```

   `AUTHPLANE_RESOURCE` stays at the public `http://localhost:8080/mcp`
   URI — it is a logical audience identifier (the token's `aud` claim
   and the registered Mint resource URI), not a network address. The
   tier-01 MCP server validates inbound JWTs against this exact value.

   Expected output: two `[agent] ... OK` lines — one for the `initialize`
   handshake and one for the `echo` tool call that bounces the
   `ECHO_TEXT` string back.

## Before / After

An MCP client without auth — a single unauthenticated POST:

```diff
- const res = await fetch(MCP_URL, {
-   method: "POST",
-   headers: { "Content-Type": "application/json" },
-   body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/call", params }),
- });
```

The same client with Authplane token acquisition:

```diff
+ import { AuthplaneClient } from "@authplane/sdk/core";
+ const ap = await AuthplaneClient.create({
+   issuer: process.env.AUTHPLANE_ISSUER!,
+   auth: { clientId: process.env.AUTHPLANE_CLIENT_ID!, clientSecret: process.env.AUTHPLANE_CLIENT_SECRET! },
+ });
+ const token = await ap.clientCredentials(["mcp:echo"], [process.env.AUTHPLANE_RESOURCE!]);
  const res = await fetch(MCP_URL, {
    method: "POST",
-   headers: { "Content-Type": "application/json" },
+   headers: {
+     "Authorization": `Bearer ${token.accessToken}`,
+     "Content-Type": "application/json",
+     "Accept": "application/json, text/event-stream",
+   },
    body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/call", params }),
  });
```

Five lines of auth code, inside the `// authplane:begin` / `// authplane:end`
markers in [`agent.ts`](./agent.ts). Run
`go run ./tools/loccount examples/typescript/02-agent-basic` from the
repo root to see the count.

## What's happening

`AuthplaneClient.create()` performs RFC 8414 AS metadata discovery against
`issuer`, learns the token endpoint, and primes an internal token cache
and circuit breaker. `clientCredentials(scopes, resources)` then POSTs to
`/oauth/token` with `grant_type=client_credentials`, the requested scope,
and one `resource=` value per element of the resources array (RFC 8707
resource indicators). Authplane validates the client and the requested scope against the
target Resource, then mints a JWT whose `aud` claim equals the resource
URI and returns it as `access_token`. The agent attaches the token as a
`Bearer` Authorization header on the MCP request. The tier-01 MCP
server's `bearerAuth` middleware validates the JWT signature against
the AS's JWKS, then checks `aud`, `exp`, and the required `mcp:echo`
scope before dispatching to the `echo` tool. The audience-bound token is
what makes this safe: even if leaked, it is only accepted by the resource
whose URI was bound at mint time.

## Next

[Tier 03 — FastMCP server + agent with DPoP](../03-mcp-server-fastmcp-dpop/)
layers RFC 9449 DPoP onto this flow, binding access tokens to a per-agent
keypair so a stolen token cannot be replayed from another host, and adds
per-tool scope enforcement.
[Tier 04](../04-broker-upstream/) puts an MCP server in front of a Broker
upstream (GitHub) with `ConsentRequiredError` handling.

## Use a locally-built authserver image

This example does not start its own authserver by default — tier 01 owns
that. If you want to run tier 02 standalone (no tier 01 process), bring
up the gated `authserver` service in this directory's `docker-compose.yml`
with `docker compose --profile standalone up -d`. To build the AS from
this checkout rather than pulling
`authplane/authserver:latest`, follow the **LOCAL BUILD ESCAPE
HATCH** comment block in
[`../../_shared/docker-compose.authserver.yml`](../../_shared/docker-compose.authserver.yml).
Mirror the change in this example's `docker-compose.yml` (the
`authserver` service mirrors the same definition) — replace the `image:`
line with the `build:` block shown in the shared file.
