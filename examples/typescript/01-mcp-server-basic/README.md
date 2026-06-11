# Tier 01 — Basic MCP server (TypeScript)

<!-- loccount:begin -->
**Auth-specific code: 5 lines · Total example: 53 lines · SDK: ts-sdk 0.2.0**
<!-- loccount:end -->

A minimal MCP server protected by Authplane-issued JWTs. Everything you need
to authenticate inbound MCP calls fits inside a single five-line block in
`server.ts`; the rest of the file is plain MCP boilerplate.

## What you'll learn

- How to wire Authplane JWT validation into an Express + MCP TypeScript SDK
  server with the `@authplane/mcp` adapter
- How to register a Mint [Resource](../../../docs/concepts/glossary.md#glossary-resource)
  whose URI matches the JWT audience your server expects
- How to register an OAuth client with the `client_credentials` grant
- How to mint a machine token and call a protected MCP tool

## Prereqs

`make check-prereqs` (auto-invoked by `make run`) enforces these and fails
loud with install hints if any are missing.

| Tool | Version | Install (macOS / Linux) |
|---|---|---|
| **Node.js** | 22+ | `brew install node@22` / [nodejs.org](https://nodejs.org/) / `nvm install 22 && nvm use 22` |
| **Docker** | 24+ (daemon running) | Docker Desktop / Rancher Desktop |
| **curl** | any | preinstalled |
| **jq** | any | `brew install jq` / `apt install jq` |

`@authplane/sdk` and `@authplane/mcp` are ESM-only (`"type": "module"` in
`package.json`). CommonJS consumers will hit `ERR_REQUIRE_ESM` — the
example's `package.json` shows the minimum ESM config.

The AS container binds **9000** (public) and **9001** (admin); the MCP
server binds **8080**. Conflicts are the most common startup failure —
see Troubleshooting below.

| | |
|---|---|
| **Time to run** | About a minute first-run (`npm install` + AS pull); ~5 s warm |
| **SDK** | `@authplane/sdk` + `@authplane/mcp` 0.2.0 (npm) |
| **MCP framework** | Express + the official MCP TS SDK (`@modelcontextprotocol/sdk`) |

## Run it

```bash
make run        # npm-installs (first run only), starts the AS in a container, launches the server via tsx
make verify     # registers Resource + client, mints a token, calls the protected tool
make logs       # tails the last 40 lines of AS + MCP-server logs
make status     # one-line health of the AS container + Node process
make clean      # stops everything; KEEPS .env and node_modules
make distclean  # full reset including .env
```

The basic flow doesn't build any Dockerfiles. The AS is pulled as a
published image; the MCP server is a plain Node process run via `tsx`
directly from `node_modules/.bin/` (avoiding the `npx` wrapper's
process-orphaning surprise). First run downloads the AS image (~30 MB)
and `npm install`s the project; subsequent runs start in seconds.

For the all-in-containers flow (slower first build) use `make docker-run`
/ `make docker-clean`.

## Troubleshooting

**`bind: address already in use` on `make run`**
Another Authplane example is sitting on :9000, :9001, or :8080. Reset:
```bash
make clean
docker ps -aq --filter name=authplane | xargs -r docker rm -f
make run
```

**`ERROR: node v20.x.x is too old. Install Node.js 22+.`**
Update via `brew upgrade node`, or switch with `nvm install 22 && nvm use 22`.

**`make verify` hangs at "waiting for ..."**
Inspect with `make status` and `make logs`. A common Node-side cause:
`await authplaneMcpAuth(...)` at module load couldn't reach the AS. The
error is in `.run/mcp.log`.

**`make verify` returns `invalid_token`**
JWT audience mismatch — the `resource` you passed to
`authplaneMcpAuth({...})`, the Resource URI at the AS, and the
`resource=...` form param on the token request must agree byte-for-byte.

**Stale state**
`make distclean` is the full reset.

## Adapting this to your project

If you're copying this example into your own project, two configuration
constraints matter the moment you deviate from the defaults:

**1. The two issuer URLs must share the same hostname.** The AS process
reads `AUTHPLANE_SERVER_ISSUER` (what hostname it announces in its
metadata document and bakes into every JWT's `iss` claim). The SDK
inside your MCP server reads `AUTHPLANE_ISSUER` (where to fetch that
metadata). The SDK enforces `metadata.issuer == config.issuer` and
fails fast on mismatch.

> **This is a decision, not a default — pick by topology and set both vars to the same host:**
> - **MCP server in the same Docker network as the AS** → `http://authserver:9000` on both.
> - **MCP server on the host, another machine, or public** → `http://localhost:9000` (or your real hostname) on both.
>
> Get it wrong and every call 401s with an opaque `invalid_token` — the token is valid, but the SDK discovered metadata at one host while the JWT's `iss` says another.

**2. The Resource URI you pass to `authplaneMcpAuth({ resource: ... })`
is the JWT audience byte-for-byte.** It must match the URL your MCP
server actually serves on — scheme, host, **port**, and **path**
included. If you change any of those, all three of these must agree:

- `resource:` argument to `authplaneMcpAuth({...})` (or
  `AUTHPLANE_RESOURCE` env)
- `uri` field on the Resource you register at the AS
- The URL the MCP client actually reaches

Custom port: `PORT=9090 npx tsx server.ts` runs on `:9090`, so the
Resource URI becomes `http://localhost:9090/mcp` and the AS
registration must use that same URI. Custom path: pass it as part of
`resource:` (e.g. `http://localhost:8080/api/mcp`) and register the
Resource with that same URI. Mismatches produce an opaque
`invalid_token` on every call — the JWT `aud` won't match what the
SDK expects.

**3. The scope string is a join key across four places.** Pick a name
once (here: `mcp:echo`) and use it in all four of these without
varying:

| # | Where it appears |
|---|------------------|
| 1 | `scopes: ["mcp:echo"]` in `authplaneMcpAuth({...})` (SDK config) |
| 2 | `scopes: [{ name: "mcp:echo", ... }]` on `POST /admin/resources` |
| 3 | `scope: "mcp:echo"` on `POST /admin/clients` |
| 4 | `scope=mcp:echo` form param on `POST /oauth/token` |

A mismatch in any one of them produces `invalid_scope` from the AS or
`insufficient_scope` from the SDK. The full lifecycle (with what each
side enforces) lives in [docs/concepts/resources-and-scopes.md ›
Lifecycle of a scope](../../../docs/concepts/resources-and-scopes.md#lifecycle-of-a-scope--the-four-places-the-same-name-appears).

**Tooling note:** `Accept: application/json, text/event-stream` is
mandatory on every MCP request — the streamable-http transport returns
SSE-framed responses for some methods and a missing/wrong `Accept`
gets a 406. On macOS, parsing the SSE wrapper with `sed` runs into
BSD-vs-GNU differences; `scripts/verify.sh` uses `awk` to stay portable.

### Tool argument types (Zod)

The `server.registerTool<Args, Args>(...)` shape pattern needs the
generic Args type to match the runtime Zod shape literally. The bare
`z.string()` form works as the example shows it. Modifiers that wrap
the type (`.default(...)`, `.optional()`, `.nullable()`, `.enum([...])`)
widen the Zod type and break the explicit-generic signature. Two
options:

```ts
// Option 1: drop the explicit generic and let TS infer everything.
server.registerTool(
  "now",
  { inputSchema: { tz: z.string().default("UTC") } },
  async ({ tz }) => ({ content: [{ type: "text" as const, text: tz }] }),
);

// Option 2: widen the shape type to z.ZodTypeAny when you need modifiers.
type NowArgs = { tz: z.ZodTypeAny };
const nowShape: NowArgs = { tz: z.string().default("UTC") };
server.registerTool<NowArgs, NowArgs>("now", { inputSchema: nowShape }, ...);
```

Use option 1 for new tools and option 2 only when you have a reason to
pin the generic explicitly (e.g. a helper that takes the shape as a
parameter). The `as const` on the content `type` field is required so
the union narrows to `"text"` instead of widening to `string`.

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
> Steps 3 and 5 emit `client_id`, `client_secret`, and `access_token` in
> their responses; assign each to a shell variable (`CLIENT_ID=...`,
> `CLIENT_SECRET=...`, `ACCESS_TOKEN=...`) before the next step uses it.

1. **Start authserver + MCP server.** `make run` brings both up. Wait for
   the AS discovery endpoint to return 200:

   ```bash
   curl -fsS http://localhost:9000/.well-known/oauth-authorization-server
   ```

2. **Register a Mint Resource.** The Resource URI must match the JWT
   audience the MCP server will expect (the `AUTHPLANE_RESOURCE` env var).
   The default in this example is `http://localhost:8080/mcp`.

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

   The same Resource can be created via the CLI inside the container.
   The canonical path is `admin resource create` (see
   [`docs/reference/cli.md#cli-admin-resource-create`](../../../docs/reference/cli.md#cli-admin-resource-create)):

   ```bash
   docker compose exec authserver /authserver admin resource create \
     --slug demo-mcp \
     --uri http://localhost:8080/mcp \
     --backend-kind mint \
     --display-name "Demo MCP" \
     --scopes 'mcp:echo||echo tool'
   ```

   Note the pipe-delimited `'name|upstream|description'` tuple syntax —
   the double-empty middle is intentional for Mint scopes (no upstream
   mapping).

3. **Register an OAuth client.** A `client_credentials` machine client
   needs the matching grant type and a confidential auth method.

   ```bash
   curl -sS -X POST http://localhost:9001/admin/clients \
     -H "Authorization: Bearer $AUTHPLANE_ADMIN_API_KEY" \
     -H "Content-Type: application/json" \
     -d '{
       "client_name": "demo-mcp-client",
       "grant_types": ["client_credentials"],
       "token_endpoint_auth_method": "client_secret_basic",
       "scope": "mcp:echo"
     }'
   ```

   The response carries `client_id` and `client_secret`. The secret is
   shown once.

4. **Mint a `client_credentials` access token.** Pass the `resource=`
   parameter so the AS sets the JWT audience to the URI you registered.

   ```bash
   curl -sS -X POST http://localhost:9000/oauth/token \
     -u "$CLIENT_ID:$CLIENT_SECRET" \
     -d "grant_type=client_credentials" \
     -d "scope=mcp:echo" \
     --data-urlencode "resource=http://localhost:8080/mcp"
   ```

   The response includes `access_token`, `token_type=Bearer`, `expires_in`,
   and `scope`. There is no refresh token for `client_credentials`.

5. **Call the MCP tool with the bearer token.** The streamable-http
   transport is a 3-step handshake: `initialize` (grab the
   `mcp-session-id` response header), `notifications/initialized` (with
   that session header), then `tools/call`. The shortest authenticated
   probe is just step 1:

   ```bash
   curl -sS -X POST http://localhost:8080/mcp \
     -H "Authorization: Bearer $ACCESS_TOKEN" \
     -H "Content-Type: application/json" \
     -H "Accept: application/json, text/event-stream" \
     -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{
       "protocolVersion":"2024-11-05","capabilities":{},
       "clientInfo":{"name":"demo","version":"1.0"}}}'
   ```

   Without the `Authorization` header the server returns HTTP 401 — proof
   that the integration is actually enforcing auth. The full
   `initialize` → `notifications/initialized` → `tools/call echo`
   round-trip (which proves the auth chain reaches a real tool, not just
   the initialize handler) is documented at
   [`docs/reference/mcp-streamable-http.md`](../../../docs/reference/mcp-streamable-http.md)
   — the three POSTs, the headers that matter, and the 4xx responses
   you'll hit if any of them are wrong.

   You can also confirm the PRM document is being served at the path the
   401 response advertises:

   ```bash
   curl -sS http://localhost:8080/.well-known/oauth-protected-resource/mcp | jq .
   # → {
   #     "resource": "http://localhost:8080/mcp",
   #     "authorization_servers": ["http://localhost:9000"],
   #     "scopes_supported": ["mcp:echo"],
   #     "bearer_methods_supported": ["header"]
   #   }
   ```

   The literal path is what `auth.protectedResourceMetadataPath` evaluates
   to — `/.well-known/oauth-protected-resource/<mcp-path>` per the MCP
   spec (suffixed with the resource's URL path component).

## Before / After

A plain Express + MCP TS SDK server, no auth:

```diff
- const app = express();
- app.use(express.json());
- app.all("/mcp", async (req, res) => { /* ...transport... */ });
```

The same server with Authplane JWT validation:

```diff
+ const auth = await authplaneMcpAuth({
+   issuer: process.env.AUTHPLANE_ISSUER!,
+   resource: process.env.AUTHPLANE_RESOURCE!,
+   scopes: ["mcp:echo"], devMode: true,
+ });
  const app = express();
  app.use(express.json());
+ app.get(auth.protectedResourceMetadataPath, auth.protectedResourceMetadataHandler);
- app.all("/mcp", async (req, res) => { /* ...transport... */ });
+ app.all("/mcp", auth.bearerAuth, async (req, res) => { /* ...transport... */ });
```

Five lines of auth code, inside the `// authplane:begin` / `// authplane:end`
markers in [`server.ts`](./server.ts). Run
`go run ./tools/loccount examples/typescript/01-mcp-server-basic` from the
repo root to see the count.

## What's happening

The `authplaneMcpAuth()` factory performs RFC 8414 AS metadata discovery
against `issuer`, fetches the JWKS, and returns an Express middleware
(`auth.bearerAuth`) plus an RFC 9728 Protected Resource Metadata handler
(`auth.protectedResourceMetadataHandler`) served at
`auth.protectedResourceMetadataPath`. Every inbound MCP request goes
through `bearerAuth`, which extracts the `Authorization: Bearer …` header,
validates the JWT against the AS's JWKS for signature, then checks the
audience, `exp`, and required scopes. The JWT audience must equal the
`resource` you pass in — so the [Mint backend](../../../docs/concepts/glossary.md#glossary-mint-backend)
Resource you register at the AS must declare its `uri` to match. The
`client_credentials` grant is the simplest way to mint a machine token
for the resource — no user, no consent, just a registered confidential
client asking for the resource and a scope it owns.

## Before production

This example is wired for local development. Before deploying:

| Setting | Dev value (here) | Production value | Why |
|---|---|---|---|
| `devMode: true` in `authplaneMcpAuth(...)` | `true` | **`false`** (or remove — it's the default) | Relaxes the SDK's SSRF guard so it accepts `http://`, `localhost`, and private-network issuers. Leaving it on in production weakens defense-in-depth against SSRF. |
| `AUTHPLANE_ISSUER` | `http://localhost:9000` | `https://auth.example.com` | Production issuers MUST be `https://`. The AS itself refuses to start with a non-localhost issuer unless cookies are also `Secure` (see next row). |
| `AUTHPLANE_SESSION_SECURE` | `true` (the example already sets this because `authserver:9000` is non-localhost) | `true` | Required by the AS's own startup validation whenever `server.issuer` is non-localhost. The AS refuses to start otherwise. Set to `false` only when both the issuer and Admin UI are reached strictly via `http://localhost`. |
| `AUTHPLANE_SESSION_SECRET` | `dev-session-secret-change-me` | `openssl rand -hex 32` | Used to sign session cookies — leaking it lets an attacker forge admin sessions. |
| `AUTHPLANE_ADMIN_API_KEY` | `dev-admin-key-change-me` | `openssl rand -hex 32` | Bearer for the entire admin surface. Treat like a root password. |
| Storage | SQLite in a Docker volume | PostgreSQL (`AUTHPLANE_STORAGE_DRIVER=postgres`) | SQLite is single-instance. PostgreSQL is required for HA. |
| Signing keys | Auto-generated in `/data/keys` | HashiCorp Vault Transit | See [`docs/guides/deploy/hashicorp-vault-transit.md`](../../../docs/guides/deploy/hashicorp-vault-transit.md). |

## Next

[Tier 02 — Calling another resource from your MCP server](../02-agent-basic/)
shows the same MCP server minting a `client_credentials` token via the SDK
to call a second protected resource. [Tier 03](../03-mcp-server-fastmcp-dpop/)
adds DPoP-bound tokens and per-tool scope enforcement.
[Tier 04](../04-broker-upstream/) puts an MCP server in front of a Broker
upstream (GitHub) with `ConsentRequiredError` handling.

## Use a locally-built authserver image

To build the AS from this checkout rather than pulling
`authplane/authserver:latest`, follow the **LOCAL BUILD ESCAPE
HATCH** comment block in
[`../../_shared/docker-compose.authserver.yml`](../../_shared/docker-compose.authserver.yml).
Mirror the change in this example's `docker-compose.yml` (which inlines
the same service definition) — replace the `image:` line with the
`build:` block shown in the shared file.
