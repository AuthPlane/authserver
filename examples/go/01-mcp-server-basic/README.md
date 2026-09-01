# Tier 01 — Basic MCP server (Go)

<!-- loccount:begin -->
**Auth-specific code: 5 lines · Total example: 49 lines · SDK: go-sdk v0.2.0**
<!-- loccount:end -->

A minimal MCP server protected by Authplane-issued JWTs. Everything you
need to authenticate inbound MCP calls fits inside a single five-line block
in `main.go`; the rest of the file is plain MCP boilerplate.

## What you'll learn

- How to wire Authplane JWT validation into an MCP server with the
  `github.com/authplane/go-sdk/mcp` adapter
- How to register a Mint [Resource](../../../docs/concepts/glossary.md#glossary-resource)
  whose URI matches the JWT audience your server expects
- How to register an OAuth client with the `client_credentials` grant
- How to mint a machine token and call a protected MCP tool

## Prereqs

`make check-prereqs` (auto-invoked by `make run`) enforces these and fails
loud with install hints if any are missing.

| Tool | Version | Install (macOS / Linux) |
|---|---|---|
| **Go** | 1.25+ | `brew install go` / [go.dev/dl](https://go.dev/dl/) |
| **Docker** | 24+ (daemon running) | Docker Desktop / Rancher Desktop |
| **curl** | any | preinstalled |
| **jq** | any | `brew install jq` / `apt install jq` |

The AS container binds **9000** (public) and **9001** (admin); the MCP
server binds **8080**. Conflicts are the most common startup failure — see
Troubleshooting below.

| | |
|---|---|
| **Time to run** | Under a minute warm-cache (`go build` + AS image pull) |
| **SDK** | `github.com/authplane/go-sdk/mcp` v0.2.0 (Go module proxy) |
| **MCP framework** | `github.com/modelcontextprotocol/go-sdk v1.4.1` (matches `go.mod`) |

## Run it

```bash
make run        # builds the MCP binary, starts the AS in a container, launches the server natively
make verify     # registers Resource + client, mints a token, calls the protected tool
make logs       # tails the last 40 lines of AS + MCP-server logs
make status     # one-line health of the AS container + MCP process
make clean      # stops everything; KEEPS .env
make distclean  # full reset including .env
```

The basic flow doesn't build any Dockerfiles. The AS is pulled as a
published image; the MCP server is a plain Go binary built with
`go build` and exec'd on the host. First run downloads the AS image
(~30 MB) and the Go modules; subsequent runs start in seconds.
`make run` auto-creates `.env` from `.env.example` on first run.

For the all-in-containers flow (slower first build, useful as a deployment
shape reference) use `make docker-run` / `make docker-clean`.

## Troubleshooting

**`bind: address already in use` on `make run`**
Another Authplane example is sitting on :9000, :9001, or :8080. Reset:
```bash
make clean
docker ps -aq --filter name=authplane | xargs -r docker rm -f
make run
```

**`make verify` hangs at "waiting for ..."**
Something didn't come up. Inspect each component:
```bash
make status   # is everything actually running?
make logs     # last 40 lines from AS + MCP-server
```

**`make verify` returns `invalid_token`**
JWT audience mismatch. The Resource URI must agree byte-for-byte across
the SDK config, the `/admin/resources` registration, and the
`resource=...` form param on the token request. The default flow gets
this right; you'll only hit it if you changed `MCP_PORT`.

**`ERROR: jq not found` from `make verify`**
`brew install jq` (macOS) or `apt install jq` (Debian/Ubuntu).

**`missing go.sum entry for module providing package github.com/authplane/go-sdk/core/...`**
`go get github.com/authplane/go-sdk/mcp@v0.2.0` pulls the `mcp` adapter but
not its transitive `go-sdk/core` dependency, so the next `go build` fails on
the missing checksum. Run `go mod tidy` (or
`go get github.com/authplane/go-sdk/mcp/pkg/authplanemcp@v0.2.0`) to record
`core` in `go.sum`. The committed `go.mod`/`go.sum` here already have it;
you only hit this when adding the adapter to your own module.

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
> - **MCP server in the same Docker network as the AS** (the example default) → `http://authserver:9000` on both.
> - **MCP server on the host, another machine, or public** → `http://localhost:9000` (or your real hostname) on both.
>
> Get it wrong and every call 401s with an opaque `invalid_token` — the token is valid, but the SDK discovered metadata at one host while the JWT's `iss` says another.

The two common topologies:

| Topology | `AUTHPLANE_SERVER_ISSUER` (AS) | `AUTHPLANE_ISSUER` (SDK) |
|---|---|---|
| Same docker network (the example default) | `http://authserver:9000` | `http://authserver:9000` |
| **AS in a container, MCP server on the host** (the common dev path) | `http://localhost:9000` | `http://localhost:9000` |

For the host-side topology, run the AS with `docker run -p 9000:9000 -p 9001:9001 -e AUTHPLANE_SERVER_ISSUER=http://localhost:9000 ...` and your Go server reads the same `http://localhost:9000` from its env. Don't mix the two — `authserver:9000` is not resolvable from your host, and `localhost:9000` inside a container points at itself.

**2. The `Resource` field on `authplanemcp.Options` is the JWT
audience byte-for-byte.** It must match the URL your MCP server
actually serves on — scheme, host, **port**, and **path** included.
If you change any of those, all three of these must agree:

- `Resource:` field on `authplanemcp.Options` (or `AUTHPLANE_RESOURCE`
  env)
- `uri` field on the Resource you register at the AS
- The URL the MCP client actually reaches

Custom port: `PORT=9090 go run ./` runs on `:9090`, so the Resource
URI becomes `http://localhost:9090/mcp` and the AS registration must
use that same URI. Custom path: change the `Resource` value AND
register the Resource with that same URI. Mismatches produce an
opaque `invalid_token` on every call — the JWT `aud` won't match
what the SDK expects.

**3. The scope string is a join key across four places.** Pick a name
once (here: `mcp:echo`) and use it in all four of these without
varying:

| # | Where it appears |
|---|------------------|
| 1 | `Scopes: []string{"mcp:echo"}` in `authplanemcp.Options` (SDK config) |
| 2 | `scopes: [{ name: "mcp:echo", ... }]` on `POST /admin/resources` |
| 3 | `scope: "mcp:echo"` on `POST /admin/clients` |
| 4 | `scope=mcp:echo` form param on `POST /oauth/token` |

A mismatch in any one of them produces `invalid_scope` from the AS or
`insufficient_scope` from the SDK. The full lifecycle (with what each
side enforces) lives in [docs/concepts/resources-and-scopes.md ›
Lifecycle of a scope](../../../docs/concepts/resources-and-scopes.md#lifecycle-of-a-scope--the-four-places-the-same-name-appears).

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
   audience the MCP server will expect. The default `AUTHPLANE_RESOURCE`
   in this example is `http://localhost:8080/mcp`.

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

## Before / After

A plain MCP Go server, no auth:

```go
server := mcp.NewServer(&mcp.Implementation{Name: "demo-server", Version: "1.0.0"}, nil)
handler := mcp.NewStreamableHTTPHandler(func(_ *http.Request) *mcp.Server { return server }, nil)
http.Handle("/mcp", handler)
http.ListenAndServe(":8080", nil)
```

The same server with Authplane JWT validation:

```diff
+ adapter := must(authplanemcp.NewAdapter(ctx, authplanemcp.Options{
+     Issuer: os.Getenv("AUTHPLANE_ISSUER"), Resource: os.Getenv("AUTHPLANE_RESOURCE"),
+     Scopes: []string{"mcp:echo"}, DevMode: true,
+ }))
+ defer adapter.Close()
+ http.Handle(adapter.WellKnownPRMPath(), adapter.ProtectedResourceMetadataHandler())
- http.Handle("/mcp", handler)
+ http.Handle("/mcp", adapter.AuthMiddleware(handler))
  http.ListenAndServe(":8080", nil)
```

`must(v, err)` is not from the SDK or stdlib — it's a tiny generic helper this example defines at the bottom of [`main.go`](./main.go) (`func must[T any](v T, err error) T { if err != nil { log.Fatal(err) }; return v }`). It keeps the auth-setup block focused on the SDK call. In production code, replace it with explicit error handling:

```go
adapter, err := authplanemcp.NewAdapter(ctx, opts)
if err != nil { /* return / log / retry — your call */ }
defer adapter.Close()
```

Five lines of auth code (counting only what's inside `// authplane:begin` / `// authplane:end`) plus two mount lines (`PRM handler`, `AuthMiddleware`) plus the `must`-or-equivalent error-handling line. Run `go run ./tools/loccount examples/go/01-mcp-server-basic` from the repo root to see the auth-line count CI enforces.


## What's happening

`authplanemcp.NewAdapter` performs RFC 8414 AS metadata discovery
against `Issuer`, fetches the JWKS, and constructs a verifier bound to
the Resource URI. The returned `Adapter` exposes
`AuthMiddleware` (which wraps an `http.Handler` and enforces
bearer-token authentication via `auth.RequireBearerToken` from the MCP
go-sdk) and `ProtectedResourceMetadataHandler`
(which serves the RFC 9728 Protected Resource Metadata document at the
canonical well-known path). Every inbound HTTP request to `/mcp` is
checked against the AS's JWKS for signature validity, then the audience
and `exp` claims are validated. The `Resource` you pass to `NewAdapter`
becomes the JWT audience the verifier requires, so the
[Mint backend](../../../docs/concepts/glossary.md#glossary-mint-backend)
Resource you register at the AS must declare its `uri` to match. The
`client_credentials` grant is the simplest way to mint a machine token
for the resource — no user, no consent, just a registered confidential
client asking for the resource and a scope it owns.

## Before production

This example is wired for local development. Before deploying:

| Setting | Dev value (here) | Production value | Why |
|---|---|---|---|
| `DevMode: true` in `authplanemcp.Options{...}` | `true` | **`false`** (or remove — it's the default) | Relaxes the SDK's SSRF guard so it accepts `http://`, `localhost`, and private-network issuers. Leaving it on in production weakens defense-in-depth against SSRF. |
| `AUTHPLANE_ISSUER` | `http://localhost:9000` | `https://auth.example.com` | Production issuers MUST be `https://`. The AS itself refuses to start with a non-localhost issuer unless cookies are also `Secure` (see next row). |
| `AUTHPLANE_SESSION_SECURE` | `true` (the example already sets this because `authserver:9000` is non-localhost) | `true` | Required by the AS's own startup validation whenever `server.issuer` is non-localhost. The AS refuses to start otherwise. Set to `false` only when both the issuer and Admin UI are reached strictly via `http://localhost`. |
| `AUTHPLANE_SESSION_SECRET` | `dev-session-secret-change-me` | `openssl rand -hex 32` | Used to sign session cookies — leaking it lets an attacker forge admin sessions. |
| `AUTHPLANE_ADMIN_API_KEY` | `dev-admin-key-change-me` | `openssl rand -hex 32` | Bearer for the entire admin surface. Treat like a root password. |
| Storage | SQLite in a Docker volume | PostgreSQL (`AUTHPLANE_STORAGE_DRIVER=postgres`) | SQLite is single-instance. PostgreSQL is required for HA. |
| Signing keys | Auto-generated in `/data/keys` | HashiCorp Vault Transit | See [`docs/guides/deploy/hashicorp-vault-transit.md`](../../../docs/guides/deploy/hashicorp-vault-transit.md). |
| Distroless base image | `gcr.io/distroless/static-debian12:nonroot` (no tzdata) | Add tzdata or switch base | The example Dockerfile uses distroless `static` which omits `/usr/share/zoneinfo`. If any of your tools calls `time.LoadLocation("America/New_York")` (or similar), it silently falls back to UTC. Either embed the tzdata at build time (`import _ "time/tzdata"` in your `main.go`) or switch the runtime base to `gcr.io/distroless/base-debian12:nonroot`. |
| `must[T]` helper | Five-line generic at the bottom of `main.go`, `log.Fatal` on error | Explicit `if err != nil { ... }` with retry, structured log, and graceful shutdown | The helper exists to keep the auth-setup block focused; it isn't production error handling. |

## Next

[Tier 02 — Calling another resource from your MCP server](../02-agent-basic/)
shows the same MCP server minting a `client_credentials` token via the SDK
to call a second protected resource. [Tier 03](../03-mcp-server-dpop-scopes/)
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
