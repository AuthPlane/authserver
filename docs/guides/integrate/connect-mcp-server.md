# Connect an MCP Server — wire JWT validation into the server you already have

*Context: this is part of [Guides — Integrate](README.md). Start with the primer if you haven't.*

**Audience:** Builders with an existing MCP server in Go, TypeScript, or Python who want Authplane to issue and validate tokens for it.

> **Prefer a runnable diff?** The retrofit example is a complete before/after pair for the exact case this guide covers — same MCP server with three tools in two versions side-by-side, plus a `make verify` that proves the `before` accepts anything and the `after` enforces auth. [Python](../../../examples/python/retrofit-existing-mcp-server/) · [TypeScript](../../../examples/typescript/retrofit-existing-mcp-server/) · [Go](../../../examples/go/retrofit-existing-mcp-server/). This guide is the prose version of what those examples encode.

## What you'll achieve in 15 minutes

- A [Resource](../../concepts/glossary.md#glossary-resource) registered in Authplane that represents your MCP server
- A [Protected Resource Metadata](../../concepts/glossary.md#glossary-protected-resource-metadata) document published from your MCP endpoint
- JWT validation on every `POST /mcp` call, rejecting unauthorized requests
- A test agent successfully calling a tool with a Bearer token

## Prereqs

- Authplane running on `http://localhost:9000` (public) / `http://localhost:9001` (admin). The fastest path is the published image — see [Get Started → Quickstart with Docker](../../start/02-quickstart-docker.md) for the one-line `docker run` against `authplane/authserver:latest`. Build from source only if you're contributing to the AS itself.
- `AUTHPLANE_ADMIN_API_KEY` exported in your shell.
- Concept context: [Resource](../../concepts/glossary.md#glossary-resource), [Mint backend](../../concepts/glossary.md#glossary-mint-backend), [JWKS](../../concepts/glossary.md#glossary-jwks), [Audience](../../concepts/glossary.md#glossary-audience).

## Steps

### 1. Register your MCP server as a Mint Resource

Pick a slug, a URI, and the tool scopes you want to expose. The URI you register here is the **canonical** form — every other place that names this Resource (your PRM document, the agent's `resource=` parameter, the JWT `aud`) must match it byte-for-byte.

```bash
# Command verified against docs/reference/cli.md#cli-admin-resource-create
authserver admin resource create \
  --slug my-mcp \
  --display-name "My MCP server" \
  --backend-kind mint \
  --uri http://localhost:8080/mcp \
  --scopes 'mcp:echo||Echo a message' \
  --scopes 'mcp:query_database||Query the database'
```

Equivalent admin API call:

```bash
# Wire shape verified against docs/reference/http-api.md#http-admin-resources-create
curl -sS -X POST http://localhost:9001/admin/resources \
  -H "Authorization: Bearer $AUTHPLANE_ADMIN_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "slug": "my-mcp",
    "display_name": "My MCP server",
    "backend_kind": "mint",
    "uri": "http://localhost:8080/mcp",
    "scopes": [
      {"name": "mcp:echo", "description": "Echo a message"},
      {"name": "mcp:query_database", "description": "Query the database"}
    ]
  }'
```

Or seed it at startup in YAML — see [`docs/reference/configuration.md`](../../reference/configuration.md#config-resources) under `resources`.

### 2. Publish Protected Resource Metadata

Your MCP server must serve a PRM document that points back at Authplane. The MCP spec says the path is `/.well-known/oauth-protected-resource` with the **resource path suffixed** — so if your MCP endpoint is at `/mcp`, the PRM URL is `/.well-known/oauth-protected-resource/mcp`. The MCP-adapter SDKs (`authplane-fastmcp`, `go-sdk/mcp`) publish at the correct suffixed path automatically; if you're rolling your own, follow the spec.

The document looks like this:

```json
{
  "resource": "http://localhost:8080/mcp",
  "authorization_servers": ["http://localhost:9000"],
  "scopes_supported": ["mcp:echo", "mcp:query_database"],
  "bearer_methods_supported": ["header"]
}
```

The `resource` field must match the `--uri` you registered in step 1 exactly — including scheme, host, port, path, and trailing-slash form. Use the [MCP canonical form](https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization#canonical-server-uri) (no trailing slash). On a 401 your server should emit `WWW-Authenticate: Bearer resource_metadata="<PRM URL>"` so the client can rediscover the AS.

### 3. Validate JWTs on the MCP endpoint

> **Pick the issuer hostname by topology — both sides must agree.**
> `AUTHPLANE_SERVER_ISSUER` (what the AS *announces*) and `AUTHPLANE_ISSUER`
> (where your SDK *discovers* metadata + JWKS) must resolve to the same host:
> - **MCP server in the same Docker network as the AS** → `http://authserver:9000` on both.
> - **MCP server on the host / another machine / public** → `http://localhost:9000` (or your real public hostname) on both.
>
> A mismatch is the silent `invalid_token` trap: the JWT's `iss` says one
> host, the SDK fetched metadata from another, and the otherwise-valid token
> is rejected. This is `iss` validation (step 4 below) failing, not a bad token.

For every request to your MCP endpoint, your server must:

1. Pull the `Authorization: Bearer <token>` header. If missing, return `401` with `WWW-Authenticate: Bearer resource_metadata="http://localhost:8080/.well-known/oauth-protected-resource/mcp"` (suffix matches your MCP endpoint path — see step 2).
2. Fetch Authplane's JWKS from `<issuer>/.well-known/jwks.json` (cache for 5 minutes, refresh on unknown `kid`).
3. Verify the JWT signature against the JWKS.
4. Validate claims: `iss == <your issuer URL>`, `aud` contains your Resource URI, `exp > now`.
5. For per-tool authorization, check the `scope` claim — return `403 {"error":"insufficient_scope"}` if the required scope is missing.

The [Resource Server SDK guide](sdk-resource-server.md) covers the language-specific middleware that does all of this in five lines. For raw HTTP, see the per-language tier-01 examples linked below.

### 4. Send a test request

Mint a token (see the [Auth Client SDK guide](sdk-auth-client.md) for the long version):

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

Call your MCP endpoint with the returned `access_token`. The
**streamable-http transport requires a 3-step handshake** — `initialize`
returns an `mcp-session-id` response header that every subsequent request
must carry, and the client must send a `notifications/initialized`
notification before issuing tool calls:

```bash
# (a) initialize — capture the mcp-session-id response header
SESSION_ID=$(curl -sS -D - -X POST http://localhost:8080/mcp \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -H "Accept: application/json, text/event-stream" \
  -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{
    "protocolVersion":"2024-11-05","capabilities":{},
    "clientInfo":{"name":"curl","version":"1.0"}}}' \
  | awk 'tolower($1)=="mcp-session-id:"{print $2}' | tr -d '\r')

# (b) notifications/initialized — required before tools become callable
curl -sS -X POST http://localhost:8080/mcp \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H "Mcp-Session-Id: $SESSION_ID" \
  -H "Content-Type: application/json" \
  -H "Accept: application/json, text/event-stream" \
  -d '{"jsonrpc":"2.0","method":"notifications/initialized"}'

# (c) tools/call — the actual authenticated tool invocation
curl -sS -X POST http://localhost:8080/mcp \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H "Mcp-Session-Id: $SESSION_ID" \
  -H "Content-Type: application/json" \
  -H "Accept: application/json, text/event-stream" \
  -d '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"echo","arguments":{"text":"hello"}}}'
```

Skip step (b) and `tools/call` returns a "session not initialized" error;
skip the `Mcp-Session-Id` header on step (c) and the MCP server treats it as
a fresh session and rejects the call. Real MCP clients handle this for you
— the curl version is here because copying it once is the fastest way to
debug an MCP server.

### Streamable-http transport cheat sheet

When you're debugging an MCP call by hand, these are the wire-level
facts that matter:

- **`Accept: application/json, text/event-stream`** is mandatory on every
  request. Missing or wrong — `406 Not Acceptable`.
- **`mcp-session-id`** is a **response header** on `initialize`, not a
  body field. HTTP header names are case-insensitive — the header may
  come back as `Mcp-Session-Id` from the server. When parsing it
  yourself, lowercase the header name first.
- **`notifications/initialized`** is a JSON-RPC *notification* (no `id`,
  no body in the response). Servers return `202 Accepted`. Do not parse
  the response body — there isn't one.
- **`tools/call`** responses are SSE-framed: the body looks like
  `event: message\ndata: {…json…}\n\n`. Strip the `data: ` prefix to
  get the JSON payload.
- **The same `Mcp-Session-Id`** must accompany every request after
  `initialize` (notifications, `tools/list`, `tools/call`). A missing
  or unknown session id is treated as a fresh client and rejected.

## Verify

```bash
# Healthcheck — should return 200
curl -sS -o /dev/null -w '%{http_code}\n' http://localhost:9000/health
# Expect: 200

# PRM document — should echo your canonical URI. Note the path suffix:
# the MCP spec serves PRM at /.well-known/oauth-protected-resource/<mcp-path>.
curl -sS http://localhost:8080/.well-known/oauth-protected-resource/mcp | jq -r .resource
# Expect: http://localhost:8080/mcp

# Resource is registered — should list "my-mcp"
# Command verified against docs/reference/cli.md#cli-admin-resource-list
authserver admin resource list --backend-kind mint
```

## What can go wrong

For a full decision-tree on 401s (aud mismatch vs signature vs scope vs DPoP vs revoked), see [Debugging 401s](debugging-401s.md). Common patterns:

| Symptom | Likely cause | Fix |
|---|---|---|
| <a id="resource-uri-mismatch"></a>Every token rejected as `invalid_audience` | Resource URI mismatch between PRM `resource`, `--uri`, and the agent's `resource=` parameter (often a trailing slash) | Pick the canonical no-slash form (e.g. `http://localhost:8080/mcp`) and use it everywhere — PRM document, `authserver admin resource create --uri`, and the agent's `resource=` form parameter |
| `401` with `kid not found` errors after rotating Authplane's signing key | JWKS cache hasn't refreshed | Implement force-refresh on unknown `kid` (the [Resource Server SDK](sdk-resource-server.md) does this automatically) |
| `403 insufficient_scope` even though the agent requested the scope | Scope not declared on the Resource | Re-run `authserver admin resource create` (or `update`) with the scope in `--scopes`; only scopes registered on the Resource can appear in tokens |
| JWKS fetch returns connection-refused inside Docker | MCP server resolving `localhost:9000`, which inside a container points at itself | Use the Compose service name (`http://authserver:9000`) and set the issuer URL to match what the JWT's `iss` claim will say |
| Claude Code or another MCP client drops the `scope` parameter | Client treats scope as optional | Set `oauth.require_scope: false` (env: `AUTHPLANE_OAUTH_REQUIRE_SCOPE=false`); Authplane will default to all registered scopes on the Resource |

## See also

- **Drive the whole flow by hand:** [Run the AS standalone and point it at your own MCP server](standalone-as-by-hand.md) — one `docker run` for the AS, then provision + mint + call with `curl`, against a server you already run.
- **Runnable proof:** [`examples/go/01-mcp-server-basic/README.md`](../../../examples/go/01-mcp-server-basic/README.md), [`examples/typescript/01-mcp-server-basic/README.md`](../../../examples/typescript/01-mcp-server-basic/README.md), [`examples/python/01-mcp-server-basic/README.md`](../../../examples/python/01-mcp-server-basic/README.md)
- [Resource Server SDK guide](sdk-resource-server.md) — the language-specific middleware
- [Concepts → Resources & scopes](../../concepts/resources-and-scopes.md)
- [Reference → HTTP API (`POST /admin/resources`)](../../reference/http-api.md#http-admin-resources-create)
- [Reference → CLI (`authserver admin resource`)](../../reference/cli.md#cli-admin-resource-create)
