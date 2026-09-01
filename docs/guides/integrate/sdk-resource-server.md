# Resource Server SDK — JWT validation in five lines

*Context: this is part of [Guides — Integrate](README.md). Start with the primer if you haven't.*

**Audience:** Builders writing an MCP **server** (resource server) in Go, TypeScript, or Python who want drop-in JWT validation, JWKS caching, [DPoP](../../concepts/glossary.md#glossary-dpop) checks, and scope enforcement.

> The canonical SDKs are published packages: [go-sdk](https://github.com/authplane/go-sdk) on the Go module proxy, [ts-sdk](https://github.com/authplane/ts-sdk) as `@authplane/sdk` / `@authplane/mcp` / `@authplane/fastmcp` on npm, and [python-sdk](https://github.com/authplane/python-sdk) as `authplane-sdk` + `authplane-fastmcp` on PyPI.

## What you'll achieve in 10 minutes

- The official SDK + matching MCP adapter installed for your language
- JWT validation, JWKS caching, and PRM publishing wired into your MCP server with the adapter's factory
- `POST /mcp` rejecting invalid tokens automatically
- Per-tool scope enforcement using `RequireScope` (Go) / `require_scopes` (Python)

## Prereqs

- Your MCP server is reachable on a known URL and registered as a [Mint Resource](../../concepts/glossary.md#glossary-mint-backend) in Authplane (see [Connect an MCP Server](connect-mcp-server.md)).
- Python users: Python **3.12+** (the SDK and its FastMCP adapter both pin `>=3.12`).
- Concept context: [Access token](../../concepts/glossary.md#glossary-access-token), [Audience](../../concepts/glossary.md#glossary-audience), [JWKS](../../concepts/glossary.md#glossary-jwks), [DPoP](../../concepts/glossary.md#glossary-dpop), [Scope](../../concepts/glossary.md#glossary-scope).

## Pick your package

Each SDK ships a core verifier plus framework adapters. Pin the adapter that matches your MCP stack — it's what the example uses and what the "5 lines" claim measures.

| Language | MCP stack | Install | Import |
|---|---|---|---|
| **Python** | FastMCP | `pip install authplane-fastmcp` | `from authplane_fastmcp import authplane_auth` |
| **Python** | Official Python MCP SDK | `pip install authplane-mcp` | `from authplane_mcp import ...` |
| **Python** | Any other framework (FastAPI, Starlette, raw ASGI) | `pip install authplane-sdk` | `from authplane import AuthplaneResource` |
| **TypeScript** | Official `@modelcontextprotocol/sdk` on Express (tier-01) | `npm install @authplane/mcp` | `import { authplaneMcpAuth } from "@authplane/mcp"` |
| **TypeScript** | FastMCP | `npm install @authplane/fastmcp` | `import { authplaneAuth } from "@authplane/fastmcp"` |
| **TypeScript** | Any other framework | `npm install @authplane/sdk` | `import { AuthplaneResource } from "@authplane/sdk"` |
| **Go** | Official `modelcontextprotocol/go-sdk` (tier-01) | `go get github.com/authplane/go-sdk/mcp` | `import "github.com/authplane/go-sdk/mcp/pkg/authplanemcp"` (`authplanemcp.NewAdapter`) |
| **Go** | net/http (raw HTTP service) | `go get github.com/authplane/go-sdk/http` | `import authhttp "github.com/authplane/go-sdk/http/pkg/auth"` |

The recipes below show the MCP-adapter path for each language — that's the one that delivers JWT validation + JWKS caching + DPoP + scope enforcement in ~5 lines. For raw-HTTP integrations (non-MCP), use the core verifier and wire your own middleware.

## Steps

### 1. Install the SDK

**Go (`modelcontextprotocol/go-sdk` adapter — tier-01):**

```bash
go get github.com/authplane/go-sdk/mcp
```

**TypeScript (`@modelcontextprotocol/sdk` adapter — tier-01):**

```bash
npm install @authplane/mcp @modelcontextprotocol/sdk express
```

**Python (FastMCP adapter — requires Python 3.12+):**

```bash
pip install authplane-fastmcp
```

### 2. Configure and mount the validator

Each adapter takes your Authplane issuer URL and the MCP server's canonical URI (the JWT audience). It serves the PRM document automatically at `/.well-known/oauth-protected-resource/<mcp-path>` and validates every inbound bearer token before your handler runs.

**Go (`go-sdk/mcp` adapter):**

```go
import "github.com/authplane/go-sdk/mcp/pkg/authplanemcp"

adapter, err := authplanemcp.NewAdapter(ctx, authplanemcp.Options{
    Issuer:   "http://localhost:9000",      // Authplane issuer
    Resource: "http://localhost:8080/mcp",  // this server's Resource URI (= JWT aud)
    Scopes:   []string{"mcp:echo"},
    DevMode:  true,                          // localhost + http: dev-only
})

http.Handle(adapter.WellKnownPRMPath(), adapter.ProtectedResourceMetadataHandler())
http.Handle("/mcp", adapter.AuthMiddleware(handler))   // handler = the MCP streamable-http handler
```

**TypeScript (`@authplane/mcp` adapter):**

```typescript
import { authplaneMcpAuth } from "@authplane/mcp";

const auth = await authplaneMcpAuth({
  issuer: "http://localhost:9000",
  resource: "http://localhost:8080/mcp",   // this server's Resource URI
  scopes: ["mcp:echo"],
  devMode: true,                            // localhost + http: dev-only
});

app.get(auth.protectedResourceMetadataPath, auth.protectedResourceMetadataHandler);
app.all("/mcp", auth.bearerAuth, mcpHandler);   // mcpHandler = StreamableHTTPServerTransport
```

**Python (`authplane-fastmcp` adapter):**

```python
import asyncio, os
from fastmcp import FastMCP
from authplane_fastmcp import authplane_auth

async def main() -> None:
    auth = await authplane_auth(
        issuer=os.environ["AUTHPLANE_ISSUER"],        # e.g. http://localhost:9000
        base_url=os.environ["AUTHPLANE_BASE_URL"],    # e.g. http://localhost:8080
        scopes=["mcp:echo"],
        dev_mode=True,                                 # localhost + http: dev-only
    )
    mcp = FastMCP("demo-server", **auth)
    # ... register tools ...
    try:
        await mcp.run_async(transport="streamable-http", host="0.0.0.0", port=8080)
    finally:
        await auth.aclose()

asyncio.run(main())
```

That's the Python integration — the audience is `base_url + /mcp`, the PRM document is published automatically, and every inbound request is JWT-validated before reaching your tool. The `auth.aclose()` in `finally` releases the SDK's `httpx.AsyncClient` and stops its background JWKS refresh task; it must run on the same event loop that constructed `auth`, which is why setup, serve, and cleanup all share one `asyncio.run(main())`.

**Serving MCP at a non-default path.** The three adapters take the resource URI differently:

- **Python (`authplane_auth`)** derives the audience as `base_url + mcp_path` (default `mcp_path="/mcp"`). To mount FastMCP at `/api/mcp`, pass `mcp_path="/api/mcp"` to `authplane_auth(...)`.
- **TypeScript (`authplaneMcpAuth`)** takes the full audience URI as the `resource` parameter — no path derivation. Pass `resource: "http://your-host/api/mcp"` directly.
- **Go (`authplanemcp.NewAdapter`)** takes the full audience URI as `Options.Resource` — same as TypeScript.

In all three cases, the URI you give the adapter **must be byte-for-byte identical** to the `--uri` you register the Resource with at the AS. The PRM document is served at `/.well-known/oauth-protected-resource/<path>` where `<path>` is the URL path component of that URI (per MCP spec).

> **`dev_mode` / `devMode` / `DevMode` is a production foot-gun by name.** Setting it to `True` relaxes the SDK's SSRF guard so it will fetch from `http://` issuers, `localhost`, and private networks. It is for local development only — production issuers MUST be `https://` and the flag MUST be `False` (the default). Leaving it on in production silently weakens defense-in-depth against SSRF.

### 3. Enforce per-tool scopes

When you have multiple tools at different sensitivity tiers, declare the required scope on the tool itself:

**Go:**

```go
// Scope strings are arbitrary identifiers; we use the `mcp:<tool>`
// convention to match the rest of these docs. The URL path is independent.
mux.Handle("POST /tools/echo",
    validator.RequireScope("mcp:echo", http.HandlerFunc(handleEcho)))
```

**Python (FastMCP):**

```python
from fastmcp.server.auth.providers.scopes import require_scopes

@mcp.tool(auth=require_scopes("mcp:admin"))
def admin_tool(...):
    ...
```

A missing scope returns `403 {"error":"insufficient_scope","scope":"<required>"}`. A missing or invalid token returns `401` with a `WWW-Authenticate: Bearer resource_metadata=...` header.

## Optional — real-time revocation via introspection

JWT validation alone accepts a token until it expires. If you cannot tolerate
that window, the SDKs can call [introspection](../../concepts/glossary.md#glossary-introspection)
on every request and reject tokens Authplane reports inactive.

This is **off unless you give the SDK credentials.** In Go, supplying them
(`WithClientCredentials` / `WithClientAuthentication`) wires RFC 7662
introspection as the revocation checker automatically — there is no separate
option to enable. Check your SDK's own docs for how it wires introspection;
the requirements below apply to any caller, whichever SDK reaches the
endpoint.

Two things Authplane requires of the caller:

1. **A confidential client.** Introspection does not accept public
   (secret-less) clients — see
   `introspection_endpoint_auth_methods_supported` in the [discovery
   document](../../reference/http-api.md), which lists only
   `client_secret_basic` and `client_secret_post`.
2. **Authorization to act AS your Resource.** Your MCP server is asking about a
   token issued to somebody else — one of your clients — so Authplane has to
   know the two are related. That link is
   [`policy.runtime.client_ids`](runtime-client-binding.md):

   ```bash
   # Command verified against docs/reference/cli.md#cli-admin-resource-runtime-client-add
   authserver admin resource runtime-client add \
     --client-id "$RS_CLIENT_ID" --slug "$RESOURCE_SLUG"
   ```

Without the binding, every introspection returns `{"active": false}`, the SDK
reads that as "revoked", and your server rejects **every** request. See the
troubleshooting table below.

## Verify

Send a request with no token — you should get `401`:

```bash
curl -sS -o /dev/null -w '%{http_code}\n' -X POST http://localhost:8080/mcp \
  -H 'Content-Type: application/json' -d '{}'
# Expect: 401
```

Mint a valid token (see [Auth Client SDK guide](sdk-auth-client.md)) and call again — you should get the MCP response. Inspect the response headers on a failure case:

```bash
curl -sS -i -X POST http://localhost:8080/mcp -H 'Authorization: Bearer not-a-real-token'
# Expect 401 + WWW-Authenticate: Bearer resource_metadata="…/.well-known/oauth-protected-resource"
```

## What can go wrong

| Symptom | Likely cause | Fix |
|---|---|---|
| Every token fails with `audience_mismatch` (or your SDK's equivalent) | The `resourceUri` you passed to the validator doesn't match the `--uri` you registered or the canonical PRM `resource` string (e.g. trailing slash) | Pick one canonical form — see [Connect an MCP Server § What can go wrong](connect-mcp-server.md#what-can-go-wrong) |
| `401 invalid_token` for a token that worked seconds ago | Clock skew between Authplane and the resource server (`exp` already past) | Configure the validator's clock-skew tolerance (default 60s); ensure NTP is healthy on both hosts |
| `401 kid_not_found` after key rotation | JWKS cache holds stale keys | The official SDKs force-refresh JWKS on unknown `kid` automatically; if you wrote a custom verifier, mirror that behavior. |
| `403 insufficient_scope` for a scope the agent did request | Scope not declared on the Resource, so Authplane stripped it | Add it via `authserver admin resource update --scopes 'name||description'` ([cli.md#cli-admin-resource-update](../../reference/cli.md#cli-admin-resource-update)) |
| Every token rejected as revoked, right after adding SDK credentials | Introspection auto-wired, but the RS client is not authorized to act AS the Resource, so Authplane answers `{"active": false}` | `authserver admin resource runtime-client add --client-id <rs-client-id> --slug <slug>` ([runtime-client-binding.md](runtime-client-binding.md)) |
| `401 invalid_client` from `/oauth/introspect` | The RS client is public (no secret), or has been suspended | Register a confidential client; check `authserver admin client list` for its status |
| DPoP-bound token rejected with `dpop_required` even though the agent sent a proof | Proof signed with a different key than the token's `cnf.jkt`, or proof `htu`/`htm` don't match the request | Verify the agent reuses the same signer for both token request and resource call; `htu` must match the request URL byte-for-byte (RFC 9449 §4.3) |

## See also

- **Runnable proof:** [`examples/go/01-mcp-server-basic/README.md`](../../../examples/go/01-mcp-server-basic/README.md), [`examples/typescript/01-mcp-server-basic/README.md`](../../../examples/typescript/01-mcp-server-basic/README.md), [`examples/python/01-mcp-server-basic/README.md`](../../../examples/python/01-mcp-server-basic/README.md)
- **DPoP + per-tool scopes (tier 3):** [`examples/go/03-mcp-server-dpop-scopes/README.md`](../../../examples/go/03-mcp-server-dpop-scopes/README.md), [`examples/python/03-mcp-server-dpop-scopes/README.md`](../../../examples/python/03-mcp-server-dpop-scopes/README.md), [`examples/typescript/03-mcp-server-fastmcp-dpop/README.md`](../../../examples/typescript/03-mcp-server-fastmcp-dpop/README.md)
- [Connect an MCP Server guide](connect-mcp-server.md)
- [Auth Client SDK guide](sdk-auth-client.md)
- [Runtime Client Binding guide](runtime-client-binding.md)
- [Concepts → Tokens & claims](../../concepts/tokens-and-claims.md)
- [Concepts → DPoP](../../concepts/dpop-and-proof-of-possession.md)
