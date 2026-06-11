# MCP streamable-http transport — the wire-level handshake

This is what you actually need to know to call an MCP server from your
own client code. It covers the three-step handshake, the headers that
matter, and the 4xx responses you'll hit if any of them are wrong.

If you're writing a server, the MCP SDKs (Go, Python, TypeScript) handle
all of this for you — see the relevant tier-01 example. This page is for
the **client** side: an agent or test script that needs to drive the
transport directly via `curl`, `fetch`, `requests`, or any other HTTP
library.

## The three POSTs

Every MCP call over streamable-http is a sequence of three POST requests
to the same endpoint (`/mcp` by default):

1. **`initialize`** — opens the session. The response carries the
   server's capabilities and, in a response header, a session id you
   must echo on every subsequent call.
2. **`notifications/initialized`** — a one-way notification that
   acknowledges the handshake. No response body.
3. **`tools/call`** (or any other method) — the actual work.

Skipping step 2 or omitting the session id on step 3 returns 400.

### 1. `initialize`

```bash
curl -fsS -D /tmp/init-headers -X POST http://localhost:8080/mcp \
  -H "Authorization: Bearer ${ACCESS_TOKEN}" \
  -H "Content-Type: application/json" \
  -H "Accept: application/json, text/event-stream" \
  -d '{
    "jsonrpc":"2.0",
    "id":1,
    "method":"initialize",
    "params":{
      "protocolVersion":"2024-11-05",
      "capabilities":{},
      "clientInfo":{"name":"my-client","version":"1.0"}
    }
  }'
```

The server returns its capability document in the body. **Capture the
session id from the response headers** — the header name is
`Mcp-Session-Id`, case-insensitive:

```bash
SESSION_ID=$(awk 'tolower($1)=="mcp-session-id:"{print $2}' /tmp/init-headers | tr -d '\r')
```

Use `awk` with `tolower(...)`, not `sed`. HTTP headers are
case-insensitive but BSD `sed` (macOS default) lacks the GNU label
syntax for portable case-insensitive matching. `awk` works everywhere.

### 2. `notifications/initialized`

```bash
curl -fsS -o /dev/null -X POST http://localhost:8080/mcp \
  -H "Authorization: Bearer ${ACCESS_TOKEN}" \
  -H "Mcp-Session-Id: ${SESSION_ID}" \
  -H "Content-Type: application/json" \
  -H "Accept: application/json, text/event-stream" \
  -d '{"jsonrpc":"2.0","method":"notifications/initialized"}'
```

No response body (it's a JSON-RPC notification). The server now
considers the session ready for real method calls.

### 3. `tools/call`

```bash
curl -fsS -X POST http://localhost:8080/mcp \
  -H "Authorization: Bearer ${ACCESS_TOKEN}" \
  -H "Mcp-Session-Id: ${SESSION_ID}" \
  -H "Content-Type: application/json" \
  -H "Accept: application/json, text/event-stream" \
  -d '{
    "jsonrpc":"2.0",
    "id":2,
    "method":"tools/call",
    "params":{"name":"echo","arguments":{"text":"hello"}}
  }'
```

The response body may be either raw JSON or a Server-Sent-Events frame
(`event: message\ndata: {...}\n\n`) depending on the transport
negotiation. Strip the SSE wrapper either way:

```bash
payload=$(echo "$body" | sed -n 's/^data: //p')
[[ -z "$payload" ]] && payload="$body"
```

## Headers that matter

| Header | Sent on | Why |
|---|---|---|
| `Authorization: Bearer <token>` | Every request | Token from `/oauth/token`. Omit on `initialize` only if your server allows unauth (rare). |
| `Content-Type: application/json` | Every request | The body is JSON-RPC 2.0. |
| `Accept: application/json, text/event-stream` | Every request | **Mandatory.** Some methods return SSE-framed responses; omit or shorten this and the server returns 406. |
| `Mcp-Session-Id: <session-id>` (request) | Step 2 and beyond | The exact value from the `initialize` response header. |
| `Mcp-Session-Id: <session-id>` (response) | Step 1 only | Server-emitted on `initialize`. Capture from response headers, not body. |

## 4xx responses and what they mean

| Status | Likely cause |
|---|---|
| `400 Bad Request` | Missing `Mcp-Session-Id` on a non-`initialize` call, malformed JSON-RPC body, unknown method. |
| `401 Unauthorized` | Missing/invalid bearer token, expired token, or bearer-required-but-missing on `initialize`. The response will carry a `WWW-Authenticate: Bearer resource_metadata="..."` header pointing to the Protected Resource Metadata document (RFC 9728) so a client can discover the AS. |
| `403 Forbidden` | Valid token but missing a required scope (`insufficient_scope`). |
| `406 Not Acceptable` | Wrong `Accept` header. Add `text/event-stream` to the list. |
| `415 Unsupported Media Type` | Missing or wrong `Content-Type` (must be `application/json`). |

## Discovering the AS from a 401

A standards-compliant MCP server returns a `WWW-Authenticate` header on
401 that tells the client where to authenticate:

```
WWW-Authenticate: Bearer resource_metadata="http://localhost:8080/.well-known/oauth-protected-resource/mcp"
```

Fetch that URL to get the Protected Resource Metadata document (RFC
9728), which lists the authorization servers, supported scopes, and
bearer-methods for this resource:

```bash
curl -s http://localhost:8080/.well-known/oauth-protected-resource/mcp | jq .
```

```json
{
  "resource": "http://localhost:8080/mcp",
  "authorization_servers": ["http://localhost:9000"],
  "scopes_supported": ["mcp:echo"],
  "bearer_methods_supported": ["header"]
}
```

From there, fetch the AS's own metadata to learn the token endpoint:

```bash
curl -s http://localhost:9000/.well-known/oauth-authorization-server | jq .token_endpoint
```

## Minting the token (client_credentials)

The simplest path for machine-to-machine. Register an OAuth client at
the AS once (admin API), then call the token endpoint:

```bash
curl -fsS -X POST http://localhost:9000/oauth/token \
  -u "${CLIENT_ID}:${CLIENT_SECRET}" \
  -d "grant_type=client_credentials" \
  -d "scope=mcp:echo" \
  --data-urlencode "resource=http://localhost:8080/mcp"
```

The `resource=...` parameter sets the `aud` claim on the issued JWT. It
must match the Resource URI you registered at the AS **byte-for-byte**
(scheme + host + port + path) — that's the single most common
misconfiguration in Authplane integrations.

## See also

- [Connect an MCP Server](../guides/integrate/connect-mcp-server.md) — the
  higher-level integration guide.
- [HTTP API reference](./http-api.md) — the full HTTP surface of the
  AS itself.
- [Error codes](./error-codes.md) — JSON error bodies returned on 4xx.
