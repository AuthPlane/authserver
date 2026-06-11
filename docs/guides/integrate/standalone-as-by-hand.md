# Run the AS standalone and point it at your own MCP server

*Context: this is part of [Guides — Integrate](README.md). It is the prose
version of what every example's `scripts/verify.sh` does — the runnable
narrative for **provision a Resource + Client → mint a token → call the
tool, entirely by hand with `curl`**, against an MCP server you already
run.*

**Audience:** You have (or are standing up) an MCP server somewhere — on
your host, in a container, behind a real hostname — and you want Authplane
to issue and validate tokens for it. The `make run` flow in each
`examples/` directory boots *its own* before/after servers; this guide is
for the case the examples don't cover: **your server, your URI, the AS
pointed at it.**

Everything here is `curl` + `docker` only. No SDK, no compose, no clone.
For field-level truth on every admin payload, the authority is
[`docs/reference/http-api.md`](../../reference/http-api.md) (generated from
the handlers); this page is the runnable sequence that strings those calls
together.

## Step 0 — decide the issuer hostname (do this first)

> **Is your MCP server in the same Docker network as the AS?**
> → use `http://authserver:9000` (the AS container's network name) for the
> issuer on **both** sides.
> **Is your MCP server on the host, on another machine, or public?**
> → use `http://localhost:9000` (or your real public hostname, e.g.
> `https://auth.example.com`) for the issuer on **both** sides.
>
> Two env vars must resolve to that *same* hostname:
>
> - **`AUTHPLANE_SERVER_ISSUER`** — what the **AS announces** as its issuer
>   (the `iss` it stamps on tokens and the URL in its discovery document).
> - **`AUTHPLANE_ISSUER`** — where your **MCP server's SDK discovers**
>   metadata and fetches JWKS.
>
> If they disagree, the SDK fetches metadata from one host, the JWT's `iss`
> claim says another, and every call fails `401` with an opaque
> `invalid_token` — the single most common Authplane misconfiguration. A
> token can be perfectly valid and still be rejected for this reason alone.

This guide uses the **host** case (`http://localhost:9000`) throughout.
For the same-Docker-network case, substitute `http://authserver:9000`
everywhere `http://localhost:9000` appears below and run the AS with
`--name authserver` on a shared `--network`.

## Step 1 — boot the AS with one `docker run` (no compose)

```bash
# Command verified against README.md § Quick Start and docs/reference/cli.md#cli-serve
export AUTHPLANE_ADMIN_API_KEY="$(openssl rand -hex 32)"
export AUTHPLANE_SESSION_SECRET="$(openssl rand -hex 32)"
echo "Admin API key (save it): $AUTHPLANE_ADMIN_API_KEY"

docker run -d --name authplane-as \
  -p 9000:9000 -p 9001:9001 \
  -e AUTHPLANE_SERVER_ISSUER=http://localhost:9000 \
  -e AUTHPLANE_ADMIN_API_KEY \
  -e AUTHPLANE_SESSION_SECRET \
  -e AUTHPLANE_CLIENT_CREDENTIALS_ENABLED=true \
  -v authplane-as-data:/data \
  authplane/authserver:latest serve
```

What each flag is doing:

- `:9000` is the **public OAuth** surface (token, JWKS, well-knowns);
  `:9001` is the **admin API** (Resource/Client management). Both are
  documented in [`docs/reference/http-api.md`](../../reference/http-api.md).
- `AUTHPLANE_SERVER_ISSUER` is the Step-0 decision. It defaults to
  `http://localhost:9000`, so on the host you *could* omit it — but set it
  explicitly so the value is visible and matches the SDK side. The
  README quick-start omits it (it's relying on that default); the
  `examples/` `.env` files set it explicitly. Same value, two styles — see
  [Reconciling the two AS-config presentations](#reconciling-the-two-as-config-presentations).
- `AUTHPLANE_CLIENT_CREDENTIALS_ENABLED=true` turns on the machine-to-machine
  grant. **Every grant is off by default** and the discovery endpoint
  silently omits a grant that isn't enabled — so if you skip this, the
  token step below fails with `unsupported_grant_type`. (DPoP and token
  exchange have their own `AUTHPLANE_*_ENABLED` flags; see
  [`docs/reference/env-vars.md`](../../reference/env-vars.md).)

Wait for readiness, then export the admin bearer for the calls below:

```bash
# Discovery returns 200 once the AS is up.
until curl -fsS -o /dev/null http://localhost:9000/.well-known/oauth-authorization-server; do sleep 1; done
echo "AS ready"
```

## Step 2 — register YOUR server as a Mint Resource

Pick the **canonical Resource URI**: the exact scheme + host + port + path
your MCP endpoint is reachable at. This string is the contract — it must
match byte-for-byte in three places (the registration here, your server's
Protected Resource Metadata document, and the `resource=` token parameter
in Step 4). A trailing slash or `http`-vs-`https` mismatch here is the
second-most-common misconfiguration.

```bash
# Wire shape verified against docs/reference/http-api.md#http-admin-resources-create
# Swap RESOURCE_URI for YOUR server's real, reachable MCP endpoint.
export RESOURCE_URI="http://localhost:8080/mcp"

curl -fsS -X POST http://localhost:9001/admin/resources \
  -H "Authorization: Bearer $AUTHPLANE_ADMIN_API_KEY" \
  -H "Content-Type: application/json" \
  -d "{
    \"slug\": \"my-server\",
    \"display_name\": \"My MCP server\",
    \"backend_kind\": \"mint\",
    \"uri\": \"$RESOURCE_URI\",
    \"scopes\": [{\"name\": \"mcp:tools\", \"description\": \"Call my tools\"}]
  }"
```

`backend_kind: "mint"` means Authplane issues its own JWTs for this
Resource (as opposed to `broker`, which fronts an upstream OAuth provider —
see [Broker vs Mint](../../concepts/broker-vs-mint.md)). Only scopes you
declare here can appear in a token for this Resource.

## Step 3 — register a Client

```bash
# Wire shape verified against docs/reference/http-api.md#http-admin-clients-create
client_resp=$(curl -fsS -X POST http://localhost:9001/admin/clients \
  -H "Authorization: Bearer $AUTHPLANE_ADMIN_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "client_name": "my-server-client",
    "grant_types": ["client_credentials"],
    "token_endpoint_auth_method": "client_secret_basic",
    "scope": "mcp:tools"
  }')
export CLIENT_ID=$(echo "$client_resp" | jq -er '.client_id')
export CLIENT_SECRET=$(echo "$client_resp" | jq -er '.client_secret')
echo "client_id: $CLIENT_ID"
```

The `client_secret` is shown **once** and never stored in plaintext —
capture it now. The `scope` you grant the client must include the scope
strings you declared on the Resource in Step 2.

## Step 4 — mint a token by hand

```bash
# Wire shape verified against docs/reference/http-api.md#http-public-oauth-token
token_resp=$(curl -fsS -X POST http://localhost:9000/oauth/token \
  -u "$CLIENT_ID:$CLIENT_SECRET" \
  -d "grant_type=client_credentials" \
  -d "scope=mcp:tools" \
  --data-urlencode "resource=$RESOURCE_URI")
export ACCESS_TOKEN=$(echo "$token_resp" | jq -er '.access_token')
echo "token length: ${#ACCESS_TOKEN}"
```

`--data-urlencode "resource=..."` sets the JWT `aud` claim. It must equal
the Resource URI from Step 2 byte-for-byte — that's the same canonical
string, a third time.

## Step 5 — call your server (the 3-step MCP handshake)

Streamable-http is **not** a single request: it's `initialize` →
`notifications/initialized` → `tools/call`, with an `Mcp-Session-Id`
response header from step 1 echoed on every later call, and an
`Accept: application/json, text/event-stream` header on all three. The full
wire-level walkthrough — headers, the SSE-framing of responses, the exact
4xx you get when each piece is missing — lives in
[`docs/reference/mcp-streamable-http.md`](../../reference/mcp-streamable-http.md).
Drive it against your server with the token you just minted:

```bash
# 1. initialize — capture the session id from the RESPONSE header
SESSION_ID=$(curl -fsS -D - -o /dev/null -X POST "$RESOURCE_URI" \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -H "Accept: application/json, text/event-stream" \
  -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"curl","version":"1.0"}}}' \
  | awk 'tolower($1)=="mcp-session-id:"{print $2}' | tr -d '\r')

# 2. notifications/initialized — required before tools become callable
curl -fsS -o /dev/null -X POST "$RESOURCE_URI" \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H "Mcp-Session-Id: $SESSION_ID" \
  -H "Content-Type: application/json" \
  -H "Accept: application/json, text/event-stream" \
  -d '{"jsonrpc":"2.0","method":"notifications/initialized"}'

# 3. tools/call — the authenticated invocation (swap in one of your tools)
curl -fsS -X POST "$RESOURCE_URI" \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H "Mcp-Session-Id: $SESSION_ID" \
  -H "Content-Type: application/json" \
  -H "Accept: application/json, text/event-stream" \
  -d '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"echo","arguments":{"text":"hello"}}}'
```

A real MCP client does all of this for you; the `curl` version is here
because copying it once is the fastest way to confirm the AS, the token,
and your server agree.

## Step 6 — confirm auth is actually enforced

A passing call only proves the happy path. Also confirm the **negative**:
an unauthenticated call must be rejected.

```bash
# No bearer → expect HTTP 401 with a WWW-Authenticate header pointing at your PRM
curl -s -o /dev/null -w '%{http_code}\n' -X POST "$RESOURCE_URI" \
  -H "Content-Type: application/json" \
  -H "Accept: application/json, text/event-stream" \
  -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}'
# Expect: 401
```

If this returns `200`, your server is not enforcing auth — the bearer
middleware isn't wrapping the MCP endpoint. See
[Connect an MCP server](connect-mcp-server.md) for wiring it.

## Reconciling the two AS-config presentations

You will see the AS configured two slightly different ways across this repo.
They are the same server — different trade-offs for different jobs:

| | README Quick Start | `examples/**/.env` + `examples/_shared/config.example.yaml` |
|---|---|---|
| Secrets | `openssl rand -hex 32` (fresh, throwaway) | fixed dev values (`dev-admin-key-change-me`) so a run is reproducible and `make verify` is hermetic |
| `AUTHPLANE_SERVER_ISSUER` | omitted (relies on the `http://localhost:9000` default) | set **explicitly**, because the examples also run an all-in-Docker mode where it must become `http://authserver:9000` |
| Goal | zero-to-running demo in under a minute | repeatable, CI-smoke-tested integration |

The reconciliation rule: **on the host, the README's minimal command and the
examples' explicit `AUTHPLANE_SERVER_ISSUER=http://localhost:9000` produce
the identical issuer** — the examples just spell it out because they support
switching to the Docker-network hostname (Step 0). For anything beyond a
local demo, generate real secrets (the README style) **and** set the issuer
explicitly (the examples style), and flip the production knobs in
[Hardened deployment](../deploy/hardened-deployment.md).

## See also

- [`docs/reference/mcp-streamable-http.md`](../../reference/mcp-streamable-http.md) — the full wire-level handshake, headers, and 4xx meanings.
- [`docs/reference/http-api.md`](../../reference/http-api.md) — authoritative request/response DTOs for every admin + public endpoint used above.
- [Connect an MCP server](connect-mcp-server.md) — wiring the SDK validation into the server (the in-code version of Steps 2–6).
- [Debugging 401s](debugging-401s.md) — decision tree when an authenticated call still comes back 401.
