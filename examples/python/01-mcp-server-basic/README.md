# Tier 01 — Basic MCP server (Python)

<!-- loccount:begin -->
**Auth-specific code: 5 lines · Total example: 31 lines · SDK: python-sdk 0.2.0**
<!-- loccount:end -->

A minimal FastMCP server protected by Authplane-issued JWTs. Everything you
need to authenticate inbound MCP calls fits inside a single five-line block
in `server.py`; the rest of the file is plain MCP boilerplate.

## What you'll learn

- How to wire Authplane JWT validation into a FastMCP server with the
  `authplane-fastmcp` adapter
- How to register a Mint [Resource](../../../docs/concepts/glossary.md#glossary-resource)
  whose URI matches the JWT audience your server expects
- How to register an OAuth client with the `client_credentials` grant
- How to mint a machine token and call a protected MCP tool

## Prereqs

`make check-prereqs` (auto-invoked by `make run`) enforces these and fails
loud with install hints if any are missing.

| Tool | Version | Install (macOS / Linux) |
|---|---|---|
| **Python** | 3.12+ (FastMCP requirement) | `brew install python@3.12` / `apt install python3.12 python3.12-venv` |
| **Docker** | 24+ (daemon running) | Docker Desktop / Rancher Desktop |
| **curl** | any | preinstalled |
| **jq** | any | `brew install jq` / `apt install jq` |

The Makefile auto-picks `python3.13` → `python3.12` → `python3` on PATH.
If your system's `python3` is older than 3.12 and you have 3.12 installed
elsewhere, pass it explicitly: `PY=/path/to/python3.12 make run`.

The AS container binds **9000** (public) and **9001** (admin); the MCP
server binds **8080**. Conflicts are the most common startup failure — see
Troubleshooting below.

| | |
|---|---|
| **Time to run** | About a minute first-run (venv install + AS pull); ~5 s warm |
| **SDK** | `authplane-fastmcp` 0.2.0 (PyPI) — depends on `authplane-sdk` 0.2.0 |
| **MCP framework** | `fastmcp >= 3.0, < 4` (matches `pyproject.toml`) |

## Run it

```bash
make run        # creates a venv (first run only), starts the AS in a container, launches the server natively
make verify     # registers Resource + client, mints a token, calls the protected tool
make logs       # tails the last 40 lines of AS + MCP-server logs
make status     # one-line health of the AS container + MCP process
make clean      # stops everything; KEEPS .env and the venv
make distclean  # full reset including .env and venv
```

The basic flow doesn't build any Dockerfiles. The AS is pulled as a
published image; the MCP server is a plain Python process in a
virtualenv at `.run/.venv`. First run downloads the AS image (~30 MB)
and installs FastMCP + the Authplane adapter; subsequent runs start in
seconds.

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

**`ERROR: ... is Python 3.11 but FastMCP needs 3.12+`**
The Makefile's prereq check caught a too-old Python. Install 3.12+ or
pass `PY=python3.12 make run`.

**`make verify` hangs at "waiting for ..."**
Inspect with `make status` and `make logs`. The Authlib deprecation
warning in `mcp.log` is normal; what you're looking for is a real
exception above the FastMCP banner.

**`make verify` returns `invalid_token`**
JWT audience mismatch. `AUTHPLANE_BASE_URL` + `/mcp` must equal the
Resource URI registered at the AS, byte-for-byte.

**Stale state**
`make distclean` is the full reset (also removes the venv).

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
> - **MCP server on the host, another machine, or public** → `http://localhost:9000` (or, behind a reverse proxy / TLS, one stable public hostname) on both.
>
> Get it wrong and every call 401s with an opaque `invalid_token` — the token is valid, but the SDK discovered metadata at one host while the JWT's `iss` says another.

**2. The JWT audience must match the URL your MCP server actually
serves on — byte-for-byte.** `authplane_auth()` derives the audience
as `base_url + mcp_path` (default `mcp_path="/mcp"`). If you change
any of port, host, or path, all three of these must agree:

- `base_url=` (and `mcp_path=` if non-default) on `authplane_auth(...)`
- `uri` field on the Resource you register at the AS
- The URL the MCP client actually reaches

Custom port: `PORT=9090 python server.py` runs on `:9090`, so the
Resource URI is `http://localhost:9090/mcp` (with `AUTHPLANE_BASE_URL`
updated to match) and the AS registration must use that same URI.
Custom path: pass `mcp_path="/api/mcp"` to `authplane_auth(...)` AND
register the Resource with that same URI. Mismatches produce an
opaque `invalid_token` on every call — the JWT `aud` won't match
what the SDK expects.

**3. The scope string is a join key across four places.** Pick a name
once (here: `mcp:echo`) and use it in all four of these without
varying:

| # | Where it appears |
|---|------------------|
| 1 | `scopes=["mcp:echo"]` in `authplane_auth(...)` (SDK config) |
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
   audience the MCP server will expect (`base_url` + `/mcp`). The default
   `base_url` in this example is `http://localhost:8080` so the URI is
   `http://localhost:8080/mcp`.

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

A plain FastMCP server, no auth:

```python
mcp = FastMCP("demo-server")
mcp.run(transport="streamable-http", host="0.0.0.0", port=8080)
```

The same server with Authplane JWT validation:

```diff
+ async def main() -> None:
+     auth = await authplane_auth(
+         issuer=os.environ["AUTHPLANE_ISSUER"],
+         base_url=os.environ["AUTHPLANE_BASE_URL"],
+         scopes=["mcp:echo"], dev_mode=True,
+     )
-     mcp = FastMCP("demo-server")
+     mcp = FastMCP("demo-server", **auth)
+     try:
+         await mcp.run_async(transport="streamable-http", host="0.0.0.0", port=8080)
+     finally:
+         await auth.aclose()
+
+ asyncio.run(main())
```

Five lines of auth code, inside the `# authplane:begin` / `# authplane:end`
markers in [`server.py`](./server.py). Run
`go run ./tools/loccount examples/python/01-mcp-server-basic` from the
repo root to see the count.

## What's happening

The `authplane_auth()` factory performs RFC 8414 AS metadata discovery
against `issuer`, fetches the JWKS, and wires up a FastMCP
[`RemoteAuthProvider`](https://github.com/PrefectHQ/fastmcp) backed by an
Authplane [token verifier](../../../docs/concepts/glossary.md#glossary-token-verifier).
Every inbound HTTP request is checked against the AS's JWKS for signature
validity, then the audience and `exp` claims are validated. The JWT
audience is derived as `base_url` + `/mcp`, so the
[Mint backend](../../../docs/concepts/glossary.md#glossary-mint-backend)
Resource you register at the AS must declare its `uri` to match. The
`client_credentials` grant is the simplest way to mint a machine token
for the resource — no user, no consent, just a registered confidential
client asking for the resource and a scope it owns.

## Before production

This example is wired for local development. Before deploying:

| Setting | Dev value (here) | Production value | Why |
|---|---|---|---|
| `dev_mode=True` in `authplane_auth(...)` | `True` | **`False`** (or remove — it's the default) | Relaxes the SDK's SSRF guard so it accepts `http://`, `localhost`, and private-network issuers. Leaving it on in production weakens defense-in-depth against SSRF. |
| `AUTHPLANE_ISSUER` | `http://localhost:9000` | `https://auth.example.com` | Production issuers MUST be `https://`. The AS itself refuses to start with a non-localhost issuer unless cookies are also `Secure` (see next row). |
| `AUTHPLANE_SESSION_SECURE` | `true` (the example already sets this because `authserver:9000` is non-localhost) | `true` | Required by the AS's own startup validation whenever `server.issuer` is non-localhost. The AS refuses to start otherwise. Set to `false` only when both the issuer and Admin UI are reached strictly via `http://localhost`. |
| `AUTHPLANE_SESSION_SECRET` | `dev-session-secret-change-me` | `openssl rand -hex 32` | Used to sign session cookies — leaking it lets an attacker forge admin sessions. |
| `AUTHPLANE_ADMIN_API_KEY` | `dev-admin-key-change-me` | `openssl rand -hex 32` | Bearer for the entire admin surface. Treat like a root password. |
| Storage | SQLite in a Docker volume | PostgreSQL (`AUTHPLANE_STORAGE_DRIVER=postgres`) | SQLite is single-instance. PostgreSQL is required for HA and cross-instance LISTEN/NOTIFY. |
| Signing keys | Auto-generated in `/data/keys` | HashiCorp Vault Transit | See [`docs/guides/deploy/hashicorp-vault-transit.md`](../../../docs/guides/deploy/hashicorp-vault-transit.md). |

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
