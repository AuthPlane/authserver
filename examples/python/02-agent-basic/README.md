# Tier 02 — Calling another resource from your MCP server (Python)

<!-- loccount:begin -->
**Auth-specific code: 8 lines · Total example: 58 lines · SDK: python-sdk 0.3.0**
<!-- loccount:end -->

When your MCP server needs to call another resource — another Mint MCP
server, an admin service, any backend that trusts Authplane — it
acquires a token via the `authplane-sdk` Auth Client. This example
isolates that outbound OAuth call so you can see what the SDK does:
build a client, request a `client_credentials` token, present it on the
call. In your real MCP server, this code lives inside the tool handler
that needs to talk to the other resource.

> **Pairs with tier 01.** Tier 01 plays "the resource being called" —
> its authserver (`:9000` / `:9001`) and MCP server (`:8080`) must be
> running before `make verify` here. Bring it up first with `make run`
> in [`../01-mcp-server-basic/`](../01-mcp-server-basic/).
>
> The standalone `agent.py` shape is purely for readability: in
> production the same SDK calls live inside an MCP server's tool
> handler, not in a sibling process.

## What you'll learn

- How to acquire a machine token from Authplane with the `authplane-sdk`
  core client via the `client_credentials` grant
- How to pin the token's audience to a specific
  [Resource](../../../docs/concepts/glossary.md#glossary-resource) URI
  using the `resources=` parameter
- How to attach the resulting bearer token to a JSON-RPC call against a
  protected MCP server
- The minimum admin setup the AS needs before a machine client can mint
  tokens for a Mint Resource

| | |
|---|---|
| **Time to run** | ~30 seconds (tier 01 must already be running) |
| **Prereqs** | Tier 01 up (`make run` there), Docker 24+, `docker compose`, `curl`, `jq`, **Python 3.12+** (only if you run outside Docker — `pyproject.toml` pins `requires-python = ">=3.12"`) |
| **SDK** | `authplane-sdk` 0.3.0 (PyPI) |
| **HTTP client** | `httpx >= 0.27, < 1` (matches `pyproject.toml`) |

## Run it in 3 commands

```bash
cp .env.example .env
make run
make verify
```

`make run` builds the agent image. `make verify` registers the Resource
and an OAuth client against tier 01's running authserver, then executes
`agent.py` inside tier 01's compose network. `make clean` tears down the
agent container and removes the `.env` file the run target created.

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
> Steps 3 and 4 emit `client_id` and `client_secret` in their responses;
> assign each to a shell variable (`CLIENT_ID=...`, `CLIENT_SECRET=...`)
> before the next step uses it.

1. **Start tier 01 first.** From the repo root:

   ```bash
   ( cd examples/python/01-mcp-server-basic && cp -n .env.example .env && make run )
   ```

   Wait for the AS discovery endpoint to return 200:

   ```bash
   curl -fsS http://localhost:9000/.well-known/oauth-authorization-server
   ```

2. **Register a Mint Resource** (idempotent — if tier 01's verify.sh
   already ran, the resource exists and you can skip this step). The
   Resource URI must match the JWT audience the tier-01 MCP server expects
   (`base_url` + `/mcp` = `http://localhost:8080/mcp`).

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
   ( cd ../01-mcp-server-basic && docker compose exec authserver /authserver admin resource create \
     --slug demo-mcp \
     --uri http://localhost:8080/mcp \
     --backend-kind mint \
     --display-name "Demo MCP" \
     --scopes 'mcp:echo||echo tool' )
   ```

   The pipe-delimited `'name|upstream|description'` tuple is the same as
   tier 01 — the double-empty middle is intentional for Mint scopes (no
   upstream mapping).

3. **Register an OAuth client.** A fresh `client_credentials` machine
   client for this agent — even if tier 01 created one, you want a new
   secret so you don't have to dig the old one out.

   ```bash
   curl -sS -X POST http://localhost:9001/admin/clients \
     -H "Authorization: Bearer $AUTHPLANE_ADMIN_API_KEY" \
     -H "Content-Type: application/json" \
     -d '{
       "client_name": "demo-agent-client",
       "grant_types": ["client_credentials"],
       "token_endpoint_auth_method": "client_secret_basic",
       "scope": "mcp:echo"
     }'
   ```

   The response carries `client_id` and `client_secret`; the secret is
   shown once.

4. **Run the agent.** The agent (see [`agent.py`](./agent.py)) creates an
   `AuthplaneClient`, calls `client.client_credentials(scopes=[...],
   resources=[...])` to mint an audience-bound access token, then POSTs a
   JSON-RPC `initialize` request to the tier-01 MCP server with the token
   in the `Authorization: Bearer` header.

   The agent prints the raw MCP response, asserts that the response
   contains the server's `serverInfo.name` (`demo-server`), and exits 0;
   non-2xx responses or missing payloads exit 1. Without the bearer
   token the same request returns HTTP 401 — proof that the integration
   is actually enforcing auth.

   `make verify` runs the agent inside the tier-01 compose network so it
   can reach the AS at `authserver:9000` and the MCP server at
   `mcp-server:8080`. If you prefer to run it on the host, set
   `AUTHPLANE_ISSUER=http://localhost:9000` and
   `MCP_URL=http://localhost:8080/mcp` instead.

## Before / After

A plain MCP client, no auth:

```python
async with httpx.AsyncClient() as http:
    resp = await http.post("http://localhost:8080/mcp", json=req)
```

The same client with an Authplane-acquired bearer token:

```diff
+ from authplane import ASCredentials, AuthplaneClient
+ client = await AuthplaneClient.create(
+     issuer=os.environ["AUTHPLANE_ISSUER"],
+     auth=ASCredentials(os.environ["CLIENT_ID"], os.environ["CLIENT_SECRET"]),
+     dev_mode=True,
+ )
+ token = (await client.client_credentials(
+     scopes=["mcp:echo"], resources=[os.environ["RESOURCE_URI"]],
+ )).access_token
  async with httpx.AsyncClient() as http:
-     resp = await http.post("http://localhost:8080/mcp", json=req)
+     resp = await http.post(
+         "http://localhost:8080/mcp",
+         headers={"Authorization": f"Bearer {token}"},
+         json=req,
+     )
```

The auth-specific lines live between the `# authplane:begin` /
`# authplane:end` markers in [`agent.py`](./agent.py). Run
`go run ./tools/loccount examples/python/02-agent-basic` from the repo
root to see the measured count.

## What's happening

The agent uses the `client_credentials` grant — the simplest OAuth 2.0
flow for machine-to-machine calls. There's no user, no consent, no
browser redirect: the agent authenticates to the AS with its own
`client_id` + `client_secret` over HTTP Basic and asks for an access
token. The AS verifies the credentials, checks that the requested
`resource=` URI corresponds to a registered Resource and that the
requested scope is one the Resource declares, and returns a JWT whose
`aud` claim is set to that URI.

The MCP server (from tier 01) is configured with the same URI as its
expected audience. When the agent calls it with the bearer token, the
server's
[token verifier](../../../docs/concepts/glossary.md#glossary-token-verifier)
checks the signature against the AS's JWKS, validates `iss`, `aud`,
`exp`, and the required scopes — and only then admits the JSON-RPC
request into the tool handler. Token lifetimes are short by default
(the SDK refreshes inside `AuthplaneClient`'s token cache), and there is
no refresh token for this grant — every renewal is a fresh
`client_credentials` request.

## Next

[Tier 03 — DPoP-bound MCP server + agent with per-tool scopes](../03-mcp-server-dpop-scopes/)
layers RFC 9449 sender-constrained tokens on top of this flow and
demonstrates per-tool scope enforcement.
[Tier 04](../04-broker-upstream/) puts an MCP server in front of a Broker
upstream (GitHub) with `ConsentRequiredError` handling.

## Use a locally-built authserver image

This example does NOT bring up its own authserver — tier 01 does. To
build the AS from this checkout rather than pulling
`authplane/authserver:latest`, follow the **LOCAL BUILD ESCAPE
HATCH** comment block in
[`../../_shared/docker-compose.authserver.yml`](../../_shared/docker-compose.authserver.yml)
and mirror the change in
[`../01-mcp-server-basic/docker-compose.yml`](../01-mcp-server-basic/docker-compose.yml).
