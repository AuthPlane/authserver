# Tier 03 — DPoP-bound MCP server + agent with per-tool scopes (Python)

<!-- loccount:begin -->
**Auth-specific code: 15 lines · Total example: 187 lines · SDK: python-sdk 0.3.0**
<!-- loccount:end -->

A paired MCP server and agent that demonstrate two production-shaped auth
concerns layered on top of tier 02:

1. **DPoP sender-constraint** (RFC 9449) — the agent generates an
   ephemeral EC P-256 key, presents a DPoP proof on the token request to
   bind the access token to that key (`cnf.jkt`), and attaches a fresh
   DPoP proof header to every MCP call. The server enforces the binding
   on every inbound request.
2. **Per-tool scope enforcement** — the server publishes two tools
   (`echo` requiring `mcp:echo`, `add_numbers` requiring `mcp:add`) and
   uses FastMCP's `require_scopes(...)` decorator to reject calls whose
   token is missing the required scope.

> **Pair**, not "depends on tier 02". This example brings up its own
> `authserver` container — it is self-contained. The companion agent
> (`agent.py`) ships in the same directory.

## What you'll learn

- How to enable DPoP-bound access tokens on the authserver via
  [`AUTHPLANE_DPOP_ENABLED`](../../../docs/reference/env-vars.md)
- How to mint a DPoP-bound `client_credentials` token from the
  `authplane-sdk` (`AuthplaneClient` with a `DPoPProvider`)
- How to attach a DPoP proof header to outbound MCP calls using
  `client.dpop_headers("POST", url, access_token=...)`
- How to enforce DPoP binding on inbound MCP requests by subclassing
  `AuthplaneTokenVerifier` and forwarding a `DPoPRequestContext` to
  `AuthplaneResource.verify(token, dpop_request=...)`
- How to declare per-tool scope requirements with
  [`require_scopes`](https://gofastmcp.com) from FastMCP

| | |
|---|---|
| **Time to run** | ~3 minutes (first build is ~90s, subsequent runs are seconds) |
| **Prereqs** | Docker 24+, `docker compose`, `curl`, `jq`, **Python 3.12+** (only if you run outside Docker — `pyproject.toml` pins `requires-python = ">=3.12"`) |
| **SDK** | `authplane-sdk` + `authplane-fastmcp` 0.3.0 (PyPI) |
| **MCP framework** | `fastmcp >= 3.2, < 4` (matches `pyproject.toml`) — the 3.2 floor comes from `authplane-fastmcp` 0.3.0 |

## Run it in 3 commands

```bash
cp .env.example .env
make run
make verify
```

`make run` builds the MCP server image and brings up both services
(authserver on `:9000` / `:9001`, MCP server on `:8080`); the agent is
defined in the same compose file but stays under the `manual` profile so
it doesn't start on `make run`. `make verify` registers the Resource and
client, then exercises the agent twice — once happy-path (both tools
succeed) and once with the DPoP proof header stripped (the MCP server
must answer 401). `make clean` tears everything down and removes the
`.env` file the run target created.

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
> Steps 3 and 5 emit `client_id` and `client_secret` in their responses;
> assign each to a shell variable (`CLIENT_ID=...`, `CLIENT_SECRET=...`)
> before the next step uses it.

1. **Start authserver + MCP server.** `make run` brings both up. Wait
   for the AS discovery endpoint to return 200:

   ```bash
   curl -fsS http://localhost:9000/.well-known/oauth-authorization-server
   ```

   The discovery document is served by the AS at the
   [`GET /.well-known/oauth-authorization-server`](../../../docs/reference/http-api.md#http-public-well-known-oauth-authorization-server)
   endpoint. With `AUTHPLANE_DPOP_ENABLED=true` (see `.env.example`) the
   document advertises `dpop_signing_alg_values_supported` and the token
   endpoint accepts DPoP proof headers.

2. **Register a Mint Resource with both scopes.** The Resource URI must
   match the JWT audience the MCP server will expect (`base_url` +
   `/mcp`). Two scopes are declared so the per-tool `require_scopes(...)`
   decorators can enforce them independently:

   ```bash
   curl -sS -X POST http://localhost:9001/admin/resources \
     -H "Authorization: Bearer $AUTHPLANE_ADMIN_API_KEY" \
     -H "Content-Type: application/json" \
     -d '{
       "slug": "demo-mcp-dpop",
       "uri": "http://localhost:8080/mcp",
       "backend_kind": "mint",
       "display_name": "Demo MCP (DPoP + per-tool scopes)",
       "scopes": [
         {"name": "mcp:echo", "description": "echo tool"},
         {"name": "mcp:add",  "description": "add_numbers tool"}
       ]
     }'
   ```

   Endpoint:
   [`POST /admin/resources`](../../../docs/reference/http-api.md#http-admin-resources-create).
   The same Resource can be created via the CLI inside the container
   (see
   [`authserver admin resource create`](../../../docs/reference/cli.md#cli-admin-resource-create)):

   ```bash
   docker compose exec authserver /authserver admin resource create \
     --slug demo-mcp-dpop \
     --uri http://localhost:8080/mcp \
     --backend-kind mint \
     --display-name "Demo MCP (DPoP + per-tool scopes)" \
     --scopes 'mcp:echo||echo tool' \
     --scopes 'mcp:add||add_numbers tool'
   ```

3. **Register an OAuth client.** A `client_credentials` machine client
   with both scopes pre-approved:

   ```bash
   curl -sS -X POST http://localhost:9001/admin/clients \
     -H "Authorization: Bearer $AUTHPLANE_ADMIN_API_KEY" \
     -H "Content-Type: application/json" \
     -d '{
       "client_name": "demo-dpop-client",
       "grant_types": ["client_credentials"],
       "token_endpoint_auth_method": "client_secret_basic",
       "scope": "mcp:echo mcp:add"
     }'
   ```

   Endpoint:
   [`POST /admin/clients`](../../../docs/reference/http-api.md#http-admin-clients-create).
   CLI equivalent:
   [`authserver admin client create`](../../../docs/reference/cli.md#cli-admin-client-create).

4. **Run the agent.** The agent (see [`agent.py`](./agent.py)):
   1. Generates a fresh EC P-256 keypair with `cryptography.hazmat`.
   2. Creates an `AuthplaneClient` configured with a `DPoPProvider`
      backed by that key. The SDK automatically attaches a DPoP proof
      header to every AS call (see python-sdk/authplane/dpop.py:294-307).
   3. Calls `client.client_credentials(scopes=["mcp:echo","mcp:add"],
      resources=["http://localhost:8080/mcp"])` to mint a DPoP-bound
      access token (the AS returns `token_type: DPoP` and embeds
      `cnf.jkt` — see
      [`POST /oauth/token`](../../../docs/reference/http-api.md#http-public-oauth-token)).
   4. Builds an `Authorization: DPoP <token>` header plus a fresh
      `DPoP: <proof>` header via `client.dpop_headers("POST", mcp_url,
      access_token=token)` for each MCP call.
   5. Calls `initialize`, `tools/call echo {"text":"hello"}`, and
      `tools/call add_numbers {"a":2,"b":3}` — all three must return 200.

   `make verify` runs the agent inside this example's compose network so
   it can reach the AS at `authserver:9000` and the MCP server at
   `mcp-server:8080`.

5. **(verify only) Negative probe.** `make verify` re-runs the agent
   with `AGENT_DROP_DPOP_PROOF=1`, which strips the `DPoP` header from
   the MCP request. The server's verifier compares the token's
   `cnf.jkt` against the missing proof and rejects with 401 — proving
   the DPoP enforcement is real, not just configured. Skip the negative
   probe with `SKIP_DPOP_NEG=1`.

## What's happening

### DPoP token mint

When the agent's `AuthplaneClient` is constructed with `dpop=
DPoPProvider(...)`, the SDK attaches a freshly-signed DPoP proof header
on every outbound call to the AS, including
`client_credentials_grant(...)`. The AS validates the proof (signature,
`htm`, `htu`, `iat`, replay) per RFC 9449 §4 and, when valid, embeds the
JWK thumbprint of the proof key into the issued access token's `cnf.jkt`
claim. The response sets `token_type: "DPoP"` instead of `"Bearer"`.

### DPoP-bound resource calls

The agent generates a fresh DPoP proof for each MCP call via
`client.dpop_headers("POST", mcp_url, access_token=token)`. The proof
carries an `ath` claim (SHA-256 of the access token), the request method
and normalized URL, and is signed with the same key the token was bound
to. The agent sends the token under the `Bearer` scheme together with
the `DPoP` proof header (`Authorization: Bearer <token>` + `DPoP:
<proof>`). RFC 9449 §7.1 also defines an `Authorization: DPoP <token>`
form, but the upstream MCP SDK's `BearerAuthBackend` only inspects
headers starting with `bearer ` (see
`mcp/server/auth/middleware/bearer_auth.py`), so the practical
interoperable choice is the `Bearer` scheme + `DPoP` header. The
sender-constraint is still enforced — the resource server verifies
`cnf.jkt` against the `DPoP` proof regardless of the access-token
scheme.

### Server-side enforcement

`server.py` passes `inbound_dpop=InboundDPoPOptions(required=True)` to
`authplane_auth(...)`. That kwarg (see the installed package's
`authplane_fastmcp/auth.py` `authplane_auth` signature) configures the
underlying `AuthplaneResource` for inbound DPoP and turns on
`dpop_signing_alg_values_supported` /
`dpop_bound_access_tokens_required` advertisement in the PRM
(RFC 9728 §2). On every inbound request the verifier:

- detects `cnf.jkt` on the token and requires a proof;
- validates the proof JWT (signature, `htm`, `htu`, `iat`, `ath`,
  replay) per RFC 9449 §4.3;
- compares the proof's JWK thumbprint against the token's `cnf.jkt`;
- raises `DPoPBindingMismatchError` / `DPoPProofMissingError` if
  anything is off.

The stock `AuthplaneTokenVerifier.verify_token` in
`authplane-fastmcp` calls `AuthplaneResource.verify(token)`
without forwarding a `DPoPRequestContext`, so we subclass it as
`DPoPVerifier` to pull the request method, URL, and `DPoP` header from
FastMCP's `fastmcp.server.dependencies.get_http_request()`. The
subclass body is plumbing — it lives outside the `# authplane:begin` /
`# authplane:end` markers because a future minor release of
`authplane-fastmcp` is expected to fold the request-context forwarding
into the stock verifier and remove the need for the subclass entirely.

### Per-tool scopes

`@mcp.tool(auth=require_scopes("mcp:echo"))` tells FastMCP to gate the
handler on the presence of that scope in the validated token. FastMCP
checks the scope before the handler runs; missing scope returns HTTP
403 and the handler is never invoked. The same Resource declares both
scopes, so a single token can carry both; the gate is one-per-tool.

## Before / After (vs. tier 02)

The agent goes from "bearer token" to "DPoP-bound token with proof per
call":

```diff
+ from authplane import DPoPKeyMaterial, DPoPProvider
+ priv_pem = ec.generate_private_key(ec.SECP256R1()).private_bytes(...)
  client = await AuthplaneClient.create(
      issuer=...,
      auth=ASCredentials(CLIENT_ID, CLIENT_SECRET),
+     dpop=DPoPProvider(DPoPKeyMaterial.from_pem(priv_pem)),
      dev_mode=True,
  )
  token = (await client.client_credentials(
-     scopes=["mcp:echo"], resources=[RESOURCE_URI],
+     scopes=["mcp:echo", "mcp:add"], resources=[RESOURCE_URI],
  )).access_token
  headers = {
      "Authorization": f"Bearer {token}",
+     **client.dpop_headers("POST", mcp_url, access_token=token),
  }
```

The server gains two-scope advertising + a per-tool gate, plus
`inbound_dpop=` for the AS-side DPoP wiring:

```diff
- scopes=["mcp:echo"]
+ scopes=["mcp:echo", "mcp:add"]
+ inbound_dpop=InboundDPoPOptions(required=True)
+ result.auth.token_verifier = DPoPVerifier(...)
+ @mcp.tool(auth=require_scopes("mcp:echo"))
+ @mcp.tool(auth=require_scopes("mcp:add"))
```

The auth-specific lines live between the `# authplane:begin` /
`# authplane:end` markers in [`server.py`](./server.py) and
[`agent.py`](./agent.py). Run `go run ./tools/loccount
examples/python/03-mcp-server-dpop-scopes` from the repo root to see the
measured count.

## Next

[Tier 04 — MCP server fronting a Broker](../04-broker-upstream/) shows
the MCP server doing RFC 8693 token exchange to a Broker resource (an
upstream OAuth provider like GitHub), surfacing `ConsentRequiredError`
when the user has not yet consented and resuming after the consent
round-trip.

## Use a locally-built authserver image

To build the AS from this checkout rather than pulling
`authplane/authserver:latest`, follow the **LOCAL BUILD ESCAPE
HATCH** comment block in
[`../../_shared/docker-compose.authserver.yml`](../../_shared/docker-compose.authserver.yml).
Mirror the change in this example's `docker-compose.yml` (which inlines
the same service definition) — replace the `image:` line with the
`build:` block shown in the shared file.
