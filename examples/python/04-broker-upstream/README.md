# Tier 04 — MCP server fronting a Broker (Python)

<!-- loccount:begin -->
**Auth-specific code: 26 lines · Total example: 59 lines · SDK: python-sdk 0.3.0**
<!-- loccount:end -->

When your MCP server needs to call a third-party API on the user's
behalf — GitHub, Slack, Google Workspace, Notion — it does an
[RFC 8693 Token Exchange](../../../docs/reference/http-api.md#http-public-oauth-token)
against a Broker resource. Authplane brokers the OAuth dance with the
provider, holds the user's encrypted refresh token, and vends the
provider's native token (e.g. `gho_…`). Your MCP server uses that
token to call the upstream API.

This example shows the SDK's outbound Token Exchange call and how to
handle `ConsentRequiredError` — the branch every MCP server fronting a
Broker must handle, since the user must complete `/connect/{provider}`
at least once before tokens can be vended.

For the conceptual model, see [docs/concepts/broker-vs-mint.md](../../../docs/concepts/broker-vs-mint.md)
— the "Fronting — a relationship between a Mint and a Broker" section
has the end-to-end sequence diagram.

> **Self-contained.** This example brings up its own `authserver`
> container; it does not depend on the tier-01..03 examples. The
> standalone `agent.py` shape is purely for readability — in production
> the same SDK calls live inside the tool handler of an MCP server
> whose Mint resource has a fronting link to this Broker.

## What you'll learn

- How to register a [Broker provider](../../../docs/guides/upstream-providers/connecting-providers.md#step-2-register-the-upstream-provider-in-authplane)
  via [`POST /admin/broker-providers`](../../../docs/reference/http-api.md#http-admin-broker-providers-create)
- How to register a Broker-backed [Resource](../../../docs/reference/http-api.md#http-admin-resources-create)
  with `backend_kind=broker` + `broker_provider_slug=…`
- How to register an OAuth client with the
  [`urn:ietf:params:oauth:grant-type:token-exchange`](../../../docs/guides/upstream-providers/token-exchange-grant.md)
  grant type
- How to call `client.exchange(TokenExchangeOptions(...))` on the
  `authplane-sdk` Python client (`client.py:301`) to perform RFC 8693
- How to catch `ConsentRequiredError` and read its `consent_url` field
  — the URL a real user would visit through `/connect/{provider}` to
  land the upstream-OAuth grant

| | |
|---|---|
| **Time to run** | ~2 minutes (first build is ~60s, subsequent runs are seconds) |
| **Prereqs** | Docker 24+, `docker compose`, `curl`, `jq`, **Python 3.12+** (only if you run outside Docker — `pyproject.toml` pins `requires-python = ">=3.12"`) |
| **SDK** | `authplane-sdk` 0.3.0 (PyPI) |
| **Topology** | Agent ↔ Authserver only — no MCP server in this tier |

## Run it in 3 commands

```bash
cp .env.example .env
make run
make verify
```

`make run` builds and brings up only the `authserver` service (the agent
runs under the `manual` profile and is invoked one-shot by `make verify`).
`make verify` registers every artifact the broker exchange needs
(provider, Broker resource, Mint actor resource, OAuth client, two
policies) and then runs the agent. The agent asks for a brokered token
and — because no `broker_grants` row exists for this user/agent pair yet
— receives `consent_required` with a `consent_url`. `make clean` tears
everything down and removes the `.env` file the run target created.

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
> Step 5 emits `client_id` and `client_secret` in its response; assign each
> to a shell variable (`CLIENT_ID=...`, `CLIENT_SECRET=...`) before the
> next step uses it.

1. **Start authserver.** `make run` brings it up with
   `AUTHPLANE_TOKEN_EXCHANGE_ENABLED=true`,
   `AUTHPLANE_DATA_ENCRYPTION_DRIVER=aes_master`,
   `AUTHPLANE_CONNECT_STATE_SECRET=…`, and
   `AUTHPLANE_CONNECT_REDIRECT_BASE_URL=…` — see `.env.example` for the
   full list. Discovery should advertise the token-exchange grant:

   ```bash
   curl -fsS http://localhost:9000/.well-known/oauth-authorization-server \
     | jq '.grant_types_supported | index("urn:ietf:params:oauth:grant-type:token-exchange")'
   ```

   Endpoint:
   [`GET /.well-known/oauth-authorization-server`](../../../docs/reference/http-api.md#http-public-well-known-oauth-authorization-server).

2. **Register a Broker provider.** The provider is the upstream identity
   the AS will (eventually) connect users to. We use a fake hostname
   because this example never actually drives the browser through
   `/connect/<provider>`:

   ```bash
   curl -sS -X POST http://localhost:9001/admin/broker-providers \
     -H "Authorization: Bearer $AUTHPLANE_ADMIN_API_KEY" \
     -H "Content-Type: application/json" \
     -d '{
       "slug": "github-stub",
       "display_name": "GitHub (stub)",
       "protocol": "oauth",
       "config_data": {
         "client_id": "stub-client-id",
         "client_secret_ref": "AUTHPLANE_ADMIN_API_KEY",
         "authorize_url": "https://github-stub.example.invalid/login/oauth/authorize",
         "token_url":     "https://github-stub.example.invalid/login/oauth/access_token"
       }
     }'
   ```

   Endpoint:
   [`POST /admin/broker-providers`](../../../docs/reference/http-api.md#http-admin-broker-providers-create).
   CLI equivalent:
   [`authserver admin provider create`](../../../docs/reference/cli.md#cli-admin-provider-create).

3. **Register the actor MCP (Mint resource).** Even though there's no
   long-lived MCP server in this tier, the Broker exchange dispatch
   identifies the *acting* MCP by looking up a Mint resource that lists
   the calling client_id in its `policy.runtime.client_ids` (see
   `internal/services/token_exchange.go:1244-1255`). Without this row
   the exchange fails with `unauthorized_client`:

   ```bash
   curl -sS -X POST http://localhost:9001/admin/resources \
     -H "Authorization: Bearer $AUTHPLANE_ADMIN_API_KEY" \
     -H "Content-Type: application/json" \
     -d '{
       "slug": "mcp-agent",
       "uri": "http://localhost:8080/mcp",
       "backend_kind": "mint",
       "display_name": "Tier-04 demo agent (actor MCP)",
       "scopes": [{"name": "mcp:tools", "description": "agent base scope"}]
     }'
   ```

   Endpoint:
   [`POST /admin/resources`](../../../docs/reference/http-api.md#http-admin-resources-create).
   CLI equivalent:
   [`authserver admin resource create`](../../../docs/reference/cli.md#cli-admin-resource-create).

4. **Register the Broker resource.** The Broker resource names the
   AS-side fine scopes the agent may request and maps each to an
   upstream scope. `broker_provider_slug` references the provider from
   step 2:

   ```bash
   curl -sS -X POST http://localhost:9001/admin/resources \
     -H "Authorization: Bearer $AUTHPLANE_ADMIN_API_KEY" \
     -H "Content-Type: application/json" \
     -d '{
       "slug": "github",
       "uri": "https://github-stub.example.invalid/api",
       "backend_kind": "broker",
       "broker_provider_slug": "github-stub",
       "display_name": "GitHub (brokered)",
       "scopes": [
         {"name": "repo",      "upstream": "repo",      "description": "repo access"},
         {"name": "read:user", "upstream": "read:user", "description": "user profile"}
       ]
     }'
   ```

5. **Register an OAuth client** with both `client_credentials` (for the
   base machine token) and `urn:ietf:params:oauth:grant-type:token-exchange`
   (for the brokered vend). Public clients cannot do token exchange — see
   [docs/guides/upstream-providers/token-exchange-grant.md, step 2](../../../docs/guides/upstream-providers/token-exchange-grant.md):

   ```bash
   curl -sS -X POST http://localhost:9001/admin/clients \
     -H "Authorization: Bearer $AUTHPLANE_ADMIN_API_KEY" \
     -H "Content-Type: application/json" \
     -d '{
       "client_name": "tier04-broker-agent",
       "grant_types": [
         "client_credentials",
         "urn:ietf:params:oauth:grant-type:token-exchange"
       ],
       "token_endpoint_auth_method": "client_secret_basic",
       "scope": "mcp:tools repo read:user"
     }'
   ```

   Endpoint:
   [`POST /admin/clients`](../../../docs/reference/http-api.md#http-admin-clients-create).
   CLI equivalent:
   [`authserver admin client create`](../../../docs/reference/cli.md#cli-admin-client-create).

6. **Bind the client to the actor MCP.** This is what tier 03 does for
   Mint resources; here it tells the AS "treat this client_id as the
   `mcp-agent` MCP for actor-attestation lookups during token exchange":

   ```bash
   curl -sS -X POST \
     "http://localhost:9001/admin/resources/mcp-agent/policy/runtime/client-ids" \
     -H "Authorization: Bearer $AUTHPLANE_ADMIN_API_KEY" \
     -H "Content-Type: application/json" \
     -d "{\"client_id\": \"$CLIENT_ID\"}"
   ```

   Endpoint:
   [`POST /admin/resources/{slug}/policy/runtime/client-ids`](../../../docs/reference/http-api.md#http-admin-resources-slug-policy-runtime-client-ids-create).
   CLI equivalent:
   [`authserver admin resource runtime-client add`](../../../docs/reference/cli.md#cli-admin-resource-runtime-client-add).

7. **Authorize the client to exchange against the Broker resource.**
   Per-resource ACL for the token-exchange grant:

   ```bash
   curl -sS -X POST \
     "http://localhost:9001/admin/resources/github/policy/exchange/allowed-clients" \
     -H "Authorization: Bearer $AUTHPLANE_ADMIN_API_KEY" \
     -H "Content-Type: application/json" \
     -d "{\"client_id\": \"$CLIENT_ID\"}"
   ```

   Endpoint:
   [`POST /admin/resources/{slug}/policy/exchange/allowed-clients`](../../../docs/reference/http-api.md#http-admin-resources-slug-policy-exchange-allowed-clients-create).
   The CLI exposes this list as the `--policy-allowed-clients` flag on
   [`authserver admin resource create`](../../../docs/reference/cli.md#cli-admin-resource-create);
   there's no per-row add subcommand today.

8. **Run the agent.** The agent (see [`agent.py`](./agent.py)):
   1. Creates an `AuthplaneClient` (no DPoP in this tier).
   2. Mints a base `client_credentials` token. The cc grant is scoped to
      the **Broker resource URI** (not the actor MCP URI) so the subject
      token's `aud` claim resolves directly to the exchange target —
      otherwise the dispatcher would interpret the cross-resource jump as
      a [fronted topology](../../../docs/topologies/) and demand a
      `fronting_links` row (see
      `internal/services/token_exchange.go:1206-1242`). See
      `python-sdk/authplane/client.py` for the helper and
      [`POST /oauth/token`](../../../docs/reference/http-api.md#http-public-oauth-token)
      for the wire shape.
   3. Calls `client.exchange(TokenExchangeOptions(subject_token=...,
      resources=("github",), scope="repo"))` —
      `python-sdk/authplane/client.py:301`.
   4. Receives `consent_required` because there's no `broker_grants`
      row for this user/agent pair yet. The SDK
      (`python-sdk/authplane/errors.py:336-343`) raises
      `ConsentRequiredError`, and the agent reads `e.consent_url`
      (`python-sdk/authplane/errors.py:161`).
   5. Prints the URL and exits.

   `make verify` runs the agent inside this example's compose network so
   it can reach the AS at `authserver:9000`.

## What's happening

### Broker vs Mint

In tiers 01-03 the AS is *minting* its own JWT access tokens that target
your MCP server. Tier 04 introduces the second backend kind: **Broker**.
A Broker resource doesn't issue an AS-signed JWT — instead, on a
successful exchange, the AS reaches out to the upstream provider
(GitHub, Slack, Google, …), refreshes the user's grant if needed, and
returns the **upstream's** actual access token directly to the caller.
Authplane stores the upstream refresh-grant encrypted at rest
(`broker_grants` table, AES-256-GCM via the configured
[`data_encryption`](../../../docs/reference/configuration.md) driver)
and the agent never sees it. The vended `access_token` IS the real
upstream Bearer that the agent can present to `api.github.com`.

### RFC 8693 wire shape

The exchange is a plain form-POST to `/oauth/token` with
`grant_type=urn:ietf:params:oauth:grant-type:token-exchange`. The
`resource=` form param names the **AS-side resource slug** (`github`),
NOT a URL — the AS resolves that to the Broker resource row, which in
turn points at the provider. See
[docs/guides/upstream-providers/token-exchange-grant.md](../../../docs/guides/upstream-providers/token-exchange-grant.md)
for the full request/response shape.

### ConsentRequiredError and `consent_url`

When any of the three-bound consent checks fails, the token endpoint
emits HTTP 400 with `{"error":"consent_required","consent_url":...}`
(the wire field is `consent_url`, per `api/shared/errors.go:40`). The
Python SDK maps this to `ConsentRequiredError` and exposes `.consent_url`
(`python-sdk/authplane/errors.py:145-162`). The URL the AS picks
depends on which bound failed:

- **Bound B** (no agent attestation on file) → `/authorize?resource=<actor-mcp>&scope=...`
  — the user needs to consent to your *agent* acting against your MCP
  resource. This is what this example demonstrates.
- **Bound D** (no broker grant on file) → `/connect/<provider>?...`
  — the user needs to authorize the **upstream provider** (GitHub etc.).
- **Bound C/E** (scope insufficient) → either of the above, with a
  narrower `scope` query parameter.

From the developer's point of view all four shapes look identical: catch
`ConsentRequiredError`, redirect the user to `e.consent_url`, retry the
exchange when they return.

The auth-specific lines live between the `# authplane:begin` /
`# authplane:end` markers in [`agent.py`](./agent.py). Run `go run
./tools/loccount examples/python/04-broker-upstream` from the repo root
to see the measured count.

## Before / After (vs. having no broker at all)

Without Authplane Broker, an MCP server that needs the user's GitHub
token must (a) implement its own OAuth client, (b) store refresh tokens
itself, (c) refresh + revoke them on a schedule, and (d) re-prompt the
user when the refresh chain breaks. The agent sees the refresh token —
the most-stealable credential in the system.

With Authplane Broker the MCP server (or any agent) trades its
AS-issued user-bound token at `/oauth/token` and receives a fresh
upstream Bearer scoped to the requested scopes. Authplane holds the
refresh chain, encrypts it at rest, and proxies the refresh round-trip
transparently. The agent never sees the upstream refresh token.

```diff
+ from authplane import ASCredentials, AuthplaneClient, ConsentRequiredError
+ from authplane.oauth import TokenExchangeOptions

  client = await AuthplaneClient.create(issuer=ISSUER, auth=ASCredentials(...))
  base = (await client.client_credentials(scopes=["mcp:tools"], resources=[MCP_URI])).access_token
+ try:
+     upstream = await client.exchange(TokenExchangeOptions(
+         subject_token=base, scope="repo", resources=("github",),
+     ))
+     # `upstream.access_token` is `gho_…` — pass it to api.github.com directly.
+ except ConsentRequiredError as e:
+     redirect_user_to(e.consent_url)   # /connect/<provider> or /authorize?resource=…
```

## Next

Tier 04 is the final tier shipped today. For advanced topologies
(gateway fan-out, fronted Broker, multi-hop delegation chains, the
service-account-user "bot" pattern) see
[`docs/topologies/`](../../../docs/topologies/) and the
[Token Exchange grant recipe](../../../docs/guides/upstream-providers/token-exchange-grant.md).
SDK helpers and worked examples in other languages live in the public
SDK packages: `github.com/authplane/go-sdk` (Go module proxy) and
`@authplane/sdk` (npm).

## Use a locally-built authserver image

To build the AS from this checkout rather than pulling
`authplane/authserver:latest`, follow the **LOCAL BUILD ESCAPE
HATCH** comment block in
[`../../_shared/docker-compose.authserver.yml`](../../_shared/docker-compose.authserver.yml).
Mirror the change in this example's `docker-compose.yml` (which inlines
the same service definition) — replace the `image:` line with the
`build:` block shown in the shared file.
