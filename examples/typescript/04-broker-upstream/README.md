# Tier 04 — MCP server fronting a Broker (TypeScript)

<!-- loccount:begin -->
**Auth-specific code: 21 lines · Total example: 59 lines · SDK: ts-sdk 0.2.0**
<!-- loccount:end -->

When your MCP server needs to call a third-party API on the user's
behalf — GitHub, Slack, Google Workspace, Notion — it does an
[RFC 8693 Token Exchange](https://www.rfc-editor.org/rfc/rfc8693) against
a Broker-backed Resource. Authplane brokers the OAuth dance with the
provider, holds the user's encrypted refresh token, and vends the
provider's native access token. Your MCP server uses that token to call
the upstream API.

This example shows the SDK's outbound Token Exchange call and how to
handle `ConsentRequiredError` — the typed exception the SDK raises when
the user hasn't connected the provider yet. Its `consentUrl` points the
human at `/connect/{provider}` (or `/authorize?resource=…`, depending
on which bound failed). Everything needed to drive the exchange and
catch the error fits inside `// authplane:begin` / `// authplane:end`
markers in [`agent.ts`](./agent.ts).

For the conceptual model, see [docs/concepts/broker-vs-mint.md](../../../docs/concepts/broker-vs-mint.md)
— the "Fronting — a relationship between a Mint and a Broker" section
has the end-to-end sequence diagram.

> **Self-contained.** This example does not depend on tier-01..03.
> The standalone `agent.ts` shape is purely for readability — in
> production the same SDK calls live inside an MCP server's tool
> handler.

## What you'll learn

- How to enable the Token Exchange grant on Authplane via
  `AUTHPLANE_TOKEN_EXCHANGE_ENABLED=true` (see
  [`docs/reference/env-vars.md`](../../../docs/reference/env-vars.md))
- How to register a [Broker provider](../../../docs/guides/upstream-providers/connecting-providers.md#step-2-register-the-upstream-provider-in-authplane)
  and front it with a `backend_kind=broker` Resource that the agent can
  target by `resource=<slug>`
- How to gate which acting clients may exchange against a Broker resource
  via `policy.exchange.allowed-clients` ([HTTP API anchor](../../../docs/reference/http-api.md#http-admin-resources-slug-policy-exchange-allowed-clients-create))
- How the SDK's `AuthplaneClient.exchange(...)` issues an RFC 8693 call and
  why a missing `broker_grants` row collapses into `ConsentRequiredError`
  with a `consentUrl` you hand to the user
- Where the upstream **refresh** token lives — inside the AS in the
  encrypted `broker_grants` row, never on the wire; every exchange triggers
  a transparent upstream refresh under the hood when the access token has
  expired

| | |
|---|---|
| **Time to run** | ~2 minutes (first build is ~90s, subsequent runs are seconds) |
| **Prereqs** | Docker 24+, `docker compose`, `curl`, `jq`, Node.js 22+ (only if you run outside Docker) |
| **SDK** | `@authplane/sdk` 0.2.0 (npm) |
| **Wire grant** | `urn:ietf:params:oauth:grant-type:token-exchange` (RFC 8693) |
| **Stops at** | the agent catching `ConsentRequiredError` and printing the `consentUrl` — there is no real upstream provider in this example |

## Run it in 3 commands

```bash
cp .env.example .env
make run
make verify
```

`make run` brings up authserver on `:9000`/`:9001` with the Token Exchange
grant enabled. `make verify` registers a placeholder Broker provider, a
Broker-kind Resource, a Mint actor-MCP Resource, and an OAuth client; wires
the client through `policy.runtime.client_ids` and
`policy.exchange.allowed-clients`; then runs the agent as a one-shot
container. The agent acquires a `client_credentials` subject token, calls
`AuthplaneClient.exchange(...)` against the Broker resource, catches the
`ConsentRequiredError`, and prints the `consentUrl`. `make clean` tears
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
> to a shell variable (`CLIENT_ID=...`, `CLIENT_SECRET=...`) before steps 6
> and 7 use them.

1. **Start authserver.** `make run` brings the AS up. The
   `AUTHPLANE_TOKEN_EXCHANGE_ENABLED=true` env var (see
   [`docs/reference/env-vars.md`](../../../docs/reference/env-vars.md))
   advertises `urn:ietf:params:oauth:grant-type:token-exchange` in the
   discovery document and turns on the dispatcher. Wait for the AS to
   answer:

   ```bash
   curl -fsS http://localhost:9000/.well-known/oauth-authorization-server
   ```

2. **Register the Broker provider.** A Broker provider is the AS-side
   record of an upstream OAuth provider's authorize/token URLs and the
   client_secret env-var name. Verified against
   [`POST /admin/broker-providers`](../../../docs/reference/http-api.md#http-admin-broker-providers-create):

   ```bash
   curl -sS -X POST http://localhost:9001/admin/broker-providers \
     -H "Authorization: Bearer $AUTHPLANE_ADMIN_API_KEY" \
     -H "Content-Type: application/json" \
     -d '{
       "slug": "github",
       "display_name": "GitHub OAuth",
       "protocol": "oauth",
       "config_data": {
         "client_id": "Iv1.fakeoauthapp_abc123",
         "client_secret_env": "AUTHPLANE_ADMIN_API_KEY",
         "authorize_url": "https://github.example.invalid/login/oauth/authorize",
         "token_url": "https://github.example.invalid/login/oauth/access_token"
       }
     }'
   ```

   The example uses fake URLs because the agent never reaches the upstream;
   the flow stops at `consent_required`. Connecting a real provider is the
   subject of the
   [Connecting upstream providers](../../../docs/guides/upstream-providers/connecting-providers.md)
   guide.

3. **Register a Broker-kind Resource.** This is the slug the agent passes
   as `resource=<slug>` in the exchange call. Verified against
   [`POST /admin/resources`](../../../docs/reference/http-api.md#http-admin-resources-create):

   ```bash
   curl -sS -X POST http://localhost:9001/admin/resources \
     -H "Authorization: Bearer $AUTHPLANE_ADMIN_API_KEY" \
     -H "Content-Type: application/json" \
     -d '{
       "slug": "github",
       "uri": "https://github.example.invalid",
       "backend_kind": "broker",
       "broker_provider_slug": "github",
       "display_name": "Demo upstream broker",
       "scopes": [{"name": "repo", "description": "repo access", "upstream": "repo"}]
     }'
   ```

4. **Register the actor-MCP Mint Resource.** The agent's `client_credentials`
   subject token carries this resource's URI as `aud`. The Broker
   dispatch's agent-attestation gate maps `req.client_id` back to this
   resource via `policy.runtime.client_ids` (next step). Same DTO, this
   time with `backend_kind=mint`:

   ```bash
   curl -sS -X POST http://localhost:9001/admin/resources \
     -H "Authorization: Bearer $AUTHPLANE_ADMIN_API_KEY" \
     -H "Content-Type: application/json" \
     -d '{
       "slug": "demo-mcp-tier04",
       "uri": "http://localhost:8080/mcp",
       "backend_kind": "mint",
       "display_name": "Demo actor MCP",
       "scopes": [{"name": "repo", "description": "actor-side repo scope"}]
     }'
   ```

5. **Register an OAuth client with both grants.** The client needs
   `client_credentials` (to acquire the subject token) **and**
   `urn:ietf:params:oauth:grant-type:token-exchange` (to call the exchange).
   See
   [`docs/reference/http-api.md#http-admin-clients-create`](../../../docs/reference/http-api.md#http-admin-clients-create):

   ```bash
   curl -sS -X POST http://localhost:9001/admin/clients \
     -H "Authorization: Bearer $AUTHPLANE_ADMIN_API_KEY" \
     -H "Content-Type: application/json" \
     -d '{
       "client_name": "demo-broker-upstream-client",
       "grant_types": ["client_credentials", "urn:ietf:params:oauth:grant-type:token-exchange"],
       "token_endpoint_auth_method": "client_secret_basic",
       "scope": "repo"
     }'
   ```

6. **Wire both policies.** The actor linkage is `policy.runtime.client_ids`
   on the Mint resource (anchor:
   [`http-admin-resources-slug-policy-runtime-client-ids-create`](../../../docs/reference/http-api.md#http-admin-resources-slug-policy-runtime-client-ids-create));
   the exchange ACL is `policy.exchange.allowed-clients` on the Broker
   resource (anchor:
   [`http-admin-resources-slug-policy-exchange-allowed-clients-create`](../../../docs/reference/http-api.md#http-admin-resources-slug-policy-exchange-allowed-clients-create)):

   ```bash
   curl -sS -X POST \
     "http://localhost:9001/admin/resources/demo-mcp-tier04/policy/runtime/client-ids" \
     -H "Authorization: Bearer $AUTHPLANE_ADMIN_API_KEY" \
     -H "Content-Type: application/json" \
     -d "{\"client_id\": \"$CLIENT_ID\"}"

   curl -sS -X POST \
     "http://localhost:9001/admin/resources/github/policy/exchange/allowed-clients" \
     -H "Authorization: Bearer $AUTHPLANE_ADMIN_API_KEY" \
     -H "Content-Type: application/json" \
     -d "{\"client_id\": \"$CLIENT_ID\"}"
   ```

7. **Run the agent.** The agent acquires a `client_credentials` token
   against the Broker resource, then calls `AuthplaneClient.exchange(...)`
   against it. Because no `broker_grants` row exists for the
   (user, provider) pair, the AS replies `consent_required` with a
   `consent_url`; the SDK surfaces a `ConsentRequiredError` whose
   `consentUrl` field carries that URL. See
   [`docs/reference/http-api.md#http-public-oauth-token`](../../../docs/reference/http-api.md#http-public-oauth-token):

   ```bash
   docker compose run --rm \
     -e AUTHPLANE_ISSUER=http://authserver:9000 \
     -e AUTHPLANE_CLIENT_ID="$CLIENT_ID" \
     -e AUTHPLANE_CLIENT_SECRET="$CLIENT_SECRET" \
     -e UPSTREAM_RESOURCE=github \
     -e BROKER_RESOURCE_URI=https://github.example.invalid \
     agent
   ```

   Expected output:

   ```
   [agent] consent_required: visit http://authserver:9000/connect/github?...
   ```

   The agent exits `2` — this is the expected branch for tier 04 because
   the user has not connected the upstream. In production the operator
   hands `consentUrl` to the human, who runs the
   [`/connect/{provider}`](../../../docs/reference/http-api.md#http-public-connect-provider)
   flow once, and the next `exchange(...)` call returns the vended
   upstream token.

## Before / After

A naive client that ignores the consent path:

```diff
- const upstream = await ap.exchange({
-   subjectToken: subject.accessToken,
-   scope: "repo",
-   resources: ["github"],
- });
- // -> throws an opaque OAuth error; nothing to tell the user
```

The same client with `ConsentRequiredError` handling:

```diff
+ try {
+   const upstream = await ap.exchange({
+     subjectToken: subject.accessToken,
+     scope: "repo",
+     resources: ["github"],
+   });
+   // -> upstream.accessToken is the vended upstream provider token
+ } catch (e) {
+   if (e instanceof ConsentRequiredError) {
+     console.log(`Consent required, user must visit: ${e.consentUrl}`);
+     process.exit(2);
+   }
+   throw e;
+ }
```

The full auth-specific footprint lives inside the `// authplane:begin` /
`// authplane:end` markers in [`agent.ts`](./agent.ts). Run
`go run ./tools/loccount examples/typescript/04-broker-upstream` from the
repo root to see the count.

## What's happening

A **Broker resource** is the AS-side surface for an upstream OAuth provider
(GitHub, Google, Slack, ...). Unlike Mint resources, the AS does not sign a
new JWT — it returns the actual upstream provider's access token, refreshed
on demand using the encrypted `broker_grants.refresh_token` it stored when
the user ran `/connect/{provider}` the first time.

Every brokered vend has to clear the **three-bound check** (see
[`docs/guides/upstream-providers/connecting-providers.md`](../../../docs/guides/upstream-providers/connecting-providers.md)):

1. **Consent grant** — the user has a `consent_grants` row for
   `(user_id, agent_client_id, actor_mcp_resource_id)`. Without it, the
   AS returns `consent_required` with `consent_url` pointing at
   `/authorize?resource=<actor_mcp>`.
2. **Broker grant** — the user has a `broker_grants` row for
   `(user_id, broker_provider_id)` and the requested scopes are ⊆
   `scopes_granted`. Without it (or with a strict subset), the AS returns
   `consent_required` with `consent_url` pointing at
   `/connect/{provider}`.
3. **Operator gate** — the acting `client_id` is in
   `policy.exchange.allowed_client_ids` (or the list is empty). Without it
   the response is `access_denied`.

This example exercises the first failure mode end-to-end: the verify script
sets up everything **except** the `broker_grants` row, so the agent
deterministically lands on the `consent_required` branch and the
`ConsentRequiredError.consentUrl` field carries the URL the operator would
hand to a human.

On the SDK side, `AuthplaneClient.exchange({subjectToken, scope, resources})`
builds the RFC 8693 form body, signs it with the client credentials the
constructor was given, and posts it to `POST /oauth/token` (anchor:
[`http-public-oauth-token`](../../../docs/reference/http-api.md#http-public-oauth-token)).
The response is parsed; the `consent_required` shape (`{error, consent_url, cause}`)
is mapped to a typed `ConsentRequiredError` (`@authplane/sdk/dist/auth/errors.d.ts:30`)
whose `consentUrl` field comes from the wire `consent_url` (snake-case on
the wire, camelCase in TypeScript — `@authplane/sdk/dist/auth/errors.js:115-121`).
Every other OAuth error code is mapped to its own typed error class by the
same `mapOAuthError` helper.

## Next

- Connect a real upstream provider end-to-end:
  [Guides → Connecting upstream providers](../../../docs/guides/upstream-providers/connecting-providers.md)
- Pick the right exchange shape (brokered vend vs delegation vs scope
  narrowing): [Guides → Token Exchange grant](../../../docs/guides/upstream-providers/token-exchange-grant.md)
- Topology reference for Broker-fronted Mint resources:
  [`docs/topologies/folded-resource.md`](../../../docs/topologies/folded-resource.md)
  — the canonical map for how Broker and Mint resources combine in real
  deployments.

## Use a locally-built authserver image

To build the AS from this checkout rather than pulling
`authplane/authserver:latest`, follow the **LOCAL BUILD ESCAPE
HATCH** comment block in
[`../../_shared/docker-compose.authserver.yml`](../../_shared/docker-compose.authserver.yml).
Mirror the change in this example's `docker-compose.yml` (which inlines
the same service definition) — replace the `image:` line with the
`build:` block shown in the shared file.
