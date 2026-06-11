# Tier 04 — MCP server fronting a Broker (Go)

When your MCP server needs to call a third-party API on the user's
behalf — GitHub, Slack, Google Workspace — it does an [RFC 8693 Token
Exchange](../../../docs/reference/http-api.md#http-public-oauth-token)
against a Broker-backed resource. Authplane brokers the OAuth dance
with the provider, holds the user's encrypted refresh token, and vends
the provider's native access token (e.g. a `gho_…` GitHub token —
never an AS-signed JWT for a Broker resource). Your MCP server uses
that token to call the upstream API.

This example shows the SDK's outbound Token Exchange call and how to
handle `*authplane.ConsentRequiredError` — the typed error the SDK
returns when the user hasn't authorized the upstream provider yet. Its
`ConsentURL` field points the operator at the right next step
(`/connect/{provider}` for the broker grant, `/authorize?resource=…`
for per-resource consent), so a real MCP server can `errors.As`-pivot
into a consent-elicitation flow instead of failing hard.

For the conceptual model — including why this is the *fronting*
pattern — see [docs/concepts/broker-vs-mint.md](../../../docs/concepts/broker-vs-mint.md).

The standalone `main.go` shape is purely for readability; in
production the same SDK calls live inside an MCP server's tool handler.

All the auth-specific code fits inside the `// authplane:begin` /
`// authplane:end` markers in [`main.go`](./main.go); the rest is the stub
that prints the vended-token shape.

<!-- loccount:begin -->
**Auth-specific code: 19 lines · Total example: 49 lines · SDK: go-sdk v0.1.1**
<!-- loccount:end -->

## What you'll learn

- How to perform an RFC 8693 token exchange in the Go SDK with
  `(*authplane.Client).TokenExchange` and the input shape
  `authplane.TokenExchangeInput`
- How to pivot on `*authplane.ConsentRequiredError` using `errors.As` so
  a `consent_required` response routes into a consent-elicitation
  branch instead of `log.Fatal`
- How to read the `ConsentURL` field (camelCase Go struct field; wire
  format is the JSON `consent_url`, defined in
  [`api/shared/errors.go:36`](../../../api/shared/errors.go))
- How to wire the AS-side knobs — register a broker provider, expose it as
  a `backend_kind=broker` resource with a scope catalog, gate it with
  `policy.exchange.allowed_client_ids`

| | |
|---|---|
| **Time to run** | ~2 minutes (first build ~90s; subsequent runs are seconds) |
| **Prereqs** | Docker 24+, `docker compose`, `go 1.25+`, `curl`, `jq`, a GitHub OAuth App (for live runs) |
| **SDK** | `github.com/authplane/go-sdk/core` v0.1.1 (Go module proxy) |
| **Grant** | `urn:ietf:params:oauth:grant-type:token-exchange` (RFC 8693) |
| **Upstream** | GitHub by default; the same recipe works for Google / Slack / Notion / Linear / Atlassian — see [`docs/guides/upstream-providers/connecting-providers.md`](../../../docs/guides/upstream-providers/connecting-providers.md) step 2 table |
| **Builds on** | [Tier 03 — DPoP + per-tool scopes (Go)](../03-mcp-server-dpop-scopes/) — tier 03 vends AS-signed JWTs; tier 04 keeps that foundation and swaps the grant out for the brokered upstream vend. |

## Run it in 3 commands

```bash
cp .env.example .env
make run
make verify   # no-op today — see callout above
```

`make run` brings up authserver via `docker-compose.yml`. `make verify`
registers the broker provider + Broker resource + acting client, authorizes
the client on the resource, then runs the agent (`go run ./`) and asserts
that it receives `ConsentRequiredError` and prints the `consent_url`. To
complete the round-trip against a real upstream, a user would visit that
`consent_url` (`/connect/{provider}`) and approve at the provider; the
agent's next call then succeeds with no code change.

## Step by step

The `make verify` script automates every step below; the bullets here
describe what's happening so you can reproduce the flow by hand.

> If you want to run the curl examples manually instead of via `make verify`,
> first load the env vars:
>
> ```bash
> set -a; source .env; set +a   # exports AUTHPLANE_ADMIN_API_KEY etc.
> ```

1. **Confirm the AS advertises the token-exchange grant.** Verified
   against
   [`GET /.well-known/oauth-authorization-server`](../../../docs/reference/http-api.md#http-public-well-known-oauth-authorization-server):

   ```bash
   curl -fsS http://localhost:9000/.well-known/oauth-authorization-server \
     | jq '.grant_types_supported'
   ```

   The list should include
   `"urn:ietf:params:oauth:grant-type:token-exchange"`. If not, set
   `AUTHPLANE_TOKEN_EXCHANGE_ENABLED=true` (already done in `.env.example`)
   and restart.

2. **Register the upstream broker provider.** Put your GitHub OAuth App's
   secret in `CONNECTOR_GITHUB_SECRET` — the AS reads it by env-var name so
   the value never appears in any config file. Verified against
   [`POST /admin/broker-providers`](../../../docs/reference/http-api.md#http-admin-broker-providers-create):

   ```bash
   curl -sS -X POST http://localhost:9001/admin/broker-providers \
     -H "Authorization: Bearer $AUTHPLANE_ADMIN_API_KEY" \
     -H "Content-Type: application/json" \
     -d '{
       "slug": "github",
       "display_name": "GitHub",
       "protocol": "oauth",
       "config_data": {
         "client_id": "<from github oauth app>",
         "client_secret_env": "CONNECTOR_GITHUB_SECRET",
         "authorize_url": "https://github.com/login/oauth/authorize",
         "token_url": "https://github.com/login/oauth/access_token"
       }
     }'
   ```

   CLI equivalent — verified against
   [`authserver admin provider create`](../../../docs/reference/cli.md#cli-admin-provider-create).

3. **Register the actor MCP as a Mint resource.** The broker dispatch path
   identifies the acting MCP by looking up a Mint resource whose
   `policy.runtime.client_ids` contains the acting client_id; without this
   row the exchange is rejected with `unauthorized_client` before any
   consent check runs. Verified against
   [`POST /admin/resources`](../../../docs/reference/http-api.md#http-admin-resources-create):

   ```bash
   curl -sS -X POST http://localhost:9001/admin/resources \
     -H "Authorization: Bearer $AUTHPLANE_ADMIN_API_KEY" \
     -H "Content-Type: application/json" \
     -d '{
       "slug": "mcp-agent-go",
       "uri": "http://localhost:8080/mcp-go",
       "backend_kind": "mint",
       "display_name": "Tier-04 Go demo agent (actor MCP)",
       "scopes": [
         { "name": "mcp:tools", "description": "agent base scope" }
       ]
     }'
   ```

4. **Expose the provider as a Broker resource** with a scope catalog. Each
   `scopes[].upstream` value is the upstream scope the AS sends to GitHub on
   the consent redirect and uses for the bound-E check. Verified against
   [`POST /admin/resources`](../../../docs/reference/http-api.md#http-admin-resources-create):

   ```bash
   curl -sS -X POST http://localhost:9001/admin/resources \
     -H "Authorization: Bearer $AUTHPLANE_ADMIN_API_KEY" \
     -H "Content-Type: application/json" \
     -d '{
       "slug": "github",
       "uri": "https://github-stub.example.invalid/api",
       "backend_kind": "broker",
       "broker_provider_slug": "github",
       "display_name": "GitHub (broker)",
       "scopes": [
         { "name": "repo",      "upstream": "repo" },
         { "name": "read:user", "upstream": "read:user" }
       ]
     }'
   ```

   CLI equivalent — verified against
   [`authserver admin resource create`](../../../docs/reference/cli.md#cli-admin-resource-create).

5. **Register the acting confidential client** with BOTH `client_credentials`
   (so you can mint the `subject_token` in step 8 below) AND the
   token-exchange grant (the grant the agent itself uses). Public clients
   cannot perform token exchange — see
   [`docs/guides/upstream-providers/token-exchange-grant.md`](../../../docs/guides/upstream-providers/token-exchange-grant.md)
   step 2. Verified against
   [`POST /admin/clients`](../../../docs/reference/http-api.md#http-admin-clients-create):

   ```bash
   curl -sS -X POST http://localhost:9001/admin/clients \
     -H "Authorization: Bearer $AUTHPLANE_ADMIN_API_KEY" \
     -H "Content-Type: application/json" \
     -d '{
       "client_name": "demo-broker-tier04-agent",
       "grant_types": [
         "client_credentials",
         "urn:ietf:params:oauth:grant-type:token-exchange"
       ],
       "token_endpoint_auth_method": "client_secret_basic",
       "scope": "mcp:tools repo read:user"
     }'
   ```

   The response carries `client_id` and `client_secret`. The secret is shown
   once.

6. **Bind the client to the actor MCP** via
   `policy.runtime.client_ids`. Without this, `resolveActorMCP` can't map
   the acting client_id back to its Mint resource and the exchange returns
   `unauthorized_client`. Verified against
   [`POST /admin/resources/{slug}/policy/runtime/client-ids`](../../../docs/reference/http-api.md#http-admin-resources-slug-policy-runtime-client-ids-create):

   ```bash
   curl -sS -X POST \
     "http://localhost:9001/admin/resources/mcp-agent-go/policy/runtime/client-ids" \
     -H "Authorization: Bearer $AUTHPLANE_ADMIN_API_KEY" \
     -H "Content-Type: application/json" \
     -d "{\"client_id\": \"$CLIENT_ID\"}"
   ```

7. **Add the client to `policy.exchange.allowed_client_ids`** on the broker
   resource. This is the third bound of the three-bound check (the other
   two are `consent_grants` and `broker_grants`). Verified against
   [`POST /admin/resources/{slug}/policy/exchange/allowed-clients`](../../../docs/reference/http-api.md#http-admin-resources-slug-policy-exchange-allowed-clients-create):

   ```bash
   curl -sS -X POST \
     "http://localhost:9001/admin/resources/github/policy/exchange/allowed-clients" \
     -H "Authorization: Bearer $AUTHPLANE_ADMIN_API_KEY" \
     -H "Content-Type: application/json" \
     -d "{\"client_id\": \"$CLIENT_ID\"}"
   ```

8. **Mint a base `subject_token` via `client_credentials`.** In a real
   deployment the MCP server forwards the user's access token verbatim
   (obtained from the interactive consent flow described in the next
   step); for self-contained reproduction we mint a service-account token
   that stands in for it. Verified against
   [`POST /oauth/token`](../../../docs/reference/http-api.md#http-public-oauth-token):

   ```bash
   USER_ACCESS_TOKEN=$(curl -sS -X POST http://localhost:9000/oauth/token \
     -u "$CLIENT_ID:$CLIENT_SECRET" \
     -H "Content-Type: application/x-www-form-urlencoded" \
     --data-urlencode "grant_type=client_credentials" \
     --data-urlencode "scope=mcp:tools" \
     --data-urlencode "resource=https://github-stub.example.invalid/api" \
     | jq -r '.access_token')
   ```

9. **Get the user's consent.** Direct the user's browser to
   [`GET /connect/{provider}`](../../../docs/reference/http-api.md#http-public-connect-provider) —
   this is where `ConsentRequiredError.ConsentURL` points when the first
   exchange call comes back with `consent_required`:

   ```
   GET /connect/github?resource=github&return_url=https://app.example.com/connected
   ```

   On approval the AS writes a `broker_grants` row keyed
   `(user_id, broker_provider_id)`. You can confirm with
   [`GET /admin/users/{id}/grants`](../../../docs/reference/http-api.md#http-admin-users-id-grants-list).

10. **Vend the upstream token via RFC 8693.** With `$USER_ACCESS_TOKEN` set
    (from step 8 for the demo path, or from the real consent flow in
    production), the agent calls — verified against
    [`POST /oauth/token`](../../../docs/reference/http-api.md#http-public-oauth-token)
    with `grant_type=urn:ietf:params:oauth:grant-type:token-exchange`:

    ```bash
    set -a; source .env; set +a
    go run ./
    ```

    On success the agent prints:

    ```text
    upstream token vended:
      token_type        = Bearer
      issued_token_type = urn:ietf:params:oauth:token-type:access_token
      expires_in        = 3600
      scope             = repo
      access_token      = (redacted; length=44)
    ```

    On `consent_required` it exits 2 and prints the `ConsentURL` to stderr —
    open it in a browser, complete the upstream consent, and rerun.

## Before / After

The tier-03 agent acquired an AS-issued, DPoP-bound JWT and called the MCP
server with it. The tier-04 agent skips that JWT entirely and goes
straight to an RFC 8693 exchange for the upstream provider's actual token:

```diff
- client, _ := authplane.NewClient(ctx, os.Getenv("AUTHPLANE_ISSUER"),
-     authplane.WithClientCredentials(id, secret),
-     authplane.WithDPoP(km))
- tok, _ := client.ClientCredentials(ctx, []string{"mcp:echo", "mcp:add"}, []string{resource})
+ client, _ := authplane.NewClient(ctx, os.Getenv("AUTHPLANE_ISSUER"),
+     authplane.WithClientCredentials(id, secret))
+ tok, err := client.TokenExchange(ctx, authplane.TokenExchangeInput{
+     SubjectToken:     userToken,
+     SubjectTokenType: "urn:ietf:params:oauth:token-type:access_token",
+     Resources:        []string{resource},
+     Scopes:           []string{"repo"},
+ })
+ var consentErr *authplane.ConsentRequiredError
+ if errors.As(err, &consentErr) {
+     // surface consentErr.ConsentURL to the caller (human, MCP client, ...);
+     // they complete /connect/{provider}, then we retry the exchange.
+ }
```

`tok.AccessToken` is now the **actual upstream token** (e.g.
`gho_xxxx…`), not an AS-signed JWT — `backend_kind=broker` short-circuits
the AS's own minting and forwards the upstream's token verbatim. See
[`docs/concepts/broker-vs-mint.md`](../../../docs/concepts/broker-vs-mint.md).

The auth-specific lines live inside the `// authplane:begin` /
`// authplane:end` markers in [`main.go`](./main.go). Run
`go run ./tools/loccount examples/go/04-broker-upstream` from the repo root
to see the count. A `must[T]` helper at the bottom of `main.go` (carried
over from tiers 01/02/03) keeps `NewClient`'s error handling out of the
marked block so the auth-LOC count stays focused on the SDK call shape —
in your own code, prefer canonical Go error handling.

## What's happening

**On the AS:** with `AUTHPLANE_TOKEN_EXCHANGE_ENABLED=true`
([`docs/reference/env-vars.md`](../../../docs/reference/env-vars.md)), the
token endpoint accepts
`grant_type=urn:ietf:params:oauth:grant-type:token-exchange`. For
`backend_kind=broker` resources the AS runs the three-bound check before
vending:

- requested scopes ⊆ `consent_grants.scopes` for `(user, agent, resource)`
  — set when the user runs `/authorize?resource=…` against the AS
- requested scopes ⊆ `broker_grants.scopes_granted` for
  `(user, broker_provider)` — set when the user runs
  `/connect/{provider}` and approves at the upstream
- acting client ∈ `policy.exchange.allowed_client_ids` for the resource

If any bound fails, the AS responds with HTTP 400 + JSON
`{"error":"consent_required","consent_url":"…","cause":"…"}`. The
`consent_url` field is defined in
[`api/shared/errors.go:36`](../../../api/shared/errors.go) and the AS
chooses between `/connect/{provider}` (bound C/E failures) and
`/authorize?resource=…` (bound B failures) based on the `cause`
sub-discriminator
(see [`docs/guides/upstream-providers/connecting-providers.md`](../../../docs/guides/upstream-providers/connecting-providers.md)
troubleshooting table).

**In the Go SDK:** `(*Client).TokenExchange` wraps the OAuth call,
applies the circuit breaker and token cache, and surfaces the
`consent_required` response as a typed `*authplane.ConsentRequiredError`.
The struct carries `ConsentURL`, `Description`, and
`Cause` (an `error` you can further unwrap to one of the
`oauth.Err*` sentinels). `errors.As(err, &consentErr)` is the
canonical pivot — `errors.Is(err, authplane.ErrConsentRequired)` also
works for the case where you only care that consent is needed and not
where the user should go.

**On the wire:** the AS replies with the upstream provider's actual access
token (e.g. `gho_…` for GitHub). The `issued_token_type` field is
`urn:ietf:params:oauth:token-type:access_token` and `token_type` is
typically `Bearer` (the upstream's choice). DPoP propagation rules apply
when the requesting client presents a DPoP proof — see
[`docs/guides/upstream-providers/token-exchange-grant.md` § DPoP propagation](../../../docs/guides/upstream-providers/token-exchange-grant.md#dpop-propagation).

## Next

The tier-04 example is the highest of the four numbered tiers in the Go
track. Combine it with tier 03 to ship a real broker MCP server: take the
DPoP + scope-gated MCP server from tier 03 and call `TokenExchange` from
inside a tool handler when the tool needs to talk to an upstream provider
on behalf of the user. See
[`docs/topologies/broker-mcp.md`](../../../docs/topologies/broker-mcp.md)
for the deployment topology.

## Use a locally-built authserver image

To build the AS from this checkout rather than pulling
`authplane/authserver:latest`, follow the **LOCAL BUILD ESCAPE
HATCH** comment block in
[`../../_shared/docker-compose.authserver.yml`](../../_shared/docker-compose.authserver.yml).
Mirror the change in this example's `docker-compose.yml` (which inlines
the same service definition) — replace the `image:` line with the
`build:` block shown in the shared file.
