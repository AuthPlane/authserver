# Tier 02 — Calling another resource from your MCP server (Go)

<!-- loccount:begin -->
**Auth-specific code: 5 lines · Total example: 45 lines · SDK: go-sdk v0.1.1**
<!-- loccount:end -->

When your MCP server needs to call another resource — another Mint MCP
server, an admin service, any backend that trusts Authplane — it
acquires a token via the `github.com/authplane/go-sdk/core` Auth Client.
This example isolates that outbound OAuth call so you can see what the
SDK does: build a client, request a `client_credentials` token, present
it on the call. In your real MCP server, this code lives inside the
tool handler that needs to talk to the other resource — the standalone
`main.go` shape here is purely for readability.

## What you'll learn

- How to acquire an Authplane access token from a Go agent with the
  `github.com/authplane/go-sdk/core` SDK
- How the `client_credentials` grant pairs with the `resource=` parameter
  to mint a JWT whose audience matches a registered
  [Mint Resource](../../../docs/concepts/glossary.md#glossary-mint-backend)
- How to call a protected MCP tool over HTTP with the resulting bearer
  token — and how the tier-01 server validates it before invoking the tool

| | |
|---|---|
| **Time to run** | ~30 seconds once tier-01 is up |
| **Prereqs** | The tier-01 example is up (`cd ../01-mcp-server-basic && make run && make verify`), plus `go 1.25+`, `curl`, `jq` |
| **SDK** | `github.com/authplane/go-sdk/core` v0.1.1 (Go module proxy) |
| **Pairs with** | [Tier 01 — Basic MCP server (Go)](../01-mcp-server-basic/) — the agent calls into the MCP server that tier brings up |

## Run it in 3 commands

```bash
# In one terminal: bring up tier-01.
cd ../01-mcp-server-basic && make run && make verify

# Back in this directory:
cp .env.example .env
make verify   # no-op today — see callout above
```

`make verify` registers a fresh
`client_credentials` client against the running authserver, writes the
returned `client_id` / `client_secret` into `.env`, runs the agent
(`go run ./`), and asserts that the agent successfully called the tier-01
MCP server's `echo` tool. `make clean` removes the `.env` file the run
target created.

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
> Steps 2 and 4 emit `client_id`, `client_secret`, and `access_token` in
> their responses; assign each to a shell variable (`CLIENT_ID=...`,
> `CLIENT_SECRET=...`, `ACCESS_TOKEN=...`) before the next step uses it.

1. **Confirm tier-01 is running.** The agent calls
   `http://localhost:8080/mcp` — that's the tier-01 MCP server. Without it,
   the agent has nothing to call. Tier-01's `make verify` also registers
   the Mint Resource the AS needs to mint a matching JWT audience.

   ```bash
   curl -fsS http://localhost:9000/.well-known/oauth-authorization-server
   curl -s  -o /dev/null -w '%{http_code}\n' http://localhost:8080/mcp   # expect 401
   ```

2. **Register a fresh OAuth client.** The tier-01 verify script also
   registers a client, but it lives in that script's local scope. The
   simplest path is to register a new one here so the credentials live in
   this directory's `.env`. The CLI form is also valid (see
   [`docs/reference/cli.md#cli-admin-client-create`](../../../docs/reference/cli.md#cli-admin-client-create)):

   ```bash
   curl -sS -X POST http://localhost:9001/admin/clients \
     -H "Authorization: Bearer $AUTHPLANE_ADMIN_API_KEY" \
     -H "Content-Type: application/json" \
     -d '{
       "client_name": "demo-mcp-agent",
       "grant_types": ["client_credentials"],
       "token_endpoint_auth_method": "client_secret_basic",
       "scope": "mcp:echo"
     }'
   ```

   The response carries `client_id` and `client_secret`. The secret is
   shown once.

3. **(Reference) Mint a token by hand.** The SDK does this internally —
   you do **not** call `/oauth/token` from Go code. Curl version for
   reference; see
   [`docs/reference/http-api.md#http-public-oauth-token`](../../../docs/reference/http-api.md#http-public-oauth-token):

   ```bash
   curl -sS -X POST http://localhost:9000/oauth/token \
     -u "$CLIENT_ID:$CLIENT_SECRET" \
     -d "grant_type=client_credentials" \
     -d "scope=mcp:echo" \
     --data-urlencode "resource=http://localhost:8080/mcp"
   ```

   The Go agent in `main.go` builds the same request via
   `client.ClientCredentials(ctx, scopes, resources)`. The response
   includes `access_token`, `token_type=Bearer`, `expires_in`, and
   `scope`. There is no refresh token for `client_credentials`.

4. **Run the agent.** With `AUTHPLANE_CLIENT_ID` / `AUTHPLANE_CLIENT_SECRET`
   in `.env`:

   ```bash
   set -a; source .env; set +a
   go run ./
   ```

   The agent POSTs a `tools/call` JSON-RPC request to
   `http://localhost:8080/mcp` carrying the bearer token, and prints the
   echoed text on stdout. Drop the `Authorization` header and you'll see
   a 401 — proof that the tier-01 server is actually enforcing auth.

## Before / After

A plain Go agent that calls an unauthenticated MCP server:

```go
body := []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{...}}`)
req, _ := http.NewRequest(http.MethodPost, mcpURL, bytes.NewReader(body))
req.Header.Set("Content-Type", "application/json")
resp, _ := http.DefaultClient.Do(req)
```

The same agent with an Authplane-minted bearer token:

```diff
+ client, _ := authplane.NewClient(ctx, os.Getenv("AUTHPLANE_ISSUER"),
+     authplane.WithClientCredentials(os.Getenv("AUTHPLANE_CLIENT_ID"), os.Getenv("AUTHPLANE_CLIENT_SECRET")),
+ )
+ defer client.Close()
+ tok, _ := client.ClientCredentials(ctx, []string{"mcp:echo"}, []string{resource})
  body := []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{...}}`)
  req, _ := http.NewRequest(http.MethodPost, mcpURL, bytes.NewReader(body))
+ req.Header.Set("Authorization", "Bearer "+tok.AccessToken)
  req.Header.Set("Content-Type", "application/json")
  resp, _ := http.DefaultClient.Do(req)
```

The auth-specific lines live inside the `// authplane:begin` /
`// authplane:end` markers in [`main.go`](./main.go). The example uses the
same small `must[T]` generic helper as tier-01 (defined at the bottom of
`main.go`) to keep the auth call concise; swap it for explicit
`if err != nil { ... }` in production. Run
`go run ./tools/loccount examples/go/02-agent-basic` from the repo root
to see the count.

## What's happening

`authplane.NewClient` performs RFC 8414 AS metadata discovery against the
issuer, fetches the JWKS, and constructs a `Client` that knows how to talk
to the AS's token endpoint. The
`ClientCredentials` method
posts `grant_type=client_credentials` to that endpoint with the
configured client credentials in an HTTP Basic header (RFC 6749 §2.3.1),
the requested `scope`, and the `resource=` parameter. The AS verifies
the client and the requested scope against the target Resource, then
issues an access token whose `aud` claim is the Resource URI. The SDK caches the token until shortly before `exp` so subsequent
calls are local. The agent embeds the token in an `Authorization: Bearer`
header on its outbound MCP call; the tier-01 server's adapter validates
the signature, audience, scope, and expiry before invoking the tool.

## Next

[Tier 03 — MCP server + agent with DPoP + per-tool scopes](../03-mcp-server-dpop-scopes/)
adds RFC 9449 proof-of-possession so a stolen bearer token alone is not
enough to call the resource, and demonstrates per-tool scope enforcement.
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
