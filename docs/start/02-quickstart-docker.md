# 02 — Quickstart with Docker

> For full documentation, see the [Documentation Index](../README.md).

**Time:** ~5 minutes. **Prereqs:** Docker. **Outcome:** authserver
running locally, an admin user, a registered resource server, a working
discovery endpoint.

Get a working MCP authorization server in under 10 minutes.

## Prerequisites

- Docker (any recent version)

## 1. Pull the image

```bash
docker pull authplane/authserver:latest
```

That's the published, signed release image — the path 99% of users want. Use it everywhere the steps below reference `authserver:latest`.

<details>
<summary>Alternative: build from a local checkout</summary>

Only needed if you're contributing to authserver itself or testing an unreleased change:

```bash
git clone https://github.com/authplane/authserver.git
cd authserver
docker build -t authserver:local -f build/Dockerfile .
```

Then substitute `authserver:local` for `authplane/authserver:latest` in the `docker run` command below.

</details>

## 2. Create a config file

Generate an admin API key first — you'll use it to call the admin API and log in to the Admin UI:

```bash
export AUTHPLANE_ADMIN_API_KEY="$(openssl rand -hex 32)"
```

```bash
cat > config.yaml << EOF
server:
  issuer: "http://localhost:9000"
  address: ":9000"

storage:
  driver: sqlite
  sqlite:
    path: "/data/authserver.db"
    wal: true

signing:
  algorithm: ES256
  key_path: "/data/keys"

dcr:
  mode: open

admin:
  enabled: true
  address: ":9001"
  api_key: "${AUTHPLANE_ADMIN_API_KEY}"

# Grants are off by default. Enable the ones your clients will use.
# (See docs/concepts/resources-and-scopes.md for which grant fits which use case.)
client_credentials:
  enabled: true       # machine-to-machine — the simplest MCP-server path
token_exchange:
  enabled: true       # RFC 8693 — needed for agent-to-agent delegation and Broker upstreams
  max_chain_depth: 5
  token_expiry: 1h

EOF
```

The config file deliberately does NOT preseed any resources. Step 5 below
registers your first resource via the admin CLI / API — that's the path
you'll use day-to-day. If you want to commit a resource to config (for
reproducible boots) the syntax is documented in
[`docs/reference/configuration.md`](../reference/configuration.md), but
the admin path is what the docs walk through.

## 3. Start the server

```bash
docker run -d --name authserver \
  -v $(pwd)/config.yaml:/config.yaml:ro \
  -v authserver-data:/data \
  -p 9000:9000 \
  -p 9001:9001 \
  authplane/authserver:latest serve --config /config.yaml
```

## 4. Create an admin user

```bash
docker exec authserver /authserver --config /config.yaml admin user create \
  --email admin@example.com \
  --password changeme \
  --role admin
```

## 5. Register a resource server (with its scopes)

Scopes are declared on the resource server they belong to. Register one via the CLI:

```bash
docker exec authserver /authserver --config /config.yaml admin resource create \
  --slug my-mcp-server \
  --backend-kind mint \
  --uri "http://localhost:8080/mcp" \
  --scopes 'mcp:echo||Echo a message' \
  --scopes 'mcp:add||Add two numbers'
```

The `--scopes` flag is repeatable. Each value is a `name|upstream|description`
tuple — for Mint resources the middle (upstream) part is empty, so the form
is `name||description` (double pipe).

> The Resource `uri` becomes the JWT `aud` claim byte-for-byte. It must
> match the URL your MCP server actually serves (path included). Mismatches
> cause an opaque `invalid_token` from the resource server. See
> [Connect an MCP Server § What can go wrong](../guides/integrate/connect-mcp-server.md#what-can-go-wrong)
> for the canonical-form rule.

Or via the admin API:

```bash
curl -X POST http://localhost:9001/admin/resources \
  -H "Authorization: Bearer $AUTHPLANE_ADMIN_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "slug": "my-mcp-server",
    "display_name": "My MCP server",
    "uri": "http://localhost:8080/mcp",
    "backend_kind": "mint",
    "scopes": [
      {"name": "mcp:echo", "description": "Echo a message"},
      {"name": "mcp:add",  "description": "Add two numbers"}
    ]
  }'
```

## 6. Access the Admin UI

Open `http://localhost:9001/admin/ui/` in your browser. Paste the value of `$AUTHPLANE_ADMIN_API_KEY` (from step 2) to log in. The dashboard shows server stats, registered clients, users, and scopes. You can manage all administrative operations from the web UI instead of using curl commands.

## 7. Verify it works

```bash
curl -s http://localhost:9000/.well-known/oauth-authorization-server | jq .
```

The response is the OAuth 2.0 Authorization Server Metadata (RFC 8414). Spot-check three things:

- `issuer` matches `http://localhost:9000`.
- `grant_types_supported` contains `client_credentials` and `urn:ietf:params:oauth:grant-type:token-exchange` — proof that the grant enables in `config.yaml` took effect. If you only see `["authorization_code", "refresh_token"]`, the flags didn't apply: re-check `client_credentials.enabled` and `token_exchange.enabled` and restart the container.
- `scopes_supported` contains the scopes you declared on the resource (`mcp:echo`, `mcp:add`).

```bash
curl -s http://localhost:9000/.well-known/oauth-authorization-server \
  | jq '{issuer, grant_types_supported, scopes_supported}'
```

## 8. Connect an MCP server

See the [examples/](../../examples/) directory for complete working examples:

- **[Go MCP server](../../examples/go/01-mcp-server-basic/)** — Minimal Go server using the Resource Server SDK
- **[Go agent](../../examples/go/02-agent-basic/)** — Client credentials, DPoP, introspection using the Auth SDK
- **[TypeScript MCP server](../../examples/typescript/01-mcp-server-basic/)** — Express server using the TypeScript Resource Server SDK
- **[Python MCP server](../../examples/python/01-mcp-server-basic/)** — FastMCP server using `authplane-fastmcp` (Python 3.12+)
- **[Tier-03 Go DPoP + scopes](../../examples/go/03-mcp-server-dpop-scopes/)** — Full-featured DPoP-bound, scope-enforcing example

Each example includes setup instructions. The Docker Compose examples start authserver alongside the MCP server.

## Before production

The default config is for local development. Before deploying to production:

1. **Set the issuer URL** to your public HTTPS URL (`server.issuer: https://auth.example.com`)
2. **Set a session secret** (`session.secret` or `AUTHPLANE_SESSION_SECRET` env var)
3. **Set an admin API key** (`admin.api_key` or `AUTHPLANE_ADMIN_API_KEY` env var)
4. **Enable secure cookies** (`session.secure: true` — enforced automatically for non-localhost issuers)
5. **Consider PostgreSQL** for multi-instance deployments (`storage.driver: postgres`)

See [../guides/deploy/configuration.md](../guides/deploy/configuration.md) for operator-facing configuration prose, and [../reference/configuration.md](../reference/configuration.md) for the field-by-field schema.

## What's next

- [03 — Your first MCP server](03-your-first-mcp-server.md) — drop in the Resource Server SDK
- [04 — Calling another resource from your MCP server](04-call-another-resource.md) — your MCP server acting as a client of a second resource
- [Admin UI tour](../guides/operate/admin-ui-tour.md) — manage clients, users, scopes from the web dashboard
- [Admin CLI & API](../guides/operate/admin-cli.md) — scripted management for CI/CD and automation
- [Connect an MCP server](../guides/integrate/connect-mcp-server.md) — point your MCP server at authserver
- [Configuration reference](../reference/configuration.md) — all config options with defaults
- [OIDC federation](../guides/federation/oidc.md) — connect to Okta, Entra ID, or Google Workspace
- [Deployment guide](../guides/deploy/docker-compose.md) — production Docker Compose setup
- [Architecture overview](../concepts/architecture.md) — how authserver works internally
- [Upstream Connections guide](../guides/upstream-providers/connecting-providers.md) — connect upstream OAuth providers (GitHub, Slack, etc.) and vend tokens via RFC 8693 token exchange
- SDKs — Go ([go-sdk](https://github.com/authplane/go-sdk)), TypeScript ([ts-sdk](https://github.com/authplane/ts-sdk)), Python ([python-sdk](https://github.com/authplane/python-sdk))
