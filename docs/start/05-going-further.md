# 05 — Going further

You have an MCP server and an agent talking through Authplane. From
here the path depends on what you are building.

## Add DPoP + scope enforcement (tier-03)

DPoP (RFC 9449) sender-binds an access token to a key the agent holds,
so a stolen token cannot be replayed. The tier-03 examples wire it end to
end, including scope-based authorization on each tool:

- **Go** -> [`examples/go/03-mcp-server-dpop-scopes/`](../../examples/go/03-mcp-server-dpop-scopes/)
- **TypeScript** -> [`examples/typescript/03-mcp-server-fastmcp-dpop/`](../../examples/typescript/03-mcp-server-fastmcp-dpop/)
- **Python** -> [`examples/python/03-mcp-server-dpop-scopes/`](../../examples/python/03-mcp-server-dpop-scopes/)

Concept reading: [DPoP and proof of possession](../concepts/dpop-and-proof-of-possession.md).

## Pick a production topology

There is more than one way to wire Authplane into your stack. The
[Topology reference](../topologies/) walks every named shape with
component diagrams and wire-level flows. The most common starting points:

- [Single MCP](../topologies/single-mcp.md) — one Authplane next to one MCP server.
- [MCP gateway -> Mint](../topologies/mcp-gateway-mint.md) — many MCP
  servers behind a gateway, Authplane mints all tokens.
- [MCP gateway -> Broker](../topologies/mcp-gateway-broker.md) — many
  MCP servers, Authplane brokers upstream provider tokens.
- [Enterprise XAA](../topologies/enterprise-xaa.md) — your corporate IdP
  drives identity, Authplane mints MCP tokens.

If you are unsure, start at [the topology index](../topologies/).

## Then read the guide for your stack

- [Connect an MCP server](../guides/integrate/connect-mcp-server.md)
- [Upstream OAuth providers](../guides/upstream-providers/) (GitHub, Slack, Notion, ...)
- [Federation](../guides/federation/) (Okta, Entra ID, Google Workspace, XAA)
- [Deploy](../guides/deploy/) (Docker Compose, Helm, systemd, Vault Transit)
- [Operate](../guides/operate/) (admin CLI, admin UI, key rotation)

## Reference (when you need exact field names)

- [HTTP API](../reference/http-api.md) — every endpoint + DTO
- [CLI](../reference/cli.md) — every `authserver` command and flag
- [Configuration](../reference/configuration.md) — every YAML key
- [Env vars](../reference/env-vars.md) — every `AUTHPLANE_*` variable
