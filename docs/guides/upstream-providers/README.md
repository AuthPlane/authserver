# Guides — Upstream providers

**For:** Builders and operators wiring Authplane so an MCP server can call a third-party API (GitHub, Google, Slack, Notion, Linear, Atlassian, …) on behalf of a user.

**You'll get:** A user connects their upstream account once; your MCP server then exchanges its caller's access token for a fresh upstream provider token via [RFC 8693 Token Exchange](../../concepts/glossary.md#glossary-token-exchange).

## Recipes in this section

| Recipe | When to use it |
|---|---|
| [Connecting upstream providers](connecting-providers.md) | First-time setup: register an upstream OAuth app, expose it through a [Broker resource](../../concepts/glossary.md#glossary-broker-backend), run the [Connect](../../concepts/glossary.md#glossary-consent) flow, vend tokens. Covers GitHub, Google, Slack, Notion, Linear, Atlassian, and any generic OAuth 2.0 upstream. |
| [Token Exchange grant](token-exchange-grant.md) | Operator-side configuration for the `urn:ietf:params:oauth:grant-type:token-exchange` wire flow that powers brokered vends and agent-to-agent delegation. |

> Per-provider one-pagers (`github.md`, `google.md`, …) are intentionally not split out yet. The generic recipe covers every provider with the same shape — the only per-provider variance is the OAuth-app URL, the redirect URI, the scope catalog, and (for Google) `extra_auth_params.access_type=offline`. We'll spin off per-provider pages once quirks accumulate enough to justify the maintenance cost.

## Prereqs (apply to every recipe)

- Authplane running with at-rest encryption configured — either `aes_master` or `vault_transit_encrypt`. Plaintext refresh-grants never persist. See [Deploy → Configuration](../deploy/configuration.md) and [Deploy → HashiCorp Vault Transit](../deploy/hashicorp-vault-transit.md).
- An OAuth app at the upstream provider (you'll create one in step 1 of [Connecting upstream providers](connecting-providers.md)).
- `AUTHPLANE_CONNECT_STATE_SECRET` set (HMAC key for state tokens — prevents CSRF in the Connect flow). See [`docs/reference/env-vars.md`](../../reference/env-vars.md).
- Token Exchange enabled — `token_exchange.enabled: true` in YAML or `AUTHPLANE_TOKEN_EXCHANGE_ENABLED=true`.
- Concept primers: [Broker vs Mint](../../concepts/broker-vs-mint.md), [Delegation and agent chains](../../concepts/delegation-and-agent-chains.md), [Threat model](../../concepts/threat-model.md).

## Conventions

- Every CLI verb (`authserver admin provider …`, `authserver admin resource …`, `authserver admin grant …`) is documented in [`docs/reference/cli.md`](../../reference/cli.md).
- Every admin REST route (`/admin/broker-providers`, `/admin/resources`, `/admin/grants/broker/…`) is documented in [`docs/reference/http-api.md`](../../reference/http-api.md).
- A working broker-upstream example lives at [`examples/typescript/04-broker-upstream/`](../../../examples/typescript/04-broker-upstream/) (Python and Go equivalents in the same `examples/` tree).

## Related

- [Topologies → Broker MCP](../../topologies/broker-mcp.md), [Topologies → Direct fan-out](../../topologies/direct-fanout.md) — wire-level diagrams.
- [Operate → Admin CLI & API](../operate/admin-cli.md) — for managing providers, resources, and grants after the initial setup.
