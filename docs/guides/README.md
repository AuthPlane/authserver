# Guides

**For:** Builders, Operators.
**Time:** ~5 min per recipe.
**Prereqs:** [Quickstart](../README.md). For concept-level background, see [Concepts](../concepts/).

Each subdirectory groups recipes by audience and goal:

| Section | For | Contents |
| --- | --- | --- |
| [integrate/](integrate/) | Builders | Wire Authplane into an existing MCP server or agent in your language. |
| [federation/](federation/) | Builders + Operators | Connect Authplane to upstream IdPs (Okta, Entra ID, Google Workspace) and XAA flows. |
| [upstream-providers/](upstream-providers/) | Builders | Store and vend third-party OAuth tokens (GitHub, Google, Slack, ...). |
| [deploy/](deploy/) | Operators | Get Authplane running in your environment (Docker, Helm, systemd, Vault Transit, Postgres-HA, observability). |
| [operate/](operate/) | Operators | Day-2 ops: admin CLI / UI, key rotation, audit & forensics, incident response. |

## Conventions across guides

- Every command-line example cites [`docs/reference/cli.md`](../reference/cli.md).
- Every curl example cites [`docs/reference/http-api.md`](../reference/http-api.md).
- Every env-var reference cites [`docs/reference/env-vars.md`](../reference/env-vars.md).
- Every YAML key reference cites [`docs/reference/configuration.md`](../reference/configuration.md).
- Runnable proofs live under [`examples/`](../../examples/).

## Related material

- [Concepts](../concepts/) — what Authplane is and why each piece exists.
- [Reference](../reference/) — generated specifications (HTTP API, CLI, env vars, config schema).
- [Topologies](../topologies/) — named deployment shapes (single MCP, gateway, fan-out, etc.) with end-to-end wiring.
- Grant-type guides — [client credentials](integrate/client-credentials-grant.md), [JWT bearer (XAA)](federation/jwt-bearer-grant.md), [token exchange](upstream-providers/token-exchange-grant.md).
