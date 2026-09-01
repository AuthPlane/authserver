# Guides — Integrate

**Audience:** Builders wiring Authplane into a working MCP server or agent.
**You will leave with:** Tokens flowing end-to-end between an OAuth client, Authplane, and an MCP server.

## Prereqs

- A running authserver instance. If you don't have one, follow the [deploy guides](../deploy/) or run the `examples/` Docker Compose stack.
- Concept context: skim [What is Authplane?](../../concepts/what-is-authplane.md), [Resources & scopes](../../concepts/resources-and-scopes.md), and the [Glossary](../../concepts/glossary.md) before you start. Every recipe in this folder assumes you know what [Mint](../../concepts/glossary.md#glossary-mint-backend) vs. [Broker](../../concepts/glossary.md#glossary-broker-backend) means.
- Tools — pick the row that matches what you're doing:

  | Path | What you need |
  | --- | --- |
  | Run only the Docker examples | Docker, `curl`, `jq` |
  | Build / run SDK examples locally | Docker, `curl`, `jq`, plus the language toolchain — **Go 1.25+** (examples target `go 1.25.0`), **Node.js 22+** (TS SDKs are ESM-only), **Python 3.12+** (`authplane` requires `>=3.12`) |
  | Build authserver from source | Go 1.26.6+ (matches `go.mod`), Node.js 22+ for the admin UI, Docker for integration tests — see [contribute/running-tests.md](../../contribute/running-tests.md) for the full matrix |

  Plus the `authserver` CLI for admin operations regardless of lane.

## Shared setup

Every snippet below uses the same defaults — substitute your deployment's values.

| Variable | Default | What it is |
|---|---|---|
| Issuer URL | `http://localhost:9000` | Public OAuth server. Tokens, JWKS, well-knowns. |
| Admin URL | `http://localhost:9001` | Admin API. Resource / client / grant management. |
| `AUTHPLANE_ADMIN_API_KEY` | `dev-admin-key-localhost-only` | Bearer for `Authorization` on admin endpoints. Set this in your shell before running any admin command. |

Reference: [`docs/reference/cli.md`](../../reference/cli.md) for CLI commands, [`docs/reference/http-api.md`](../../reference/http-api.md) for wire shapes, [`docs/reference/env-vars.md`](../../reference/env-vars.md) for env vars.

## Reading order

1. **[Connect an MCP server](connect-mcp-server.md)** — the grounding recipe. Register a [Resource](../../concepts/glossary.md#glossary-resource), publish [Protected Resource Metadata](../../concepts/glossary.md#glossary-protected-resource-metadata), validate JWTs on your endpoint. Start here.
2. **[Run the AS standalone and point it at your own MCP server](standalone-as-by-hand.md)** — boot the AS with one `docker run`, then provision a Resource + Client, mint a token, and call your server entirely by hand with `curl`. The prose version of every example's `verify.sh`, for the case where the server is *yours*, not the example's.
3. **[Resource Server SDK](sdk-resource-server.md)** — drop-in JWT validation middleware in Go, TypeScript, Python.
4. **[Auth Client SDK](sdk-auth-client.md)** — outbound side: have your agent mint client-credentials tokens, attach DPoP, exchange for delegated tokens.
5. **[Client Credentials grant](client-credentials-grant.md)** — operator + builder recipe for machine-to-machine: register a confidential client, mint a token, hand it to an MCP server.
6. **[Runtime client binding](runtime-client-binding.md)** — operator recipe for `policy.runtime.client_ids`. Authorize specific `client_id`s to act AS a Resource.
7. **[Debugging 401s](debugging-401s.md)** — decision tree for the four common causes when an authenticated MCP request comes back 401.

## Conventions

- Every command in these recipes carries a `# Command verified against …` comment pointing to the generated reference. If a command works for you but the comment is stale, file an issue.
- Every recipe ends with **What can go wrong** — read it before you start, not after.
- Working code for each language lives under [`examples/`](../../../examples/). Each recipe links to the relevant tier.

## Related

- [Concepts → Tokens & claims](../../concepts/tokens-and-claims.md)
- [Concepts → DPoP](../../concepts/dpop-and-proof-of-possession.md)
- [Operate → Admin CLI & API](../operate/admin-cli.md)
