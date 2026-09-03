# Authplane

[![CI](https://github.com/AuthPlane/authserver/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/AuthPlane/authserver/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/AuthPlane/authserver?include_prereleases&sort=semver)](https://github.com/AuthPlane/authserver/releases)
[![License: AGPL-3.0](https://img.shields.io/badge/license-AGPL--3.0-blue.svg)](LICENSE)
[![Go Version](https://img.shields.io/github/go-mod/go-version/AuthPlane/authserver)](go.mod)

### The self-hosted authorization server for the Model Context Protocol.

One Go binary. AGPL-3.0. MCP Authorization spec **2025-11-25**, end-to-end.

> **AI coding agents:** read [AGENTS.md](AGENTS.md) first — it has the deterministic workflow for adding Authplane to an existing MCP server, the SDK pins per stack, and the three byte-for-byte rules that cause >90% of `invalid_token` failures. If you're an agent operating from web docs (no clone), [llms.txt](llms.txt) is the same link map in the [llmstxt.org](https://llmstxt.org/) convention.

## Why Authplane

Building an MCP server is now a one-afternoon job. Securing it isn't. You need to issue tokens, validate them, federate to your existing IdP, and let agents act on each other's behalf without losing the user behind the chain. Authplane is the one piece of infrastructure that answers all of that.

- **Spec-compliant access tokens** for any MCP server in any language — discovery, scopes, audience binding, refresh rotation, in token formats your existing resource servers already understand.
- **Federation to your existing IdP** — Google, Okta, Azure AD, Auth0, anyone OIDC-compliant. Authplane handles the OAuth side; you keep the access policy.
- **Agent-to-agent delegation** — one agent calls another on a user's behalf, with every hop recorded as an act-claim chain in the issued token and the audit log.
- **Upstream provider vaulting** — store GitHub / Google / Slack / Linear refresh tokens encrypted at rest and vend fresh access tokens via RFC 8693, with per-user / per-agent / per-resource consent enforced at every hop.
- **DPoP proof-of-possession** — bind tokens to a client-held key so a leaked token can't be replayed from another machine.
- **Built-in Admin UI** — React dashboard embedded in the same binary. No separate frontend, no extra container.
- **Production storage and observability** — PostgreSQL with cross-instance LISTEN/NOTIFY, OpenTelemetry traces and metrics, Prometheus, Helm chart, Vault Transit for HSM-grade signing.
- **Zero-config dev** — default SQLite, auto-generated signing keys, sensible defaults.

(Full RFC inventory at the bottom — [Standards & Specifications](#standards--specifications).)

## Quick Start

**One `docker run`. A working OAuth 2.1 + MCP authorization server in under a minute.**

```bash
export AUTHPLANE_ADMIN_API_KEY="$(openssl rand -hex 32)"
export AUTHPLANE_SESSION_SECRET="$(openssl rand -hex 32)"
echo "Save this — it's your Admin UI login: $AUTHPLANE_ADMIN_API_KEY"

docker run -p 9000:9000 -p 9001:9001 \
  -e AUTHPLANE_ADMIN_API_KEY \
  -e AUTHPLANE_SESSION_SECRET \
  -e AUTHPLANE_CLIENT_CREDENTIALS_ENABLED=true \
  -e AUTHPLANE_DPOP_ENABLED=true \
  -e AUTHPLANE_TOKEN_EXCHANGE_ENABLED=true \
  -v authserver-data:/data \
  authplane/authserver:latest serve
```

Open http://localhost:9001/admin/ui/ and paste the printed API key. The public OAuth endpoints are on http://localhost:9000.

### Next: register your first MCP server

- **Writing an MCP server from scratch?** Start at the runnable example for your language — [Python](examples/python/01-mcp-server-basic/) · [TypeScript](examples/typescript/01-mcp-server-basic/) · [Go](examples/go/01-mcp-server-basic/). Auth in 5 lines, end-to-end smoke in `make verify`.
- **Adding auth to an MCP server you already have?** The retrofit example is a runnable before/after pair — same three tools in two versions, side-by-side, with a smoke-test that proves `before` accepts anything and `after` enforces auth. [Python](examples/python/retrofit-existing-mcp-server/) · [TypeScript](examples/typescript/retrofit-existing-mcp-server/) · [Go](examples/go/retrofit-existing-mcp-server/). Or read the [**Connect an MCP Server** guide](docs/guides/integrate/connect-mcp-server.md) for the prose version.
- **Already have an MCP server running elsewhere?** To point this AS at *your* server and drive the whole OAuth flow by hand with `curl` — no SDK, no compose — see [Run the AS standalone and point it at your own MCP server](docs/guides/integrate/standalone-as-by-hand.md). It also reconciles this Quick Start's config with the `examples/` `.env` style.
- **Operator quickstart** (upstream providers, PostgreSQL, OIDC federation, Helm, multi-instance): [`docs/README.md`](docs/README.md).
- **Building from source**: [CONTRIBUTING.md](CONTRIBUTING.md).

## The Admin UI

![Authplane Admin UI](docs/images/admin-ui.webp)

Manage everything from a browser. The Admin UI is embedded in the same binary; every operation is also exposed via the [Admin REST API](docs/reference/http-api.md).

## SDKs

**Authserver is only half the story.** The MCP server on the other side still has to validate the tokens, expose the discovery endpoint, enforce scopes per tool, handle DPoP, and decode consent errors. The Authplane SDKs do all of that in **5 lines** of integration code — measured, CI-counted, in Python / TypeScript / Go alike. The full ladder (basic MCP server → calling another resource → DPoP + per-tool scopes → fronting a Broker upstream) sits between **5 and 30 lines** of auth-specific code per tier; see [`examples/`](examples/) for the numbers under each tier's banner.

Every Authplane SDK provides the same baseline:

- JWT validation against the authserver JWKS, with caching
- Scope enforcement, per route or per tool
- The Protected Resource Metadata document at `/.well-known/oauth-protected-resource/<mcp-path>` (RFC 9728, suffixed per the MCP spec)
- DPoP proof verification (RFC 9449)
- A full OAuth client — Client Credentials, RFC 8693 Token Exchange, Introspection, Revocation
- Structured `ConsentRequiredError` decoding for the upstream-provider Broker flow

Pick the language and the framework adapter that match the stack you're already on.

| Language | Repo | Integration Adapters | Docs |
|---|---|---|---|
| **Go** | [authplane/go-sdk](https://github.com/authplane/go-sdk)<br>![License](https://img.shields.io/github/license/authplane/go-sdk) | ✓ Official MCP Go SDK (`go-sdk/mcp`) | [README](https://github.com/authplane/go-sdk#readme) |
| **TypeScript** | [authplane/ts-sdk](https://github.com/authplane/ts-sdk)<br>![License](https://img.shields.io/github/license/authplane/ts-sdk) | ✓ Official MCP TypeScript SDK (`@authplane/mcp`)<br>✓ FastMCP (`@authplane/fastmcp`) | [README](https://github.com/authplane/ts-sdk#readme) |
| **Python** | [authplane/python-sdk](https://github.com/authplane/python-sdk)<br>![License](https://img.shields.io/github/license/authplane/python-sdk) | ✓ Official MCP Python SDK (`authplane-mcp`)<br>✓ FastMCP (`authplane-fastmcp`) | [README](https://github.com/authplane/python-sdk#readme) |
| **Rust** | _roadmap_ | — | — |
| **C#** | _roadmap_ | — | — |
| **Java** | _roadmap_ | — | — |

Working examples wired against authserver live under [`examples/`](examples/) — Python / TypeScript / Go, with four tiers each (basic MCP server, calling another resource, DPoP + per-tool scopes, MCP server fronting a Broker). Every example's `make verify` is exercised by `make docs-smoke` and the per-tier LOC budget is CI-enforced via `tools/loccount`.

Integration walkthroughs: [Auth Client](docs/guides/integrate/sdk-auth-client.md) · [Resource Server](docs/guides/integrate/sdk-resource-server.md).

## Documentation

For advanced operations and deeper reference, the [`docs/`](docs/) tree is organized by audience:

| | |
|---|---|
| **Get started** | [Quickstart](docs/README.md) |
| **Configuration** | [Configuration Guide](docs/guides/deploy/configuration.md) · [Schema Reference](docs/reference/configuration.md) |
| **API Reference** | [HTTP API (all endpoints)](docs/reference/http-api.md) · [CLI](docs/reference/cli.md) · [Audit Events](docs/reference/audit-events.md) · [Metrics](docs/reference/metrics.md) |
| **Security** | [Threat Model](docs/concepts/threat-model.md) · [Tokens and Claims](docs/concepts/tokens-and-claims.md) · [Key Rotation](docs/guides/operate/key-rotation.md) · [DPoP](docs/concepts/dpop-and-proof-of-possession.md) |
| **Deployment** | [Docker Compose](docs/guides/deploy/docker-compose.md) · [systemd](docs/guides/deploy/systemd.md) · [Kubernetes](docs/guides/deploy/kubernetes.md) |
| **Guides** | [Connect an MCP Server](docs/guides/integrate/connect-mcp-server.md) · [Admin CLI & API](docs/guides/operate/admin-cli.md) · [OIDC Federation](docs/guides/federation/oidc.md) · [Observability](docs/guides/deploy/observability-prometheus-otel.md) |
| **Grant Types** | [Client Credentials](docs/guides/integrate/client-credentials-grant.md) · [Token Exchange](docs/guides/upstream-providers/token-exchange-grant.md) · [JWT Bearer / XAA](docs/guides/federation/jwt-bearer-grant.md) · [Enterprise-Managed Auth](docs/guides/federation/enterprise-managed-auth-xaa.md) |
| **Architecture** | [Architecture Overview](docs/concepts/architecture.md) · [Authentication Flows](docs/reference/flows.md) · [RFC Compliance](docs/reference/compliance.md) |
| **Full Index** | [Documentation Index](docs/README.md) |

## Standards & Specifications

Authplane implements the MCP Authorization specification (2025-11-25) and the OAuth 2.1 ecosystem standards behind it. ("OAuth 2.1" is an active IETF Internet-Draft, not a finalized RFC — the MCP spec itself targets it. See [Compliance](docs/reference/compliance.md) for the full picture.) Here's what each one gives you, in operator terms:

| Standard | What it provides |
|---|---|
| **MCP Authorization 2025-11-25** | The contract MCP clients and servers expect: discovery endpoints, dynamic client registration, audience-bound tokens. The reason your existing MCP tooling can find and talk to authserver without custom adapters. |
| **OAuth 2.1** | The base authorization flow — authorize endpoint, token endpoint, refresh tokens, scopes. PKCE-S256 is mandatory; the older insecure flows aren't supported. |
| **PKCE (RFC 7636)** | Prevents stolen authorization codes from being redeemed. Critical for public clients (CLIs, desktop apps, mobile). |
| **DPoP (RFC 9449)** | Binds tokens to a client-held key. A leaked token can't be replayed from another machine. |
| **Resource Indicators (RFC 8707)** | Audience-binds every token to a specific resource URI. An access token for one MCP server can't be replayed against another. |
| **Protected Resource Metadata (RFC 9728)** | MCP servers advertise where their authorization server lives. Clients discover the AS automatically. |
| **Dynamic Client Registration (RFC 7591)** | Clients register themselves at runtime — needed for MCP clients you don't pre-provision. Three security modes: open, approved-redirects, admin-only. |
| **Client ID Metadata Documents (CIMD)** | Auto-registration by fetching client metadata from the client's URL. The MCP-native way for agents to identify themselves without a registration round-trip. |
| **OAuth AS Metadata (RFC 8414)** + **OIDC Discovery** | The `/.well-known/oauth-authorization-server` and `/.well-known/openid-configuration` documents every OAuth client knows how to fetch. |
| **Token Exchange (RFC 8693)** | Delegated identity — one client mints a narrower or differently-scoped token from an existing one. Powers the agent-to-agent delegation chain and the upstream-provider Broker flow. |
| **JWT Bearer (RFC 7523)** | Trusted external IdPs assert identity directly into Authplane. The foundation for Cross-App Access (XAA) and enterprise federation. |
| **JWT Access Tokens (RFC 9068)** | Default token format (`at+jwt`). Every token is a self-contained JWT your resource servers can verify offline against the JWKS. |
| **Token Introspection (RFC 7662)** | Runtime token validation endpoint for revocation-aware verification. |
| **Token Revocation (RFC 7009)** | Standard endpoint to revoke refresh tokens and their families. |

## Status & roadmap

Authplane is in active development. `v0.1.x` is production-shaped — the OAuth core, MCP discovery, and audit log are spec-compliant and tested. A few things to set expectations:

- **Rust, C#, and Java SDKs** are on the roadmap; Go, TypeScript, and Python are released.
- **Upstream-provider connections** (Broker flow) require manual configuration of at-rest encryption (`aes_master` or HashiCorp Vault Transit) before they activate — covered in [`docs/guides/upstream-providers/connecting-providers.md`](docs/guides/upstream-providers/connecting-providers.md).
- **Isolating separate customers or environments** today means running separate instances. A first-class abstraction for it is post-`v1.0`.
- **Public dynamic-registration signup UI** is not in `v0.1`; Dynamic Client Registration works over HTTP today, a hosted signup page is a follow-up.
- **Helm chart (`charts/authplane`)** is at `v0.3.0`; tested for single-instance and basic HA, expect tuning for large fleets.

If something here blocks your deployment, open an issue — the priority list is informed by what you're trying to ship.

## License

AGPL-3.0-or-later — see [LICENSE](LICENSE).

### Need a different licence?

We'd love to hear from you — write to [hello@authplane.ai](mailto:hello@authplane.ai) and let's find one that fits.
