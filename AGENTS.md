# AGENTS.md — Agent Integration Guide

This file is read by AI coding agents (Claude Code, Cursor, Copilot, etc.) by convention. It documents how an agent should help a user integrate Authplane into the user's MCP server, agent, or operations workflow.

The 98% case: a user has an MCP server (or is writing one) and wants Authplane to handle auth. The 2% case: a contributor is changing authserver itself — for that, see [CONTRIBUTING.md](CONTRIBUTING.md) and [docs/contribute/](docs/contribute/).

## Hard rules

1. **Do not infer flag names, env-var names, DTO fields, or YAML keys from training data or older code samples.** They drift. The four generated reference files below are the only source of truth.
2. **Do not hand-edit `docs/reference/cli.md`, `http-api.md`, `env-vars.md`, or `configuration.md`** — they regenerate from source via `make docs-gen` (run from the authserver repo root). Hand edits fail CI.
3. **Use the published SDKs** (PyPI / npm / Go modules), not in-tree code. Sibling repos: [go-sdk](https://github.com/authplane/go-sdk), [ts-sdk](https://github.com/authplane/ts-sdk), [python-sdk](https://github.com/authplane/python-sdk).
4. **Three byte-for-byte rules** matter when wiring auth (and most opaque `invalid_token` errors trace to one of them):
   - **Issuer URLs**: the AS-side `AUTHPLANE_SERVER_ISSUER` and the SDK-side `AUTHPLANE_ISSUER` must resolve to the same hostname.
   - **Resource URI**: what you register at the AS, what you pass to the SDK, and what the MCP client reaches must match — scheme, host, port, path — exactly.
   - **Scope name**: the same string appears in four places (SDK `scopes:` array, `POST /admin/resources`, `POST /admin/clients`, `POST /oauth/token`). Pick once, use everywhere.

> **Issuer decision — get this right before anything else.** `AUTHPLANE_SERVER_ISSUER` is what the **AS announces** (the `iss` it stamps and the host in its discovery doc); `AUTHPLANE_ISSUER` is where the **SDK discovers** metadata and fetches JWKS. They must point at the *same* host, and which host depends on topology:
> - **MCP server in the same Docker network as the AS?** → `http://authserver:9000` (the compose service name) on **both**.
> - **MCP server on the host, another machine, or public?** → `http://localhost:9000` (or your real public hostname) on **both**.
>
> Get this wrong and every call fails `401` with an opaque `invalid_token` even though the token is valid — the SDK fetched metadata from one host while the JWT's `iss` says another. This is the silent trap behind most "I did everything right and it still 401s" reports.

## Authoritative references — consult before generating any example

When generating ANY `docker run`, `curl`, admin-API call, env-var list, YAML config, or example code, consult the relevant file:

| File | What it covers | Generated from |
|---|---|---|
| [`docs/reference/cli.md`](docs/reference/cli.md) | Every `authserver` subcommand, every flag, value-format quirks (e.g. `--scopes 'name\|upstream\|description'` double-pipe for Mint) | `cmd/authserver/*.go` cobra tree |
| [`docs/reference/http-api.md`](docs/reference/http-api.md) | Every public + admin HTTP endpoint, request/response DTO, auth model | `api/{public,admin}/**` + DTO struct tags |
| [`docs/reference/env-vars.md`](docs/reference/env-vars.md) | Every `AUTHPLANE_*` env var, default, when required | `internal/config/loader.go` |
| [`docs/reference/configuration.md`](docs/reference/configuration.md) | Every YAML config key, type, default | `internal/config/config.go` |

If a flag, env var, or field a user needs isn't in the generated reference, **the docs are wrong before the example is**. File an issue against authserver; don't make one up.

## SDK pin per stack

Tell the user to install one of these, **at the exact version shown**. Each adapter is published on the public registry (PyPI / npm / `proxy.golang.org`). The versions below are checked against those registries by `make sdkpin-check`, so they can't silently drift from the published release. If a newer version ships, the table *and* every example manifest must be reconciled together — don't infer a version from training data.

| Stack | Install (pinned) | Import / call |
|---|---|---|
| Python · FastMCP | `pip install authplane-fastmcp==0.3.0` | `from authplane_fastmcp import authplane_auth` |
| Python · official MCP Python SDK | `pip install authplane-mcp==0.3.0` | `from authplane_mcp import ...` |
| Python · any other framework (FastAPI, Starlette, raw ASGI) | `pip install authplane-sdk==0.3.0` | `from authplane import AuthplaneResource` |
| TypeScript · Express + `@modelcontextprotocol/sdk` | `npm i @authplane/mcp@0.3.0` | `import { authplaneMcpAuth } from "@authplane/mcp"` |
| TypeScript · FastMCP | `npm i @authplane/fastmcp@0.3.0` | `import { authplaneAuth } from "@authplane/fastmcp"` |
| TypeScript · any other framework | `npm i @authplane/sdk@0.3.0` | `import { AuthplaneResource } from "@authplane/sdk"` |
| Go · official MCP Go SDK | `go get github.com/authplane/go-sdk/mcp@v0.2.0` | `import "github.com/authplane/go-sdk/mcp/pkg/authplanemcp"` |
| Go · `net/http` resource server | `go get github.com/authplane/go-sdk/http@v0.2.0` | `import authhttp "github.com/authplane/go-sdk/http/pkg/auth"` |
| Go · raw token client (agent side) | `go get github.com/authplane/go-sdk/core@v0.2.0` | `import "github.com/authplane/go-sdk/core/authplane"` |

**Go: `go get .../mcp` (or `.../http`) is not enough on its own.** Both adapters import `github.com/authplane/go-sdk/core` transitively, and `go get` of the adapter alone does *not* record `core` in your `go.sum`. The next `go build` then fails with `missing go.sum entry for module providing package github.com/authplane/go-sdk/core/...`. Fix it by running **`go mod tidy`** immediately after `go get` (or `go get github.com/authplane/go-sdk/mcp/pkg/authplanemcp@v0.2.0` — naming the import path pulls its full transitive set). This is the one place "one package, exact version" doesn't hold: `core` rides along whether you name it or not.

Python users: SDK packages require **Python 3.12+** (`requires-python = ">=3.12"`).
TypeScript users: SDK packages are **ESM-only** and require **Node.js 22+**.

## Runnable examples to point users at

All examples are smoke-tested by CI (`make docs-smoke`). They default to the published `authplane/authserver:latest` image — no clone, no build.

| Scenario | Where |
|---|---|
| Writing a new MCP server with auth from day 1 | [`examples/python/01-mcp-server-basic/`](examples/python/01-mcp-server-basic/) · [`examples/typescript/01-mcp-server-basic/`](examples/typescript/01-mcp-server-basic/) · [`examples/go/01-mcp-server-basic/`](examples/go/01-mcp-server-basic/) |
| **Adding auth to an MCP server that already exists** (the 98% case) | [`examples/python/retrofit-existing-mcp-server/`](examples/python/retrofit-existing-mcp-server/) · [`examples/typescript/retrofit-existing-mcp-server/`](examples/typescript/retrofit-existing-mcp-server/) · [`examples/go/retrofit-existing-mcp-server/`](examples/go/retrofit-existing-mcp-server/) — before/after pair with smoke-test |
| MCP server that calls another protected resource | `02-agent-basic/` in each language |
| DPoP + per-tool scope enforcement | `03-mcp-server-{dpop-scopes,fastmcp-dpop}/` |
| MCP server fronting an upstream OAuth provider (Broker) | `04-broker-upstream/` |

For the LOC matrix and the full ladder, see [`examples/README.md`](examples/README.md).

## Three off-by-default grants

If the user wants client-credentials, DPoP, or token-exchange, the AS needs the matching env var set to `true` at startup. Easy to forget and the discovery endpoint silently omits the grant:

| Grant | Env var (set to `true`) |
|---|---|
| Client Credentials | `AUTHPLANE_CLIENT_CREDENTIALS_ENABLED` |
| DPoP sender-constrained tokens | `AUTHPLANE_DPOP_ENABLED` |
| Token Exchange (RFC 8693) | `AUTHPLANE_TOKEN_EXCHANGE_ENABLED` |

The AS listens on `:9000` (public OAuth) and `:9001` (Admin API + Admin UI at `/admin/ui/`). Implements MCP Authorization spec `2025-11-25`.

## Common user requests + where to route them

| User question | Doc |
|---|---|
| "Add auth to my MCP server" | The retrofit example for the user's language (table above) |
| "Run the AS by hand and point it at my own server" (no SDK, just `curl`) | [Run the AS standalone and point it at your own MCP server](docs/guides/integrate/standalone-as-by-hand.md) |
| "Why is my MCP server returning 401?" | [Debugging 401s](docs/guides/integrate/debugging-401s.md) |
| "What's the difference between Mint and Broker?" | [Broker vs Mint](docs/concepts/broker-vs-mint.md) |
| "How do I rotate signing keys?" | [Key rotation](docs/guides/operate/key-rotation.md) |
| "What is DPoP and do I need it?" | [DPoP and proof-of-possession](docs/concepts/dpop-and-proof-of-possession.md) |
| "How do I federate with Okta / Entra ID?" | [OIDC federation](docs/guides/federation/oidc.md) · [XAA with Okta](docs/guides/federation/xaa-with-okta.md) |
| "How do I store GitHub OAuth tokens on behalf of users?" | [Upstream providers](docs/guides/upstream-providers/) |
| "How do I implement agent-to-agent delegation?" | [Delegation and agent chains](docs/concepts/delegation-and-agent-chains.md) |
| "How do I deploy with Helm / Postgres / Vault?" | [Deploy guides](docs/guides/deploy/) |
| "How do I monitor with Prometheus / OTel?" | [Observability](docs/guides/deploy/observability-prometheus-otel.md) |
| "How do I back up the database?" | [Backup & purge](docs/guides/deploy/backup-and-purge.md) |
| "What's the threat model?" | [Threat model](docs/concepts/threat-model.md) |
| "What's the topology decision tree?" | [Topologies](docs/topologies/) |

## Default workflow — adding Authplane to an existing MCP server

This is the 98% case. Run these steps in order. Stop and consult the user only at decision points marked **ASK**.

1. **Detect the stack.** Inspect the user's server file(s) to identify:
   - Language (Go / Python / TypeScript)
   - MCP framework (e.g. `modelcontextprotocol/go-sdk`, FastMCP, official MCP TS SDK on Express, FastMCP for TS)
   - Transport (streamable-http expected; if SSE-only or stdio-only, **ASK** — the integration shape differs)
   - Port + mount path the server actually serves on (the Resource URI must match this byte-for-byte)

2. **Install the matching SDK pin** from the table in [§ SDK pin per stack](#sdk-pin-per-stack), at the exact version shown. One adapter package — don't pull in additional dependencies the example doesn't have. **Go caveat:** the `mcp` and `http` adapters drag in `go-sdk/core` transitively; run `go mod tidy` right after `go get` or the build fails on a missing `go.sum` entry (see the note under the SDK table).

3. **Open the matching retrofit example** ([§ Runnable examples](#runnable-examples-to-point-users-at)) and read `before/` next to `after/`. Your diff against the user's code should mirror the `before/`→`after/` diff in the example. Don't paraphrase — the 5-line auth-setup block is the contract.

4. **Wire three things in the user's server file:**
   - The 5-line auth-setup block at module load (between `// authplane:begin` / `// authplane:end` markers — the loccount tool reads these in the example, and they're useful as a self-documenting boundary in production code too)
   - A handler for the Protected Resource Metadata document at the SDK-provided well-known path (`adapter.WellKnownPRMPath()` / `auth.protectedResourceMetadataPath` / equivalent)
   - The bearer / auth middleware wrapping the MCP endpoint handler

   **Startup ordering matters:** because that block runs at module load, the SDK adapter does AS metadata discovery + JWKS fetch at import/construction (Python and TS especially) and **throws if the AS is unreachable at that moment**. Bring the AS up *before* the user's server, or wrap the adapter constructor in a bounded retry. (See the "throws at module load / startup" troubleshooting row below.)

5. **Wire `.env` (or your project's secret manager).** Three values: `AUTHPLANE_ISSUER` (where the SDK fetches metadata), `AUTHPLANE_RESOURCE` or `AUTHPLANE_BASE_URL` (the URI the verifier requires in JWT `aud` — Python derives `aud = base_url + mcp_path`; Go and TS take the full Resource URI), and any per-tool scope strings.

6. **Register the Resource at the AS.** `POST /admin/resources` (admin API, bearer = `AUTHPLANE_ADMIN_API_KEY`). The `uri` field must equal what you set in step 5, byte-for-byte. Include the scope catalog (`{name, description}` per scope).

7. **Register a Client at the AS.** `POST /admin/clients`. Grant types = whatever the caller will use (usually `client_credentials` for machine-to-machine, `authorization_code` for user-driven). Scope claim must include the strings from step 6.

8. **Verify end-to-end. ALL THREE must hold:**
   - Call the protected MCP endpoint **without** a bearer → expect `HTTP 401`
   - Mint a `client_credentials` token at `POST /oauth/token` (with `resource=` set to the Resource URI from step 6, and `scope=` set to a scope from the client's grant). Call the MCP endpoint with that bearer → expect `HTTP 200` and a real tool result, not just a session-establish handshake.
   - Mint a token for a **different** resource (or with a different scope than the tool requires) and call the same endpoint → expect `HTTP 401` (or `HTTP 403` for scope mismatch).

   The full curl sequence for the 3-step MCP handshake (`initialize` → `notifications/initialized` → `tools/call`) is at [`docs/reference/mcp-streamable-http.md`](docs/reference/mcp-streamable-http.md). For the complete by-hand runbook — `docker run` the AS, provision a Resource + Client, mint, and call your own server with `curl` end to end — see [Run the AS standalone and point it at your own MCP server](docs/guides/integrate/standalone-as-by-hand.md).

9. **Before declaring done, sweep the three byte-for-byte rules** ([§ Hard rules](#hard-rules)). Most opaque `invalid_token` errors trace to one of: issuer-URL mismatch, Resource-URI mismatch, scope-string drift across the four places it lives.

10. **Before production, flip the dev knobs.** `devMode: true` (or `DevMode: true` / `dev_mode=True` — varies by SDK) → off or removed. `http://` issuer → `https://`. Dev secrets → `openssl rand -hex 32`. `AUTHPLANE_SESSION_SECURE=true` if `server.issuer` is non-localhost.

**When the generated code fails:**

| Symptom | Most likely cause | First check |
|---|---|---|
| `invalid_token` on every call | Resource URI mismatch (step 5 ≠ step 6 ≠ step 8's `resource=` param) | Three places, byte-for-byte |
| 406 Not Acceptable on the MCP call | Missing `Accept: application/json, text/event-stream` header | The 3-step handshake doc |
| 401 even with what looks like a valid token | Issuer hostname mismatch (AS announces `http://X`, SDK fetches metadata at `http://Y`) | The two `AUTHPLANE_*ISSUER` env vars |
| `invalid_scope` or `insufficient_scope` | Scope string drift across the four places it appears | `Scopes:`, Resource registration, Client registration, `scope=` token param |
| `grant type not supported` | The grant is off by default; set the matching `AUTHPLANE_*_ENABLED=true` and restart the AS | [§ Three off-by-default grants](#three-off-by-default-grants) |
| SDK adapter throws at module load / startup | AS unreachable at metadata fetch time | Bring up the AS first, or wrap the adapter constructor in a bounded retry loop |
| Stale state on retry | A previous run left a Resource or Client with the same slug/name | Either `make distclean` in the example dir, or delete the conflicting record via admin API |
| Readiness probe "passes" but the run misbehaves | A leftover server/AS from a prior attempt is still bound to the port and answering the probe (even a valid-looking 401 looks "ready") — you're talking to the wrong process | `docker ps` + `lsof -i :9000 -i :9001 -i :8080 -i :8090`; kill strays (`docker ps -aq --filter name=authplane \| xargs -r docker rm -f`) before re-running. A bare port check is not proof *this* run's process answered. |

If verification step 8 doesn't pass cleanly, do not declare success and do not generate workarounds — go back to step 9 and check the byte-for-byte rules first.

## Documentation style

When writing comments, prose, or test names: prefer self-contained technical insight over references that require external context.

- ✅ State the rule inline: *Actor MCP is resolved via `Resource.policy.runtime.client_ids` list-membership, not by `slug == client_id` match.*
- ❌ Avoid bare "the spec" / "per spec". Either qualify (`per RFC 7523`, `per the OAuth 2.1 spec`, `per the MCP Authorization spec`) or state the rule directly — this file IS the spec for anyone reading the public repo.

Helm/K8s YAML `spec:` keyword and Go struct field names (`spec.Slug`) are fine.

## If you're contributing to authserver itself

You're not in the 98% case — you're modifying authserver's own code. See:

- [CONTRIBUTING.md](CONTRIBUTING.md) — architecture, dependency rules, PR gates, build commands.
- [docs/contribute/](docs/contribute/) — repo tour, hexagonal layers, recipes for adding a grant / upstream provider / storage adapter, release process, running-tests guide.
- The hard rules above still apply when generating examples in commits or PR descriptions.
