# MCP Client Compatibility Matrix

> How Authplane behaves with real MCP clients.

---

## Verified end to end

Each row is one real run against a released or release-candidate authserver: a `docker run` of the image, an MCP server built on the Authplane SDK, and the client driven through the whole flow by hand, ending in a successful `tools/call`. Only what was observed is recorded — a client is credited with *sending* a parameter, never with *validating* one.

| Client | Client version | Registration | Callback | Auth flow observed | Tool call | authserver | Date |
|---|---|---|---|---|---|---|---|
| Claude Desktop | 1.46388.4 (custom connector) | **CIMD** — `https://claude.ai/oauth/mcp-oauth-client-metadata` (`client_name: Claude`; declares `jwt-bearer` among its grant types) | hosted: `https://claude.ai/api/mcp/auth_callback` | 401 `resource_metadata` → PRM → RFC 8414 → CIMD fetch → login → consent → code → token; a second authorize seconds later completed silently on the existing session and decision. MCP server and AS on different public origins (tunnelled) | `echo` OK | 0.2.0 | 2026-09-15 |
| Claude Code | 2.1.270 | **CIMD** — `https://claude.ai/oauth/claude-code-client-metadata` | loopback, ephemeral port; document lists `http://localhost/callback` (RFC 8252 §7.3 match) | 401 → PRM → RFC 8414 → CIMD fetch → authorize with `scope` and `resource`, PKCE S256 → login → consent → code → token; a later `claude -p` run reused the stored token with no AS traffic | `echo` OK ×2 | 0.2.0 | 2026-09-15 |
| MCP Inspector | 2.6.0 (MCP TS SDK 1.30.0) | DCR, public (`token_endpoint_auth_method: none`) | `http://localhost:6274/oauth/callback` | 401 → PRM → RFC 8414 → DCR → PKCE S256 → login → consent → code → token → `initialize` → `notifications/initialized` → `tools/list`; refresh rotation observed | `echo` OK ×2 | 0.2.0 | 2026-09-15 |
| MCP Inspector | 0.14.x | DCR | — | automated: `e2e/scenarios/mcp_inspector_test.go` | — | every CI run | — |

Not exercised on 0.2.0, stated so they are not mistaken for verified:

- **MCP Inspector, CIMD mode** — 2.6.0 implements it behind an *Enable CIMD* toggle plus an HTTPS client-metadata URL with a non-root path (the identifier rule this server enforces). It needs a publicly hosted document naming Inspector's callback; none was available.
- **Claude Desktop / claude.ai, `jwt-bearer`** — the connector's document declares the Enterprise-Managed Authorization grant; whether it exercises it against `authorization_grant_profiles_supported` was not tested.
- **VS Code (Copilot Chat)** — not tested.

## Quick Reference

| Client | Version Tested | Status | Registration | PKCE | Refresh | Notes |
|--------|---------------|--------|--------------|------|---------|-------|
| Claude Desktop | 1.46388.4 — manual, authserver 0.2.0 | Verified | **CIMD** (`mcp-oauth-client-metadata`), hosted callback | S256 | — | See the table above |
| Claude Code | 2.1.270 — manual, authserver 0.2.0 | Verified | **CIMD** (`claude-code-client-metadata`), loopback callback | S256 | Rotation | Sends `scope` and `resource`; the 1.x known issues below no longer apply |
| MCP Inspector | 2.6.0 — manual, authserver 0.2.0; 0.14.x — automated | Verified | DCR, public (`none`); CIMD mode not exercised | S256 | Rotation | Full flow through `tools/call` |
| VS Code (Copilot Chat) | — | Pending | — | — | — | Requires manual validation |

**Status key:**
- **Automated** — covered by `e2e/scenarios/mcp_inspector_test.go`
- **Verified** — walked end to end by hand against a running authserver (version noted), or covered by automation
- **Known bugs** — works with documented workarounds (see `oauth.require_scope`)
- **Pending** — requires manual validation against running instance

---

## Compatibility Scenarios

### C.1: Metadata Discovery

| Client | AS Metadata | PRM | Notes |
|--------|-------------|-----|-------|
| MCP Inspector | `TestMCPInspector_MetadataDiscovery` | `TestMCPInspector_MetadataDiscovery` | Full shape verified |
| Claude Code 2.1.270 | Verified (manual) | Verified (manual) | Follows the 401 `resource_metadata` challenge to the PRM, then RFC 8414 |
| Claude Desktop 1.46388.4 | Verified (manual) | Verified (manual) | Same chain, from Anthropic's side, across two public origins |
| VS Code | Pending | Pending | — |

### C.2: Dynamic Client Registration

| Client | DCR Payload | Status | Notes |
|--------|-------------|--------|-------|
| MCP Inspector | `redirect_uris`, `token_endpoint_auth_method=none` | `TestMCPInspector_DCR` | No scope in DCR request |
| Claude Code 2.1.270 | Does not use DCR — registers via CIMD; the AS fetches its metadata document (`client_name: Claude Code`, `token_endpoint_auth_method: none`, loopback `redirect_uris`) | Verified (manual) | Its document lists `http://localhost/callback` without a port; the AS matches the ephemeral-port redirect per RFC 8252 §7.3 |
| Claude Code 1.x | Omitted `scope` from DCR (#4540) | Handled | Historical; `oauth.require_scope: false` supplied a default scope at authorize time |
| VS Code | Pending | Pending | — |

### C.3: PKCE (S256)

| Client | Challenge Method | Status | Notes |
|--------|-----------------|--------|-------|
| MCP Inspector | S256 | `TestMCPInspector_PKCEFlow` | plain rejected |
| Claude Code 2.1.270 | S256 | Verified (manual) | Standard PKCE |
| VS Code | Pending | Pending | — |

### C.4: Authorization (Scope Handling)

| Client | Scope Behavior | Status | Notes |
|--------|---------------|--------|-------|
| MCP Inspector | Sends scope | Works | Standard flow |
| Claude Code 2.1.270 | Sends `scope` and `resource` | Verified (manual) | `scope=mcp:echo&resource=http://localhost:8080/mcp` observed on the authorize request |
| Claude Code 1.x | Omitted scope (#12077) | `require_scope: false` | Historical; defaulted to all registered scopes |
| VS Code | Pending | Pending | — |

### C.5: Token Exchange

| Client | Status | Notes |
|--------|--------|-------|
| MCP Inspector | `TestMCPInspector_TokenExchange` | JWT claims verified |
| Claude Code | Expected to work | Standard code exchange |
| VS Code | Pending | — |

### C.6: Token Refresh

| Client | Status | Notes |
|--------|--------|-------|
| MCP Inspector | `TestMCPInspector_TokenRefresh` | Rotation verified |
| Claude Code | Omits offline_access (#7744) | Refresh still issued (no offline_access enforcement) |
| VS Code | Pending | — |

### C.7: Tool Calls (Bearer Token)

| Client | Status | Notes |
|--------|--------|-------|
| MCP Inspector | `TestMCPInspector_ListTools` | Bearer auth, 401 without token |
| Claude Code 2.1.270 | Verified (manual) | `tools/call` succeeded with the issued bearer; a second `claude -p` run reused the stored token with no AS traffic |
| VS Code | Pending | — |

### C.8–C.10: Manual Client Tests

These scenarios require a running Authplane instance with a real MCP server:

- **C.8: Claude Code end-to-end** — Done against authserver 0.2.0 with Claude Code 2.1.270: `claude mcp add --transport http`, `/mcp` → Authenticate (CIMD registration, login, consent), then `claude -p` calling the `echo` tool. Re-run on each release.
- **C.9: VS Code end-to-end** — Connect VS Code Copilot Chat to Authplane-protected MCP server.
- **C.10: MCP Inspector CLI** — Use `npx @modelcontextprotocol/inspector --cli` with pre-obtained bearer token.

Status: Requires manual validation against a deployment.

---

## Known Issues

The Claude Code items below were observed on 1.x. Claude Code 2.1.270 registers via CIMD and sends `scope` and `resource` on the authorize request, so none of them applies to it; they are kept for deployments still seeing 1.x clients.

### Claude Code: Scope absent from authorize request

**Bug:** anthropics/claude-code#12077
**Impact:** Claude Code omits `scope` from the `/oauth/authorize` URL. Without a workaround, the AS issues a zero-scope token, causing 403 on every tool call.
**Workaround:** Set `oauth.require_scope: false` in config.yaml (or `AUTHPLANE_OAUTH_REQUIRE_SCOPE=false`). Authplane then substitutes all registered scopes for the resource when scope is absent — one of the two responses RFC 6749 §3.3 permits. A warning log is emitted for operator visibility.
**Test:** `TestAuthorize_MissingScope_DefaultScopes` (integration), `TestAuthorize_RequireScope_*` (unit + HTTP).

### Claude Code: Scope absent from DCR

**Bug:** anthropics/claude-code#4540
**Impact:** Claude Code omits `scope` from the DCR request body. This is harmless — Authplane does not enforce scope at registration time; scope enforcement happens at authorize/token time.
**Workaround:** None needed. DCR accepts requests without scope.

### Claude Code: offline_access not requested

**Bug:** anthropics/claude-code#7744
**Impact:** Claude Code does not include `offline_access` in scope. Authplane issues refresh tokens regardless (all authorization_code grants get a refresh token), so this has no practical impact.
**Workaround:** None needed.

### Claude Code: Resource absent from authorize request

**Bug:** anthropics/claude-code#10572
**Impact:** Claude Code omits `resource` from the authorize URL. When resource is absent, Authplane defaults scope to ALL registered scopes (not just those for a specific resource). The token's `aud` claim will be empty.
**Workaround:** `oauth.require_scope: false` handles scope defaulting. Resource binding is optional per RFC 8707.
**Test:** `TestAuthorize_MissingScope_DefaultScopes/no_scope_no_resource` (integration).

---

## Configuration

### Minimal config.yaml for MCP Inspector

```yaml
server:
  host: 0.0.0.0
  port: 8080

storage:
  driver: sqlite
  sqlite:
    path: ./data/authserver.db

oauth:
  issuer: http://localhost:8080

dcr:
  mode: open

resources:
  - name: my-mcp-server
    uri: http://localhost:3000
    scopes:
      - mcp:echo
      - mcp:db_query
```

### Minimal config.yaml for Claude Code

Claude Code omits `scope` from authorize requests. Set `oauth.require_scope: false` to enable default scope substitution:

```yaml
server:
  host: 0.0.0.0
  port: 8080

storage:
  driver: sqlite
  sqlite:
    path: ./data/authserver.db

oauth:
  require_scope: false  # default scope for clients that omit it (e.g., Claude Code)

dcr:
  mode: open

resources:
  - name: my-mcp-server
    uri: http://localhost:3000
    scopes:
      - mcp:echo
      - mcp:db_query
```

Or via environment variable: `AUTHPLANE_OAUTH_REQUIRE_SCOPE=false`.

---

## Adding a New Client

1. Open an issue using the [MCP Compatibility template](../../.github/ISSUE_TEMPLATE/mcp-compatibility.md).
2. Document which scenarios (C.1–C.10) pass/fail.
3. If automated tests are feasible, add them to `e2e/scenarios/`.
4. Update this matrix.
