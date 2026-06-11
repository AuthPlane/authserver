# MCP Client Compatibility Matrix

> How Authplane behaves with real MCP clients.

---

## Quick Reference

| Client | Version Tested | Status | DCR | PKCE | Refresh | Notes |
|--------|---------------|--------|-----|------|---------|-------|
| MCP Inspector | 0.14.x | Automated | Public (none) | S256 | Rotation | E2E tests cover full flow |
| Claude Code | 1.x | Known bugs | Omits scope | S256 | Omits offline_access | See Known Issues below |
| VS Code (Copilot Chat) | — | Pending | — | — | — | Requires manual validation |

**Status key:**
- **Automated** — covered by `e2e/scenarios/mcp_inspector_test.go`
- **Known bugs** — works with documented workarounds (ADR-012)
- **Pending** — requires manual validation against running instance

---

## Compatibility Scenarios

### C.1: Metadata Discovery

| Client | AS Metadata | PRM | Notes |
|--------|-------------|-----|-------|
| MCP Inspector | `TestMCPInspector_MetadataDiscovery` | `TestMCPInspector_MetadataDiscovery` | Full shape verified |
| Claude Code | Expected to work | Expected to work | Uses standard discovery |
| VS Code | Pending | Pending | — |

### C.2: Dynamic Client Registration

| Client | DCR Payload | Status | Notes |
|--------|-------------|--------|-------|
| MCP Inspector | `redirect_uris`, `token_endpoint_auth_method=none` | `TestMCPInspector_DCR` | No scope in DCR request |
| Claude Code | Omits `scope` from DCR (#4540) | Handled | ADR-012 defaults scope at authorize time |
| VS Code | Pending | Pending | — |

### C.3: PKCE (S256)

| Client | Challenge Method | Status | Notes |
|--------|-----------------|--------|-------|
| MCP Inspector | S256 | `TestMCPInspector_PKCEFlow` | plain rejected |
| Claude Code | S256 | Expected to work | Standard PKCE |
| VS Code | Pending | Pending | — |

### C.4: Authorization (Scope Handling)

| Client | Scope Behavior | Status | Notes |
|--------|---------------|--------|-------|
| MCP Inspector | Sends scope | Works | Standard flow |
| Claude Code | Omits scope (#12077) | ADR-012 | Defaults to all registered scopes |
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
| Claude Code | Expected to work | Standard bearer |
| VS Code | Pending | — |

### C.8–C.10: Manual Client Tests

These scenarios require a running Authplane instance with a real MCP server:

- **C.8: Claude Code end-to-end** — Connect Claude Code to Authplane-protected MCP server, verify tool calls work despite missing scope/resource in authorize requests.
- **C.9: VS Code end-to-end** — Connect VS Code Copilot Chat to Authplane-protected MCP server.
- **C.10: MCP Inspector CLI** — Use `npx @modelcontextprotocol/inspector --cli` with pre-obtained bearer token.

Status: Requires manual validation against a deployment.

---

## Known Issues

### Claude Code: Scope absent from authorize request

**Bug:** anthropics/claude-code#12077
**Impact:** Claude Code omits `scope` from the `/oauth/authorize` URL. Without a workaround, the AS issues a zero-scope token, causing 403 on every tool call.
**Workaround:** Set `oauth.require_scope: false` in config.yaml (or `AUTHPLANE_OAUTH_REQUIRE_SCOPE=false`). This enables ADR-012 — Authplane substitutes all registered scopes for the resource when scope is absent. A warning log is emitted for operator visibility.
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
**Workaround:** ADR-012 handles scope defaulting. Resource binding is optional per RFC 8707.
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

Claude Code omits `scope` from authorize requests. Set `oauth.require_scope: false` to enable ADR-012 default scope substitution:

```yaml
server:
  host: 0.0.0.0
  port: 8080

storage:
  driver: sqlite
  sqlite:
    path: ./data/authserver.db

oauth:
  require_scope: false  # ADR-012: default scope for clients that omit it (e.g., Claude Code)

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
