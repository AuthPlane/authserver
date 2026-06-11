---
name: MCP Client Compatibility Report
about: Report compatibility results for an MCP client with Authplane
title: "[Compat] <Client Name> <Version>"
labels: compatibility, mcp-client
assignees: ""
---

## Client Information

- **Client:** (e.g., Claude Code, VS Code Copilot Chat, MCP Inspector)
- **Version:**
- **Platform:** (e.g., macOS, Linux, Windows)
- **Transport:** (e.g., streamable-http, stdio)

## Authplane Information

- **Version:**
- **Storage driver:** (sqlite / postgres)
- **DCR mode:** (open / approved_redirects / admin_only)
- **Config:** (attach or paste relevant config.yaml sections)

## Description

Brief summary of the compatibility test results.

## Compatibility Scenarios

Check each scenario that was tested. Mark pass/fail/skip.

- [ ] **C.1: Metadata Discovery** — `/.well-known/oauth-authorization-server` and `/.well-known/oauth-protected-resource`
- [ ] **C.2: Dynamic Client Registration** — `POST /oauth/register`
- [ ] **C.3: PKCE (S256)** — Authorization with `code_challenge_method=S256`
- [ ] **C.4: Authorization (Scope Handling)** — Scope in authorize request (or missing per ADR-012)
- [ ] **C.5: Token Exchange** — `POST /oauth/token` with authorization_code
- [ ] **C.6: Token Refresh** — `POST /oauth/token` with refresh_token
- [ ] **C.7: Tool Calls** — Bearer token accepted by resource server
- [ ] **C.8: End-to-end (manual)** — Full flow from client UI to tool call
- [ ] **C.9: Error Handling** — Invalid credentials, expired tokens, revoked tokens
- [ ] **C.10: Session Persistence** — Token refresh after long idle period

## Reproduction Steps

1. Start Authplane with the config above
2. Connect the MCP client to the protected MCP server
3. Trigger an OAuth flow (e.g., call a tool)
4. Observe results

## Logs

<details>
<summary>Authplane server logs</summary>

```
(paste relevant logs here)
```

</details>

<details>
<summary>Client logs</summary>

```
(paste relevant logs here)
```

</details>

## Additional Context

Any other relevant information (screenshots, network traces, etc.).
