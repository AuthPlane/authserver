# 01 — What is Authplane?

**Time:** 60 seconds. **Goal:** know enough vocabulary to follow the rest
of the tutorial.

Authplane is a **self-hosted OAuth 2.1 + MCP Authorization Server** that
ships as a single Go binary. You run it next to your MCP server. It:

- Implements OAuth 2.1 (authorization code + PKCE, client credentials,
  refresh tokens, token exchange RFC 8693, JWT bearer RFC 7523).
- Implements the **MCP Authorization spec (2025-11-25)** — discovery,
  resource indicators, scopes-as-tools, DPoP sender constraining
  (RFC 9449).
- Acts in one of two modes per resource:
  - **Mint** — Authplane is the issuer; it signs the access token your
    MCP server validates.
  - **Broker** — Authplane stores upstream tokens (GitHub, Slack, Okta,
    ...) and vends them to your MCP server via token exchange.
- Federates with corporate IdPs (Okta, Entra ID, Auth0) via OIDC and
  via JWT-bearer cross-AS assertions (XAA).

Two minutes of additional context (architecture, trust model, glossary):
[What is Authplane (concepts)](../concepts/what-is-authplane.md).

Ready? Continue to [02 — Quickstart with Docker](02-quickstart-docker.md).
