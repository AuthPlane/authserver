# Changelog

All notable, user-facing changes to authserver are documented here —
operator-impact and wire-shape changes only. The format follows
[Keep a Changelog](https://keepachangelog.com/); dates are ISO 8601.

## [0.1.0] — 2026-06-10

Initial public release of the Authplane Authorization Server: a self-hosted
OAuth 2.1 authorization server implementing the MCP Authorization
specification (2025-11-25), shipped as a single Go binary with an embedded
React Admin UI.

### Added

- **Cross-App Access (XAA)** — enterprise federation via external
  authorization assertions: a trusted upstream authorization server signs a
  JWT asserting the user's identity, which the client exchanges at
  `/oauth/token` through the JWT Bearer flow (RFC 7523). No login UI — the
  upstream AS has already authenticated the user. This is the basis for
  enterprise-managed auth across applications.
- **OAuth 2.1 + MCP Authorization** — authorization code with PKCE, the
  Protected Resource Metadata document (RFC 9728), and Authorization Server
  Metadata discovery (RFC 8414).
- **Grant types** — client credentials, token exchange (RFC 8693), and JWT
  Bearer (RFC 7523, the foundation for XAA).
- **Token issuance & lifecycle** — JWT and opaque access tokens, refresh
  with rotation, introspection (RFC 7662), and revocation (RFC 7009).
- **DPoP** sender-constrained tokens (RFC 9449).
- **Broker / Connect flows** — mint tokens for downstream resources and
  broker upstream-provider connections, with at-rest encryption via an AES
  master key or HashiCorp Vault Transit.
- **OIDC federation** — front the authorization server with an upstream OIDC
  identity provider.
- **Dynamic Client Registration** (RFC 7591).
- **Admin UI + REST API** — manage clients, resources, scopes, grants, and
  issuances from the embedded console or the admin API.
- **SDKs** for Go, TypeScript, and Python (auth client + resource server).
- **Deployment** — Docker image (`authplane/authserver`), Helm chart, and
  standalone binary; SQLite or PostgreSQL storage.
