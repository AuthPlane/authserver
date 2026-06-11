# RFC Compliance Statement

authserver implements the following standards. Each section lists the RFC, the relevant sections implemented, and any intentional deviations.

> **A note on OAuth 2.1.** OAuth 2.1 is currently an active IETF Internet-Draft ([draft-ietf-oauth-v2-1](https://datatracker.ietf.org/doc/draft-ietf-oauth-v2-1/), `-15` as of March 2026), not a finalized RFC. Where this document refers to "OAuth 2.1 security requirements" or "OAuth 2.1 guidance," it means the consensus in that draft (PKCE-mandatory, implicit and ROPC removed, refresh-rotation with reuse detection). We implement against the draft because the MCP Authorization specification itself targets OAuth 2.1.

**Design philosophy**: authserver implements the subset of each RFC needed for MCP authorization — not less, not more. Where an RFC offers multiple approaches (e.g., token formats, client auth methods), we pick the secure-by-default option and document deviations explicitly. Legacy grant types (implicit, ROPC) are intentionally omitted per OAuth 2.1 security guidance. Every deviation is tied to an ADR (Architecture Decision Record) so you can trace the reasoning.

## Core OAuth

### RFC 6749 — OAuth 2.0 Authorization Framework

**Implemented sections**: §4.1 (Authorization Code Grant), §3.3 (Scope)

**Coverage**:
- Authorization code grant with PKCE enforcement
- Scope validation against registered scopes
- Client authentication: `none`, `client_secret_basic`, `client_secret_post`
- Error responses per §5.2

**Intentional deviation** (ADR-012): When `oauth.require_scope: false`, missing scope in authorize requests defaults to all registered scopes for the resource instead of rejecting. This deviates from §3.3 which states the AS "MUST NOT assume a default scope." The deviation is opt-in and disabled by default.

**Not implemented**: Implicit grant (§4.2), Resource Owner Password Credentials (§4.3). Only Authorization Code and Client Credentials are supported per OAuth 2.1 security requirements.

### RFC 6749 §4.4 — Client Credentials Grant

**Implemented**: Machine-to-machine token issuance via `grant_type=client_credentials`. Requires `client_secret_post` or `client_secret_basic` authentication. Supports scope validation and resource audience binding.

**Configuration**: `client_credentials.enabled: true` to activate. Disabled by default. Only confidential clients with `client_credentials` in their `grant_types` are authorized.

**Token format**: RFC 9068 JWT access tokens with `typ: at+jwt`, `sub` set to `client_id` (no user context), `aud` bound to resource URI when resource indicators are configured.

**Introspection + Revocation**: Machine tokens support RFC 7662 introspection and RFC 7009 revocation via the same endpoints as user tokens.

**No deviations.**

### RFC 7636 — PKCE

**Implemented**: S256 only. `plain` method is rejected. Missing `code_challenge` is rejected.

**No deviations.**

### RFC 9700 — OAuth 2.0 Security Best Current Practice

**Coverage**: PKCE required, exact redirect URI matching, refresh token rotation, no implicit grant.

## Token Format

### RFC 9068 — JWT Profile for OAuth 2.0 Access Tokens

**Implemented**: Access tokens are JWTs with `typ: at+jwt`, standard claims (`iss`, `sub`, `aud`, `exp`, `iat`, `jti`, `client_id`, `scope`).

**No deviations.**

### RFC 7517 — JSON Web Key (JWK)

**Implemented**: JWKS endpoint at `/.well-known/jwks.json`. Supports ES256 (EC P-256) and RS256 key types.

## Discovery

### RFC 8414 — OAuth 2.0 Authorization Server Metadata

**Implemented**: Full AS metadata at `/.well-known/oauth-authorization-server`.

**Fields returned**: `issuer`, `authorization_endpoint`, `token_endpoint`, `registration_endpoint`, `revocation_endpoint`, `introspection_endpoint` (conditional), `jwks_uri`, `response_types_supported`, `grant_types_supported`, `token_endpoint_auth_methods_supported`, `code_challenge_methods_supported`, `scopes_supported`, `resource_indicators_supported`.

### RFC 9728 — OAuth 2.0 Protected Resource Metadata

**Implemented by the Authplane SDK on the resource server, not by authserver itself.** PRM is the resource server's contract — it tells a calling client "this resource is protected by AS at *X*" — so the document is served by the MCP server's process, not by the AS. The Go / Python / TypeScript adapters in [`go-sdk`](https://github.com/authplane/go-sdk), [`python-sdk`](https://github.com/authplane/python-sdk), and [`ts-sdk`](https://github.com/authplane/ts-sdk) each register a handler at `/.well-known/oauth-protected-resource/<mcp-path>` (RFC 9728 path-scoped form) returning the resource URI, the list of authorization servers, and the supported scopes.

The AS itself does **not** serve PRM (it is not a protected resource); the AS's discovery surface is RFC 8414 (`/.well-known/oauth-authorization-server`) only. See [`docs/reference/mcp-streamable-http.md`](./mcp-streamable-http.md) for the wire-level flow showing how a 401 from the resource points the client at its PRM, which in turn points at the AS.

## Client Registration

### RFC 7591 — Dynamic Client Registration

**Implemented**: Three modes (`open`, `approved_redirects`, `admin_only`). Supports `redirect_uris`, `client_name`, `token_endpoint_auth_method`.

### draft-ietf-oauth-client-id-metadata-document

**Implemented**: CIMD fetch, validation, and caching. When `client_id` is a URL, authserver fetches the metadata document, validates fields, and uses it for registration.

**Configuration**: `cimd.require_https: true` (default) requires HTTPS URLs for CIMD documents in production.

## Resource Indicators

### RFC 8707 — Resource Indicators for OAuth 2.0

**Implemented**: The `resource` parameter in authorize requests binds tokens to a specific resource server. Access tokens include the resource as the `aud` claim.

**Strict matching**: Resource URIs use exact string matching. Trailing slashes matter.

## Token Lifecycle

### RFC 7009 — Token Revocation

**Implemented**: Revocation endpoint at `/oauth/revoke`. Accepts both access tokens and refresh tokens. Always returns 200 per spec.

### RFC 7662 — Token Introspection

**Implemented**: Introspection endpoint at `/oauth/introspect`. Accepts access tokens and machine tokens. Requires client authentication (`client_secret_post` or `client_secret_basic`) for confidential clients.

**No deviations.**

### Refresh Token Rotation

Refresh tokens rotate on every use (new token issued, old consumed). Reuse of a consumed refresh token triggers revocation of the entire token family per OAuth 2.1 security requirements.

## Error Format

### RFC 9457 — Problem Details for HTTP APIs

**Implemented**: Error responses include both OAuth error fields (`error`, `error_description`) and Problem Details fields (`type`, `title`, `detail`, `status`). Content-Type: `application/problem+json`.

## Proof of Possession

### RFC 9449 — OAuth 2.0 Demonstrating Proof of Possession (DPoP)

**Implemented**: Full DPoP support including proof validation, token binding, and server nonces.

**Coverage**:
- DPoP proof JWT validation (§4.3): `typ`, `alg`, `jwk`, `htm`, `htu`, `iat`, `jti`, `nonce`
- Supported algorithms: ES256, RS256, PS256
- Algorithm restriction: `alg:none` and all symmetric algorithms rejected
- Private key in `jwk` header rejected
- `htu` comparison strips query string (scheme + host + path only)
- JKT computation per RFC 7638 (JWK Thumbprint)
- Token binding via `cnf.jkt` claim in access tokens
- DPoP-bound token type: `token_type: DPoP`
- Server-issued nonces (`DPoP-Nonce` response header) with configurable TTL
- JTI replay prevention with database-backed store and background purge
- `ath` (access token hash) validation on resource requests
- Backward compatible: no DPoP proof = standard Bearer token
- Introspection returns `cnf.jkt` for DPoP-bound tokens
- AS metadata: `dpop_signing_alg_values_supported`

**Configuration**: `dpop.enabled: true` to activate. Disabled by default.

**No deviations.**

## Token Exchange

### RFC 8693 — OAuth 2.0 Token Exchange

**Implemented**: Full token exchange support for impersonation and delegation flows.

**Coverage**:
- `grant_type=urn:ietf:params:oauth:grant-type:token-exchange`
- Subject token validation: signature, issuer, expiry, revocation check
- Subject token types: `urn:ietf:params:oauth:token-type:access_token`, `urn:ietf:params:oauth:token-type:jwt`
- Impersonation: no actor token, no `act` claim, `sub` preserved
- Delegation: actor token present, nested `act` claim per §4.1
- Multi-hop delegation: correct chain nesting
- Scope narrowing: requested scope must be subset of subject token scope
- Configurable chain depth limit (1-10, default 5)
- Policy enforcement: self-exchange, `may_act` claim, config allowlist
- DPoP binding propagation on exchanged tokens
- AS metadata: `grant_types_supported` includes token exchange URN

**Configuration**: `token_exchange.enabled: true` to activate. Disabled by default.

**No deviations.**

## Authplane Extensions

### Enterprise-Managed Authorization (XAA)

**Type**: JWT Bearer grant type per RFC 7523, with ID-JAG assertion format (Authplane extension).

**Coverage**:
- `grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer`
- ID-JAG assertion validation: signature, issuer, audience, expiry, type header (`oauth-id-jag+jwt`)
- Trusted IdP registry with JWKS discovery and caching (SSRF-protected)
- Policy engine: IdP + client_id + scope + resource constraint evaluation
- Subject mapping: `auto_map` (federated subject) and `strict` (explicit mapping required) modes
- Replay prevention: assertion JTI single-use enforcement with automatic purging
- Scope intersection: policy scopes narrow the issued token's scope
- Resource binding: `resource` parameter flows to token `aud` claim
- DPoP binding: XAA tokens support `cnf.jkt` proof-of-possession
- Machine token storage: XAA tokens tracked in machine token store for revocation/introspection
- AS metadata: `grant_types_supported` includes jwt-bearer URN when enabled

**Configuration**: `xaa.enabled: true` to activate. Disabled by default.

**No deviations from RFC 7523 §2.1 (JWT assertion profile).**

### Agent Identity Claims

**Type**: Authplane-specific extension (not standardized).

**Coverage**:
- `agent_id` claim in JWT: set to `client_id` when issuing client has `is_agent=true`
- `agent_chain` claim: ordered list built from delegation `act` chain, capped at 8
- Agent registration via DCR: `agent: true`, `agent_description` (max 255 chars)
- Optional JWKS agent listing (`agents.enable_jwks_listing: true`)
- AS metadata: `authplane_agent_identity_supported: true`

## MCP-Specific

### MCP Authorization Specification (2025-11-25)

**Implemented**: Full discovery flow (PRM → AS Metadata → DCR → Authorize → Token), CIMD support, resource indicators. The MCP Authorization spec targets OAuth 2.1 (see the note at the top of this page on OAuth 2.1's IETF-draft status).

**Tested against**: Claude Code, Claude Desktop, MCP Inspector.

**Spec reference**: [modelcontextprotocol.io/specification/2025-11-25/basic/authorization](https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization).
