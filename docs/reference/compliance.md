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

**Scope requirements and default value** (§3.3 asks servers to document both): when an authorize request omits `scope`, the behavior is configurable. With `oauth.require_scope: true` — the shipped default — the request is rejected with `invalid_scope`. With `oauth.require_scope: false`, the request is processed using a pre-defined default value: all scopes registered for the target resource.

Both are conformant. §3.3 requires the authorization server to "either process the request using a pre-defined default value or fail the request indicating an invalid scope", so the two settings select between the two permitted behaviors rather than opting into a deviation.

**Not implemented**: Implicit grant (§4.2), Resource Owner Password Credentials (§4.3). Only Authorization Code and Client Credentials are supported per OAuth 2.1 security requirements.

### RFC 6749 §4.4 — Client Credentials Grant

**Implemented**: Machine-to-machine token issuance via `grant_type=client_credentials`. Requires `client_secret_post` or `client_secret_basic` authentication. Supports scope validation and resource audience binding.

**Configuration**: `client_credentials.enabled` — `true` by default as of v0.2.0; set `false` to turn the grant off. Only confidential clients with `client_credentials` in their `grant_types` are authorized.

**Token format**: RFC 9068 JWT access tokens with `typ: at+jwt`, `sub` set to `client_id` (no user context), `aud` bound to resource URI when resource indicators are configured.

**Introspection + Revocation**: Machine tokens support RFC 7662 introspection and RFC 7009 revocation via the same endpoints as user tokens.

**No deviations.**

### RFC 9207 — OAuth 2.0 Authorization Server Issuer Identification

**Implemented**: every authorization response — success and error alike — carries `iss` set to the AS issuer identifier (§2). AS metadata emits `authorization_response_iss_parameter_supported: true` explicitly rather than omitting it, so a client applying §2.4's strict policy can reject a response that arrives without `iss`. The MCP 2026-07-28 specification lists this as SHOULD, announced to become MUST.

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

**Fields returned**: `issuer`, `authorization_endpoint`, `token_endpoint`, `registration_endpoint`, `revocation_endpoint`, `introspection_endpoint` (conditional), `jwks_uri`, `response_types_supported`, `grant_types_supported`, `token_endpoint_auth_methods_supported`, `code_challenge_methods_supported`, `scopes_supported`, `resource_indicators_supported`, `client_id_metadata_document_supported`, `authorization_response_iss_parameter_supported` (always emitted, never omitted — see RFC 9207 below), `dpop_signing_alg_values_supported`, `authorization_grant_profiles_supported` (see Enterprise-Managed Authorization below). The same document is aliased at `/.well-known/openid-configuration`.

### RFC 9728 — OAuth 2.0 Protected Resource Metadata

**Implemented on both sides.** PRM is the resource server's contract — it tells a calling client "this resource is protected by AS at *X*" — so the Authplane SDK adapters in [`go-sdk`](https://github.com/authplane/go-sdk), [`python-sdk`](https://github.com/authplane/python-sdk), and [`ts-sdk`](https://github.com/authplane/ts-sdk) each serve it from the MCP server's own process at `/.well-known/oauth-protected-resource/<mcp-path>` (§3.1 path-insertion form).

As of v0.2.0 the AS also serves the document for every registered Resource, so a resource server that cannot host well-known paths itself — a hosted function, a proxy-fronted service, a server on a different origin from its identifier — still has a conformant PRM a client can discover. Two shapes: `GET /.well-known/oauth-protected-resource` for a Resource whose identifier is the AS origin, and `GET /.well-known/oauth-protected-resource/{ref}` where `ref` is either the §3.1 path suffix of the Resource URI or the Resource's slug. The document carries `resource` (the registered URI, byte for byte — a Resource registered without a URI is answered 404 rather than with an empty `resource`, which §2 makes REQUIRED), `authorization_servers`, and `scopes_supported`. Multi-segment paths are supported.

Reaching the AS-hosted form requires the resource server's 401 to carry `WWW-Authenticate: Bearer resource_metadata="<that URL>"` (§5.1). The SDK adapters emit the challenge for the document they serve themselves; pointing it at the AS-hosted copy is a configuration choice on the resource side. See [`docs/reference/mcp-streamable-http.md`](./mcp-streamable-http.md) for the wire-level flow.

## Client Registration

### RFC 7591 — Dynamic Client Registration

**Implemented**: Three modes (`open`, `approved_redirects`, `admin_only`). Supports `redirect_uris`, `client_name`, `token_endpoint_auth_method`, and `application_type` (`web` or `native`, per OIDC Registration §2; the MCP specification requires clients to send it, and a client that omits it is defaulted to `web` and told so in the response — under OIDC that default refuses the loopback redirect URIs native clients need).

The MCP 2026-07-28 specification deprecates DCR in favour of CIMD for clients with no prior relationship to the AS. DCR remains supported; `dcr.mode: open` is still the default so that clients which have not adopted CIMD keep working, and the server logs a warning at boot while it is open. Deployments whose clients use CIMD or are pre-provisioned should set `admin_only` or `approved_redirects`.

### draft-ietf-oauth-client-id-metadata-document

**Implemented**: CIMD fetch, validation, and caching, enabled by default and advertised as `client_id_metadata_document_supported: true`. When `client_id` is a URL, authserver fetches the metadata document, validates it, and uses it for registration.

**Identifier rules** (draft §3, MCP client-registration §CIMD): the `client_id` URL must use `https` and must carry a path component — an origin-only identifier such as `https://example.com` is refused with `invalid_client`, because it would collapse every client hosted on that origin into one identity and one consent record. A dot-segment or an empty segment does not count as a path.

**Document validation**: `client_id` in the document must equal the fetch URL exactly; `client_name` and `redirect_uris` are required; the response must be JSON, at most 1 MB, served without following redirects, over an SSRF-filtered transport.

**Caching**: documents are cached according to their own `Cache-Control` / `Expires` headers, bounded above by `cimd.cache_ttl` and below by a short floor; `no-store` is honoured. The cache is bounded in entries. Failed fetches are negatively cached and concurrent fetches of one document are collapsed, so an unauthenticated `/oauth/authorize` cannot drive outbound traffic at will.

**Configuration**: `cimd.require_https` (default `true`) governs the document URL's scheme and nothing else; `cimd.allow_private_addresses` (default `false`) governs whether the fetch may reach loopback, RFC 1918 or link-local addresses. Both are local-development escape hatches: the server refuses to boot with either relaxed unless `server.issuer` is localhost.

## Resource Indicators

### RFC 8707 — Resource Indicators for OAuth 2.0

**Implemented**: The `resource` parameter in authorize requests binds tokens to a specific resource server. Access tokens include the resource as the `aud` claim.

**At the token endpoint**: `resource` is optional, and when present it must name the resource the grant already covers. Anything else is refused with `invalid_target` (§2.2) rather than ignored — a request that named one audience and received a token for another would only fail later, at the resource server, with nothing pointing back at the parameter that caused it.

**Strict matching**: Resource URIs use exact string matching. Trailing slashes matter. The one exception is case in the scheme and host, which is folded when comparing, because [MCP client compatibility](mcp-client-compatibility.md) asks servers to accept that variation.

## Token Lifecycle

### RFC 7009 — Token Revocation

**Implemented**: Revocation endpoint at `/oauth/revoke`. Accepts both access tokens and refresh tokens. Always returns 200 per spec.

### RFC 7662 — Token Introspection

**Implemented**: Introspection endpoint at `/oauth/introspect`. Accepts access tokens and machine tokens. Requires client authentication (`client_secret_post` or `client_secret_basic`) — public clients are refused, since RFC 6749 §2.3 forbids relying on a public client's authentication to identify it.

Per §4, the caller must also be entitled to the token it asks about: either it issued the token, or it is a resource server authorized to act AS the Resource named in the token's `aud` (see [Runtime Client Binding](../guides/integrate/runtime-client-binding.md)). Callers that qualify for neither receive `{"active": false}` — the same body an invalid token produces, so the endpoint cannot confirm that a token exists.

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

**Configuration**: `dpop.enabled` — `true` by default as of v0.2.0. Enabled means *supported*, not required: a client that presents no proof still receives a bearer token, and `dpop.require_nonce` stays `false`. Set `false` to stop advertising and accepting DPoP.

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
- Policy enforcement: self-exchange, per-resource `policy.exchange.allowed_client_ids` and `policy.runtime.client_ids`
- DPoP binding propagation on exchanged tokens
- AS metadata: `grant_types_supported` includes token exchange URN

**Configuration**: `token_exchange.enabled` — `true` by default as of v0.2.0; set `false` to turn the grant off. A cross-client exchange against a Mint resource — the acting client presenting a token minted for a different client — additionally requires the acting `client_id` to be named on the target Resource, in `policy.exchange.allowed_client_ids` or `policy.runtime.client_ids`; otherwise it is denied with `access_denied`. An exchange by the token's own client is unaffected.

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
- AS metadata: `grant_types_supported` includes the jwt-bearer URN, and `authorization_grant_profiles_supported` lists `urn:ietf:params:oauth:grant-profile:id-jag` — the field the stable MCP Enterprise-Managed Authorization extension tells clients to check. The pre-standard `identity_assertion_supported: true` is still emitted for one release and is deprecated: no conformant client reads it, and it is scheduled for removal in v0.3.0.

**Configuration**: `xaa.enabled` — `true` by default as of v0.2.0. The grant validates nothing until an operator registers a trusted IdP, because the registry starts empty; set `false` to stop advertising it.

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

### MCP Authorization Specification (2026-07-28)

**Implemented**: the full authorization-server side of the 2026-07-28 revision, and the stable Enterprise-Managed Authorization extension.

| Requirement | Level | Where |
|---|---|---|
| Protected Resource Metadata (RFC 9728), served by the resource server and, as of v0.2.0, by the AS for any registered Resource | MUST | RFC 9728 above |
| AS metadata discovery (RFC 8414), aliased at `/.well-known/openid-configuration` | MUST | RFC 8414 above |
| Client ID Metadata Documents, enabled by default, `https` + path component required, documents cached per their own headers | MUST | CIMD above |
| Dynamic Client Registration with `application_type` | Deprecated by the spec, retained | RFC 7591 above |
| Authorization code + PKCE (S256), `resource` indicator (RFC 8707) bound to `aud`, enforced at both endpoints | MUST | RFC 7636 / RFC 8707 above |
| `iss` on authorization responses (RFC 9207) | SHOULD → MUST | RFC 9207 above |
| DPoP (RFC 9449), advertised and accepted by default | — | RFC 9449 above |
| Enterprise-Managed Authorization: ID-JAG via `jwt-bearer`, `authorization_grant_profiles_supported` | Extension (stable) | XAA above |

**Out of scope on this side**: the non-auth bulk of 2026-07-28 (stateless core, `server/discover`, subscriptions, cache hints) is MCP server and SDK territory; acting as the enterprise IdP that mints ID-JAGs is the identity provider's role — authserver is the MCP authorization server in that three-party model; the OAuth Client Credentials ext-auth extension is still draft and is not committed to.

**Evidence**: every change to this server is gated on a wire-level conformance journey that starts from a bare resource URL and derives every hop from what the server actually returns — PRM, AS metadata, CIMD registration, authorization, token, and an authenticated call. The per-requirement probe suite that produced the table above runs alongside it.

**Tested against** (0.2.0, by hand, full flow through `tools/call`): Claude Desktop 1.46388.4 (CIMD, hosted callback), Claude Code 2.1.270 (CIMD, loopback callback), MCP Inspector 2.6.0 (DCR; its opt-in CIMD mode not exercised). See [MCP client compatibility](mcp-client-compatibility.md) for what each client sent.

**Spec reference**: [modelcontextprotocol.io/specification/2026-07-28/basic/authorization](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization).
