# Changelog

All notable, user-facing changes to authserver are documented here —
operator-impact and wire-shape changes only. The format follows
[Keep a Changelog](https://keepachangelog.com/); dates are ISO 8601.

## [0.1.2] — 2026-08-31

Security and hardening release, built with Go 1.26.6.

> **Contains breaking changes despite the patch version.** Three bite a
> deployment that changes no configuration: introspection, account lockout,
> and the `POST /login` throttle response. Read the next section first.

### Breaking changes

- **`POST /oauth/introspect` now checks who is asking.** Previously any client
  could introspect any token. The caller must now have issued the token, or be
  a resource server authorized to act as the Resource in the token's `aud`;
  anyone else gets `{"active": false}`. Public (secret-less) clients can no
  longer introspect, and suspended clients are refused on introspect and
  revoke.
  **Action:** authorize each resource server that introspects, before upgrading:
  ```bash
  authserver admin resource runtime-client add --client-id <rs-client-id> --slug <resource-slug>
  ```
  Otherwise it sees every token inactive and rejects every request, on the
  first call. Clients introspecting their own machine tokens are unaffected.

- **`rate_limit.enabled: false` no longer disables account lockout.** The
  lockout's own switch is `rate_limit.auth_fail_max`. A deployment running
  `enabled: false` **will start locking accounts**.
  **Action:** set `auth_fail_max: 0` to keep the old behaviour.

- **`rate_limit.requests_per_second` and `burst` must be > 0** when
  `rate_limit.enabled` is true; the server now refuses to start otherwise.
  Zero never disabled the limiter, it bricked it. Use `enabled: false` to turn
  throughput limiting off.

- **`rate_limit.auth_lockout` and `auth_fail_window` must be > 0.** The server
  refuses to start on `0s`. Only a config explicitly setting one to `0s` is
  affected.

- **A locked-out `POST /login` answers `429 text/html`,** re-rendering the form,
  instead of `application/problem+json` with `error: slow_down`. `Retry-After`
  now carries the real remaining lockout. Scripts keying off the old JSON body
  on `/login` must use the status code. Other public routes are unchanged.

- **`xaa.require_resource` is now enforced.** It was previously parsed and
  documented but never read. With it `true`, a jwt-bearer exchange naming no
  resource is refused with `invalid_target`. Default remains `false`.

- **`GET /admin/audit` is now bounded.** Without `since` it returns the last 24
  hours (was: all history); `since` beyond 30 days, `limit` > 1000 and `offset`
  > 100000 are rejected with `400`, as are malformed values that were
  previously ignored. Both lookback bounds are configurable — see Added.

- **Helm liveness and readiness probes moved to the new `GET /livez`,** so a
  database outage no longer withdraws the pod and takes down the JWKS endpoint
  resource servers need to validate tokens. `/health` and `/ready` are
  unchanged. **Action:** if you run your own manifests, move both probes.

- **Go API (embedders only):** `admin.NewServer` returns `(*Server, error)`;
  `output.SecretStore` → `output.SecretEncoder` and `SecretResolver.Resolve`
  takes a `SecretSource`; the auth-failure lockout moved from
  `shared.RateLimiter` to the new `shared.AuthLockout`.

### Upgrading from 0.1.1

- Config and database from 0.1.1 work unchanged apart from the above.
  Migrations `002` and `003` apply on first start — both additive (nullable
  columns on `broker_providers` and `token_families`; existing rows stay NULL
  and nothing backfills them). Provider rows written by 0.1.x still read,
  including the legacy `client_secret_env` / `sa_key_env` spellings.
- Review `rate_limit` before upgrading: an explicit `enabled: false`, or a `0`
  in `requests_per_second`, `burst`, `auth_lockout` or `auth_fail_window`, now
  behaves differently or refuses to boot.
- Authorize any introspecting resource server (see above).

### Security

- **Go 1.26.6**, closing seven reachable standard-library advisories:
  GO-2026-6218 (`net/url`), GO-2026-6091 (`html/template`), GO-2026-6090
  (`crypto/tls`), GO-2026-6089 and GO-2026-5026 (`net/http`), GO-2026-6088
  (`encoding/xml`), GO-2026-5972 (`encoding/asn1`).
- IdP JWKS fetching now goes through the shared SSRF guard, enforced repo-wide
  by a build gate.
- Login CSRF token is bound to a pre-session nonce instead of a constant.
- Disabling a user now ends their browser session and blocks pending
  authorization.
- Failed logins no longer reveal which addresses have accounts.
- `oidc.show_local_login: false` now actually disables local password login.
- Tokens issued from a replayed authorization code are revoked.
- A missing `exp` or `iat` is rejected at access-token verification.
- Failed introspection is audited as `token.introspect_denied`.
- Vault Transit follows at most one redirect and refuses https→http.

### Added

- **`rate_limit.max_tracked_identities`** (default `250000`) bounds the account
  lockout's tracking map; at the bound it evicts unlocked entries rather than
  refusing new identities, so a flood cannot leave an untouched account
  unprotected. Values below `10000` are rejected at startup.
- **`admin.audit_default_lookback`** (default 24h) and **`admin.audit_max_lookback`**
  (default 720h) set the audit feed's bounds. Unset reproduces the built-in
  defaults exactly; an unparseable value fails the boot rather than reverting.
- **`oauth.state_max_age`** (default 10m) bounds the OIDC state cookie lifetime
  and callback freshness window.
- **`GET /livez`** — liveness that touches no dependency.
- **Encrypted upstream-provider secrets** via new `broker_providers.enc_secret_data`
  / `enc_secret_backend` columns. Providers using an env reference are
  unaffected. Note: with an encryptor configured, an inline secret is *moved*
  into the new column — re-supply secrets if you roll back.
- **Extensibility seams** for downstream distributions (middleware chain,
  admin auth and routes, per-request URL building). Default behaviour unchanged.
- **Signed releases** — cosign (keyless) signatures and syft SBOMs. See
  [verifying-releases.md](docs/guides/deploy/verifying-releases.md) for how to
  check a download or image against the workflow that built it.
- **The Helm chart is published to `oci://ghcr.io/authplane/charts`** by the
  release workflow. The Helm guide has always named that location; nothing
  pushed to it until now. The chart carries its own version, so a release that
  does not touch `charts/` republishes nothing.

### Changed

- Upstream-provider secret references are restricted to env names prefixed
  `CONNECTOR_` or `AUTHPLANE_VAULT_`. References carried over from
  `oidc.client_secret_env` are exempt.
- OpenTelemetry resource attributes use semconv 1.43.0; attribute names
  unchanged.

### Deprecated

- **`oidc.client_secret_env` → `oidc.client_secret_ref`** (and
  `AUTHPLANE_BROKER_PROVIDER_CLIENT_SECRET_ENV` → `..._REF`). Old spellings are
  still honoured, keep their 0.1.x precedence, and warn at startup.
- **`api/shared.NewJWTMiddleware`** — applies neither audience isolation nor
  DPoP replay protection.

## [0.1.1] — 2026-08-11

Security maintenance release — Go toolchain and dependency updates only, no
functional or wire-shape changes.

### Security

- Build with Go 1.26.5, picking up the crypto/tls Encrypted Client Hello
  privacy fix (GO-2026-5856), net/textproto error-escaping fix
  (GO-2026-5039), and crypto/x509 hostname-parsing fix (GO-2026-5037).
- `github.com/jackc/pgx/v5` v5.9.1 → v5.10.0 — fixes SQL injection via
  placeholder confusion with dollar-quoted string literals (GO-2026-5004).
- `google.golang.org/grpc` v1.80.0 → v1.83.0 — fixes HTTP/2 transport
  server and xDS RBAC vulnerabilities (GO-2026-6061).
- `golang.org/x/text` v0.35.0 → v0.40.0 — fixes infinite loop on invalid
  input (GO-2026-5970).
- OpenTelemetry modules v1.43.0 → v1.45.0 — restores the baggage-parsing
  raw-header length cap (GO-2026-5158).

### Changed

- OpenTelemetry resource attributes now use semantic-conventions schema
  1.43.0 (previously 1.40.0). Telemetry attribute names are unchanged.
- Helm chart 0.2.1: default image tag (`appVersion`) now 0.1.1 — a default
  install previously deployed the stale `0.1.0-rc1` image.

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
