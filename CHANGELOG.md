# Changelog

All notable, user-facing changes to authserver are documented here —
operator-impact and wire-shape changes only. The format follows
[Keep a Changelog](https://keepachangelog.com/); dates are ISO 8601.

## [0.2.2] — 2026-10-03

Security patch release. No new config keys, metrics or audit actions.
Read the upgrade notes first: one step applies to fronting links, and
three schema migrations run automatically.

### Upgrade notes

- **Fronting links:** add your gateway's `client_id` to the source
  resource's runtime clients before upgrading
  (`authserver admin resource runtime-client add --slug <source>
  --client-id <gateway>`). Until then its exchanges are refused with
  `access_denied`.
- **Migration 014** makes `users.email` nullable (on SQLite it rebuilds
  the `users` table, keeping every row). Once applied, do not start an
  older binary against the database without first running
  `014_user_email_nullable.down.sql`, which works only while at most one
  user has no email.
- **Migration 015** allows one account per federated identity. It refuses
  to apply if two federated accounts already share a provider subject;
  the migration file has the query that finds them.
- **Migration 016** adds `refresh_token` to every client stored with
  `grant_types` exactly `["authorization_code"]`, so existing clients keep
  refresh (see Security).

### Security

- Any client holding the token-exchange grant, including one registered
  through open dynamic registration, could exchange through a fronting
  link and reach the target as the gateway. Only the gateway may now:
  a client listed in the source resource's `policy.runtime.client_ids`,
  or in the target's `policy.exchange.allowed_client_ids` (see Upgrade
  notes).
- Token exchange through a fronting link with no `scope` parameter skipped
  the link's scope check. A caller whose token lacked the mapped source
  scope was issued a token for the target with no `scope` claim, or, on a
  broker target, the user's stored upstream token. When `scope` is omitted
  the server now derives it from the subject token's scopes through the
  link, and refuses the exchange when none map. Both fronting-link issues
  affect 0.1.0 through 0.2.1 when token exchange is enabled (the default
  from 0.2.0).
- A direct token exchange with no `scope` returned the user's full
  upstream credential on a broker resource, and a token with an empty
  scope on a Mint resource. The scope now defaults to what the exchange is
  authorized for (on a broker, what the agent is consented for), and the
  exchange is refused when that is empty.
- `client_credentials` with a `resource` issued scopes the resource never
  declared, and a client with no scopes (for example one registered
  through open dynamic registration) could get a token for any resource
  by omitting `scope`. Scopes are now limited to the client's scopes the
  resource declares; nothing left → `invalid_scope`. An unknown
  `resource` returns `invalid_target`.
- XAA (jwt-bearer) kept issuing tokens for a mapped local user after the
  user was disabled or deleted, and those tokens stayed active at
  introspection. Both are now refused. A subject mapping must name an
  existing user.
- Token exchange accepted subject and actor tokens of disabled users and
  suspended clients, which introspection already reports inactive. Those
  are now refused with `invalid_grant`.
- A jwt-bearer client with no scope ceiling, such as one registered
  through open dynamic registration, received the XAA policy's maximum
  scopes. It is now refused with `invalid_scope`.
- Refresh tokens were issued to clients not registered for the
  `refresh_token` grant. They are now issued and honored only for
  clients that have it. Registrations that omit `grant_types` default to
  `authorization_code` and `refresh_token`.
- A config value written as `${VAR}` that no environment variable
  overrides now fails at startup instead of being used literally. The
  Docker quickstart showed one for `admin.api_key` without passing the
  variable; if you copied it, rotate the key and pass it as
  `AUTHPLANE_ADMIN_API_KEY`.
- A few log lines, one span attribute and three audit records that
  included the user's email address no longer do. `user_id` identifies
  the record instead.
- Container image base layers are pinned by digest.

### Changed

- Tokens minted through a fronting link name the agent at `act.act.sub`
  (previously the gateway, when gateway and agent are different
  clients), and they introspect as active to the target resource's
  runtime clients (previously inactive to everyone).
- Audit rows for fronted exchanges record the calling client in
  `client_id` and `actor_client`; the source resource stays in
  `via_link`.
- Examples and `AGENTS.md` pin the current SDKs: TypeScript and Python
  0.5.0, Go v0.4.0.

### Fixed

- Federated sign-in works for users whose identity provider sends no
  email; previously only the first such user could sign in. A first
  sign-in whose email belongs to another account gets a 409 page that
  explains why. Two simultaneous first sign-ins no longer create two
  accounts. Server-side failures on the callback return 500, not 401.
- Audit events raised inside an HTTP request carry the caller's IP.
- Traces: a 5xx response marks the server span as an error; Vault Transit
  signing joins the request trace; upstream broker, CIMD dispatch and IdP
  discovery calls get spans and log a WARN on failure.
- Dashboards: three Operations panels queried renamed or nonexistent
  metrics; every exported instrument is charted; Prometheus alert rules
  ship in `deploy/observability/alerts.yaml`.
- Audit catalog: `token.issue_denied`, `token.refresh_denied`,
  `admin.ui.login`, `key.rotated` and `dcr.mode_updated` documented;
  `GET /admin/audit` query filters documented.
- Deploy guides: the Vault alert string is `vault token renewal failed`;
  the admin port default is `:9001`; `AUTHPLANE_DPOP_PURGE_INTERVAL` is
  removed from the compose files (nothing reads it); rate limiting behind
  a reverse proxy is explained (the limiter keys on the peer address, so
  every client behind one proxy shares a bucket).
- Topology pages: the broker-mcp flow now shows how an agent reaches a
  broker resource (consent at its own Mint resource, then token exchange;
  a broker resource is never the target of `/authorize`); the
  gateway-mint request names target-side scopes; the
  `fronting_link_missing` error links to a page that exists.
- Reference docs: rows for `invalid_client_metadata`,
  `invalid_redirect_uri` and `invalid_target`; HTTP metric labels named
  correctly.
- CLI help: `admin fronting` and `admin resource runtime-client` describe
  the gateway rule; `admin resource create --description`, which was
  never stored, is hidden and warns when used.

## [0.2.1] — 2026-09-21

Post-launch fixes. One additive schema change.

### Security

- Revoking a consent grant (`DELETE /admin/grants/consent/{id}`) now
  revokes every token issued because of it: the client's access token,
  every token exchanged from it, and the client's refresh families for the
  resource. Introspection reports them inactive and they are refused as a
  `subject_token`. An authorization code issued before the revoke can still
  be redeemed within its 10-minute life; the next minor closes that.
  Resource servers that verify JWTs locally see nothing until `exp`.
- `DELETE /admin/issuances/{id}` now takes effect at introspection.
- The per-client scope ceiling (`client.Scope`) is enforced on
  `authorization_code` and `refresh_token`, not only on the machine grants.
  A client whose ceiling is narrower than what it requests now gets
  `invalid_scope`. Check any client that has both a `scope` and
  `authorization_code` before upgrading.
- New config `oauth.default_client_scope`
  (`AUTHPLANE_OAUTH_DEFAULT_CLIENT_SCOPE`): the ceiling assigned to clients
  created through dynamic registration or CIMD whose grants keep a user in
  the loop. Applies to new registrations only.

### Deprecated

- Clients with no scope ceiling will be refused at `/oauth/authorize` and
  on `refresh_token` from v0.3.0. Set `oauth.default_client_scope` or use
  `dcr.mode: admin_only` and grant scopes per client. The server logs a
  startup warning while it is unset.

### Fixed

- `agent_id` is emitted on `authorization_code` and `refresh_token` access
  tokens for agent clients, as it already was on the other grants.
  Delegated agent tokens now log one `attached agent_id claim` line (with
  `chain_length`) instead of two; anything keyed on
  `attached agent_chain claim` goes quiet.
- `GET /admin/clients`, `GET /admin/clients/{id}` and the `PATCH` response
  include `scope`, `agent` and `agent_description`, always present.
- `GET /admin/issuances` and `GET /admin/issuances/{id}` include
  `consent_client_id` and `parent_jti`.
- Docs: agent identity identifies the issuing client; it does not vouch
  for it. The token exchange guide describes what revocation reaches.
- Conformance register: AP-EXT-005 (consent revocation reaches derived
  tokens) and AP-EXT-006 (scope ceiling on the interactive grants).

### Schema

- Migration 013 adds `issuances.consent_client_id`, `issuances.parent_jti`
  and an index on `parent_jti`. It is numbered past the range the next
  minor reserves; the migration runner now applies every embedded version
  not yet recorded, so upgrades in either order apply cleanly.

## [0.2.0] — 2026-09-14

MCP Authorization **2026-07-28** release, built with Go 1.26.6. Every gap
between authserver and the current revision of the specification is closed,
and the spec-surface features now ship enabled. A wire-level conformance
journey gates every change.

> **Contains breaking changes.** Three bite a deployment that changes no
> configuration: the spec-surface features are on, a cross-client token
> exchange needs an operator allowlist entry, and an origin-only CIMD
> `client_id` is refused. Read the next section first.

### Breaking changes

- **DPoP, client credentials, token exchange and XAA are enabled by default.**
  `dpop.enabled`, `client_credentials.enabled`, `token_exchange.enabled` and
  `xaa.enabled` now default to `true`; a stock deployment previously
  advertised only `authorization_code` and `refresh_token`. The discovery
  document grows accordingly. DPoP `enabled` means *supported*, not required —
  a client sending no proof still gets a bearer token. Grants remain gated by
  client registration, so enabling one widens what a client *may* register
  for; it grants nothing retroactively. XAA validates nothing until a trusted
  IdP is registered. The Helm chart (0.4.0) follows suit.
  **Action:** set any of the four to `false` (or the matching
  `AUTHPLANE_*_ENABLED`) to keep the previous posture.

- **A cross-client token exchange needs an operator allowlist entry.** A
  client presenting a token minted for a *different* client — the common
  shape is an MCP server exchanging a user's web-app or agent token for a
  Mint resource token — must be named on the target Resource, in
  `policy.exchange.allowed_client_ids` or `policy.runtime.client_ids`.
  Otherwise the exchange is refused with `access_denied` (not
  `consent_required`; re-prompting the user would not fix it). Previously an
  empty allowlist meant "any client may act", so any client holding another
  client's token could spend that client's consent. Unaffected: a client
  exchanging a token issued to itself, fronted exchanges, Broker resources,
  and an MCP server exchanging for its *own* resource where it is already in
  `runtime.client_ids`.
  **Action:** for each MCP server that exchanges for a downstream resource it
  does not act as:
  ```
  PATCH /admin/resources/{id}
  {"policy": {"exchange": {"allowed_client_ids": ["<exchanging-client-id>"]}}}
  ```

- **A CIMD `client_id` URL must use `https` and carry a path component.**
  Per the 2026-07-28 client-registration rules. An origin-only identifier
  (`https://example.com`) collapses every client on that domain into one
  identity and one consent record, so it is refused at `/oauth/authorize`
  with `invalid_client`; dot-segments and empty segments do not count as a
  path. Those identifiers were never spec-legal.
  **Action:** re-register affected clients against a metadata URL with a path.

- **`cimd.require_https: false` is only accepted with a localhost issuer.**
  The server refuses to boot otherwise: a metadata document served over
  plaintext decides a client's identity and redirect URIs and is modifiable in
  transit. Both shipped configs already use a localhost issuer.

- **`cimd.require_https` no longer governs SSRF address filtering;
  `cimd.allow_private_addresses` does.** Turning HTTPS enforcement off for
  local development previously also, and silently, removed dial-time address
  filtering, so a DNS name resolving to a private or cloud-metadata address
  was fetched unchecked. The two controls are now independent; both default
  to their protective setting, and the new key is likewise refused off a
  localhost issuer.
  **Action:** if you run `require_https: false` and serve CIMD documents from
  loopback, a container network or a LAN address (the shape of the demo
  config), add `cimd.allow_private_addresses: true`.

- **`resource` at the token endpoint is enforced.** On the authorization-code
  and refresh paths it was read and dropped; the audience came from the
  session, so a client naming a different resource got a token for the one
  it authorized, with a 200. A `resource` that is not one the grant covers is
  now refused with `invalid_target` (RFC 8707 §2.2), before the code or
  refresh token is consumed. Omitting it is unchanged. The likeliest way to
  hit this is a spelling difference: resource URIs match exactly and a
  trailing slash counts.

- **Go API (embedders only):** `Fetcher.SetAllowLoopback` is removed — the
  address policy rides on the per-request `CIMDFetchConfig`;
  `ssrf.NewSafeTransport` is variadic; `AccessTokenClaims.MayAct` is removed;
  `api/public.NewServer` panics when the authorize or consent handlers are
  wired without an `IssuerProvider`.

### Upgrading from 0.1.2

- Config and database from 0.1.2 work unchanged apart from the above.
  Migration `004` applies on first start — additive (a nullable
  `application_type` column on `clients`; existing rows stay NULL and read
  as `web`).
- Decide the posture for the four now-on features before upgrading.
- Authorize each MCP server that exchanges for a downstream resource (see
  above). An MCP server exchanging for its own resource needs nothing.
- If any client uses an origin-only CIMD `client_id`, re-register it first.

### Security

- **The consent screen shows where an approval will be sent, and warns when
  that is the user's own machine.** The client name is self-declared; the
  redirect URI is the one thing on the screen the server has verified. The
  destination host is rendered in its own block above Deny/Allow; a loopback
  destination is marked, with a warning that any program on the machine can
  ask for this. Parsed from the URI, so a userinfo decoy
  (`https://good.example.com@evil.example/cb`) displays `evil.example`.
- **The CIMD fetch path is bounded.** `GET /oauth/authorize` needs no session
  and a URL-shaped `client_id` is fetched, so an unauthenticated caller could
  drive outbound traffic at will. Failed fetches are negatively cached,
  concurrent fetches of one document collapse into one, total outbound
  concurrency is capped, and the document cache is bounded in entries.
- **The DPoP nonce middleware no longer issues a nonce — a durable insert —
  for every `/oauth/token` request.** Only a request presenting a `DPoP`
  header gets one. Reachable now that DPoP is on by default.
- **Dependency updates.** `google.golang.org/grpc` v1.83.2 (CVE-2026-84445);
  `go-jose/v4` v4.1.5 — verification key chosen per signature, `alg` checked
  against the key's curve, malformed Ed25519 JWKs and out-of-range
  `NumericDate` rejected, on the paths a trusted-IdP JWKS reaches;
  `golang.org/x/crypto` v0.57.0 (CVE-2026-56855, CVE-2026-78662).
- The `dcr.mode: open` boot warning now reports the *effective* mode, so a
  mode persisted through the admin API cannot leave it silent.
- `AUTHPLANE_XAA_SUBJECT_MODE` is validated at boot; a typo no longer
  silently downgrades `strict` to `auto_map`.

### Added

- **The AS serves OAuth 2.0 Protected Resource Metadata (RFC 9728)** for
  every registered Resource, at `GET /.well-known/oauth-protected-resource`
  and `/.well-known/oauth-protected-resource/{ref}` — `ref` being the §3.1
  path suffix of the Resource URI or its slug. A resource server that cannot
  host well-known paths itself still has a conformant document to point its
  `WWW-Authenticate: resource_metadata` at. A Resource with no URI is 404, not
  a document with an empty `resource`.
- **RFC 9207 `iss` on every authorization response**, success and error
  alike, and `authorization_response_iss_parameter_supported: true` in
  discovery — emitted unconditionally, because a client keys its strict
  rejection on it and "absent" differs from "false". The value is written
  verbatim; clients compare it byte for byte.
- **`authorization_grant_profiles_supported`** in discovery, listing
  `urn:ietf:params:oauth:grant-profile:id-jag` — the field the stable MCP
  Enterprise-Managed Authorization extension tells clients to check. This
  server previously advertised the capability only under a pre-standard flag
  no conformant client reads.
- **`POST /oauth/register` accepts and persists `application_type`** (`web`
  or `native`). MCP clients are required to send it; a client that omits it
  is defaulted to `web` and told so in the response, which under OIDC refuses
  the loopback redirect URIs native clients need.
- **`xaa.*` is configurable from the environment**: `AUTHPLANE_XAA_ENABLED`,
  `_TOKEN_EXPIRY`, `_MAX_ASSERTION_AGE`, `_REQUIRE_RESOURCE`,
  `_SUBJECT_MODE`, `_JWKS_CACHE_TTL`.
- **`cimd.allow_private_addresses`** (default `false`,
  `AUTHPLANE_CIMD_ALLOW_PRIVATE_ADDRESSES`) — see Breaking changes.

### Changed

- **CIMD documents are cached according to their own HTTP cache headers**
  (`Cache-Control`, `Expires`), bounded above by `cimd.cache_ttl` and below by
  a short floor; `no-store` is honoured. `cimd.cache_ttl` is now a ceiling
  rather than a fixed lifetime.
- **The server warns at boot when `dcr.mode` is `open`.** The 2026-07-28
  specification deprecates DCR in favour of CIMD, which needs no registration
  endpoint and is on by default, so most deployments no longer need open DCR.
  It stays the default only because client-side CIMD support is still
  arriving.

### Deprecated

- **`identity_assertion_supported`** in AS metadata — still emitted this
  release; removed in v0.3.0. Read `authorization_grant_profiles_supported`.
- **Dynamic Client Registration as the primary registration path**, per the
  specification. Still supported; set `dcr.mode: admin_only` or
  `approved_redirects` once your clients register via CIMD.

### Removed

- **`may_act`.** Its writer was removed long ago; the reader, claim field and
  documentation were unreachable leftovers. Operator impact: none — a
  cross-client exchange with no `resource` was already impossible and fails
  at the same point with the same `access_denied`.

### Fixed

- `GET /.well-known/oauth-protected-resource/{ref}` answered 500 on a `ref`
  that was not valid UTF-8; it is 404 now.
- The consent `POST` resolved the issuer after minting the authorization
  code, so an issuer failure orphaned the code and persisted the grant.
- The compliance statement declared a `require_scope` deviation that was not
  one, citing a record that did not exist.
- The generated config reference documented zeros for every `xaa.*` default.

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
