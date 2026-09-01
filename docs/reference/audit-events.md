<!-- Hand-maintained reference. Keep in sync with internal/domain/audit/entity.go. -->

# Audit events

Every state-changing operation in the authorization server emits an audit record via the [`audit.Service`](../../internal/services/audit.go). Each record carries an `Action` (one of the constants declared in [`internal/domain/audit/entity.go`](../../internal/domain/audit/entity.go)), an `ActorID` (user id, client id, or `"system"` / `"admin"`), a `ClientID`, a source IP, a free-form `Detail` string (canonically `key=value key=value ...` so it is greppable), and the OTel trace id of the request that triggered the emit. This page is the authoritative catalog of every action name and the detail keys it carries.

The `Detail` column lists the keys you can expect to see in the canonical `key=value` payload. Optional keys are wrapped in square brackets. The `Emitted by` column cites the emit site as `file:line` so you can verify the exact format string. Most emits live in the service layer; a few fire from the HTTP handler that owns the decision, and the cited path says which.

| Action | Detail keys | Emitted by | Example query |
| --- | --- | --- | --- |
| `token.issued` | `family` | `exchangeCode` in `internal/services/token.go` | `WHERE action='token.issued'` |
| `token.refreshed` | `family` | `refreshToken` in `internal/services/token.go` | `WHERE action='token.refreshed'` |
| `token.revoked` | `family` \| `machine_token jti` \| `machine_jti` | `RevokeToken` / `tryRevokeMachineToken` in `internal/services/revocation.go`, `RevokeToken` in `internal/services/admin.go` | `WHERE action='token.revoked'` |
| `auth_code.reused` | `code_reuse session verifier` | `handleCodeReuse` in `internal/services/token.go` | `WHERE action='auth_code.reused' AND detail LIKE '%verifier=valid%'` (a replayer who proved PKCE and the session's `client_id` — the strongest reuse signal the server emits). `actor_id` and `client_id` are the user and client the code was issued to, not the replayer |
| `family.revoked` | `reuse_detection family` (refresh-token reuse) \| `code_reuse family` (authorization-code reuse) | `revokeFamilyHalf` in `internal/services/token.go`, reached from `revokeFamilyOnReuse` or `handleCodeReuse` | `WHERE action='family.revoked'` (reuse alarm — the detail prefix says which path) |
| `family.revocation_failed` | `reuse_detection family path half` \| `code_reuse family path half` | `reportReuseHalfFailure` in `internal/services/token.go`, reached from `revokeFamilyHalf` | `WHERE action='family.revocation_failed'` (reuse detected, family could not be revoked — still live) |
| `family.denylist_failed` | `reuse_detection family path half` \| `code_reuse family path half` | `reportReuseHalfFailure` in `internal/services/token.go`, reached from `denylistFamilyJTIs` | `WHERE action='family.denylist_failed'` (the family's access-token JTIs could not be denylisted; additive to the family row above, never instead of it) |
| `token.introspected` | `jti issuing_client` (actor blank; `client_id` carries the *requesting* client, which is not always the token's owner) | `IntrospectToken` in `internal/services/introspection.go` | `WHERE action='token.introspected'` |
| `token.introspect_denied` | `reason [jti]` | `recordDenial` in `internal/services/introspection.go` | `WHERE action='token.introspect_denied' AND detail LIKE '%reason=caller_not_authorized_for_token%'` |
| `token.exchanged` | `jti sub subject_client actor_client type scopes` (basic) · `jti sub subject_client actor_client type=mint_dispatch resource scopes chain_kind via_link` (registry mint) · `jti sub subject_client actor_client type=broker_dispatch resource scopes chain_kind via_link` (registry broker) | `internal/services/token_exchange.go:462,1112,1431,1633,1692` | `WHERE action='token.exchanged' AND detail LIKE '%type=broker_dispatch%'` |
| `token.exchange_denied` | `reason` | `internal/services/token_exchange.go:638` | `WHERE action='token.exchange_denied' AND detail LIKE '%reason=invalid_subject_token%'` |
| `client_credentials.issued` | `jti scopes` | `internal/services/client_credentials.go:319` | `WHERE action='client_credentials.issued'` |
| `client_credentials.denied` | `reason` | `internal/services/client_credentials.go:380` | `WHERE action='client_credentials.denied' AND detail LIKE '%reason=invalid_client%'` |
| `jwt_bearer.issued` | `jti idp scopes` | `internal/services/jwt_bearer.go:468` | `WHERE action='jwt_bearer.issued'` |
| `jwt_bearer.denied` | `reason` | `internal/services/jwt_bearer.go:524` | `WHERE action='jwt_bearer.denied'` |
| `upstream.token.issued` | `provider resource scopes` | `internal/services/broker_issuer.go:345` | `WHERE action='upstream.token.issued' AND detail LIKE '%provider=github%'` |
| `broker_grant.created` | `provider grant_id version` | `internal/services/connect.go:360` | `WHERE action='broker_grant.created'` |
| `broker_grant.revoked` | `provider grant_id` | `internal/services/connect.go:442` | `WHERE action='broker_grant.revoked'` |
| `broker_grant.revoked_admin` | `id user_id broker_provider_id` | `internal/services/grant_admin.go:217` | `WHERE action='broker_grant.revoked_admin'` |
| `consent.granted` | `resource scopes` (or empty if no resource) | `internal/services/consent.go:288` | `WHERE action='consent.granted'` |
| `consent.denied` | `session` | `internal/services/consent.go:310` | `WHERE action='consent.denied'` |
| `consent_grant.revoked_admin` | `id user_id client_id resource_id` | `internal/services/grant_admin.go:159` | `WHERE action='consent_grant.revoked_admin'` |
| `client.registered` | `source=dcr` | `internal/services/dcr.go:167` | `WHERE action='client.registered'` |
| `client.created_admin` | `name` | `internal/services/admin.go:160` | `WHERE action='client.created_admin'` |
| `client.secret_rotated` | `(empty)` | `internal/services/admin.go:221` | `WHERE action='client.secret_rotated'` |
| `client.updated` | `(empty)` | `internal/services/admin.go:283` | `WHERE action='client.updated'` |
| `client.suspended` | `(empty)` | `internal/services/admin.go:345` | `WHERE action='client.suspended'` |
| `client.revoked` | `(empty)` | `internal/services/admin.go:370` | `WHERE action='client.revoked'` |
| `client.deleted` | `force` | `internal/services/admin.go:477` | `WHERE action='client.deleted'` |
| `user.created` | `email` | `internal/services/admin.go:676` | `WHERE action='user.created'` |
| `user.updated` | `user` | `internal/services/admin.go:739` | `WHERE action='user.updated'` |
| `user.deleted` | `user force` | `internal/services/admin.go:799` | `WHERE action='user.deleted'` |
| `user.disabled` | `user` | `internal/services/admin.go:829` | `WHERE action='user.disabled'` |
| `user.force_logout` | `user revoked` | `internal/services/admin.go:913` | `WHERE action='user.force_logout'` |
| `user.login` | `(empty)` | `internal/services/user_auth.go` (`Authenticate`) | `WHERE action='user.login'` |
| `user.login_failed` | `reason` (`user_not_found` \| `user_disabled` \| `user_not_local` \| `invalid_credentials` \| `unusable_stored_hash`), `email` (quoted). **`actor_id` is set** — see the note below | `internal/services/user_auth.go` (`denyLogin`) | `WHERE action='user.login_failed'` |
| `auth.locked_out` | `until email` (email quoted — it is form input) | `api/public/oauth/login.go` (`recordLockout`) | `WHERE action='auth.locked_out'` |
| `user.oidc_login` | `(empty)` | `internal/services/oidc.go:146` | `WHERE action='user.oidc_login'` |
| `user.oidc_login_failed` | `code exchange failed` \| `user disabled` | `internal/services/oidc.go:65,109` | `WHERE action='user.oidc_login_failed'` |
| `resource.created` | `id slug` | `internal/services/resource_admin.go:233` | `WHERE action='resource.created'` |
| `resource.patched` | `id slug fields` | `internal/services/resource_admin.go:398` | `WHERE action='resource.patched' AND detail LIKE '%fields=scope_catalog%'` |
| `resource.deleted` | `id slug [cascaded_links]` | `internal/services/resource_admin.go:495` | `WHERE action='resource.deleted'` |
| `resource.policy.exchange.allowed_client.added` | `(see emit site for exact key list)` | `internal/services/resource_admin.go:627` | `WHERE action='resource.policy.exchange.allowed_client.added'` |
| `resource.policy.exchange.allowed_client.removed` | `(see emit site)` | `internal/services/resource_admin.go:682` | `WHERE action='resource.policy.exchange.allowed_client.removed'` |
| `resource.policy.connect.allowed_return_url.added` | `(see emit site)` | `internal/services/resource_admin.go:753` | `WHERE action='resource.policy.connect.allowed_return_url.added'` |
| `resource.policy.connect.allowed_return_url.removed` | `(see emit site)` | `internal/services/resource_admin.go:814` | `WHERE action='resource.policy.connect.allowed_return_url.removed'` |
| `resource.policy.runtime.client.added` | `(see emit site)` | `internal/services/resource_admin.go:969` | `WHERE action='resource.policy.runtime.client.added'` |
| `resource.policy.runtime.client.removed` | `(see emit site)` | `internal/services/resource_admin.go:1024` | `WHERE action='resource.policy.runtime.client.removed'` |
| `broker_provider.created` | `id slug` | `internal/services/broker_provider_admin.go:148` | `WHERE action='broker_provider.created'` |
| `broker_provider.patched` | `id slug fields` | `internal/services/broker_provider_admin.go:233` | `WHERE action='broker_provider.patched'` |
| `broker_provider.deleted` | `id` | `internal/services/broker_provider_admin.go:265` | `WHERE action='broker_provider.deleted'` |
| `fronting_link.created` | `source target scopes` | `internal/services/fronting.go:170` | `WHERE action='fronting_link.created'` |
| `fronting_link.patched` | `source target scopes` | `internal/services/fronting.go:220` | `WHERE action='fronting_link.patched'` |
| `fronting_link.deleted` | `source target` | `internal/services/fronting.go:244,371` | `WHERE action='fronting_link.deleted'` |
| `issuance.revoked_admin` | `id subject_user_id client_id resource_id` | `internal/services/issuance_admin.go:214` | `WHERE action='issuance.revoked_admin'` |

> **`user.login_failed` carries an `actor_id` that the failed request did not
> authenticate as.** When the submitted address resolves to an account, the row
> names that account's user id; when it resolves to nothing, `actor_id` is empty.
> Both are deliberate — `actor_id` is contracted as a real user id, and there is
> no id to name for an address nobody owns — but the consequence is worth
> knowing before you build forensics on it:
>
> - An unauthenticated `POST /login` writes a row against **someone else's**
>   indexed `actor_id`. A per-actor query (`?actor_id=`) therefore returns rows
>   an attacker caused, not only actions that account took. Read
>   `user.login_failed` as *"someone tried to log in as this account"*, never as
>   *"this account did something"*.
> - The volume a third party can add to one account's timeline is bounded by the
>   auth-failure lockout, which caps failures per identity per source address.
>   An attacker with many source addresses raises that ceiling.
> - The opposite gap matters too: probes against addresses that resolve to
>   nothing carry no `actor_id`, so a per-actor query cannot see enumeration
>   sweeps at all. Query those by `action` and `reason=user_not_found` instead.

### `token.introspect_denied` reasons

Every non-successful introspection records one row. The `reason` value says which
check refused, and `jti` is present only once the token has been parsed — so its
absence marks a request that failed before the token was understood.

| `reason` | Meaning |
| --- | --- |
| `client_not_found` | *(not recorded — see below)* No client matched the presented `client_id`. |
| `public_client` | *(not recorded — see below)* The caller has no secret. Introspection accepts confidential clients only (RFC 6749 §2.3). |
| `missing_client_secret` | *(not recorded — see below)* The caller sent no `client_secret`. |
| `invalid_client_secret` | The caller sent a `client_secret` that did not verify. |
| `client_not_active` | The caller is suspended or revoked. Recorded only after its secret verified, so it is not a status oracle. |
| `invalid_token` | Signature, issuer, `exp` or `nbf` check failed. Note this covers an ordinary expired token as well as an unparseable one, so it is not by itself a sign of probing. |
| `caller_not_authorized_for_token` | The caller neither issued the token nor is authorized to act AS a Resource the token names in `aud`. **This is the probing signal**; pair it with `client_id` to see who is asking. |
| `ambiguous_runtime_binding` | Two Resources answer to one slug or URI in the token's `aud`, so the AS will not guess which was meant. An operator mistake, not a caller one — kept apart from the probing signal so a misconfiguration does not read as a scan. |
| `token_revoked` / `machine_token_revoked` | The token's `jti` is revoked. |
| `issuing_client_inactive` | The client the token was issued to is suspended, revoked or gone. |
| `subject_inactive` | The user the token represents is disabled or gone. |

The client-authentication reasons are the ones a caller can trigger without
holding a valid token, so a rising rate on them is the shape of a scan. Note
that no `ip` is populated on these events, so `client_id` is the only
attribution a row carries.

Six outcomes are deliberately **not** recorded.

Three are the AS failing to decide rather than the caller failing to qualify: a
JWKS that could not be assembled, a revocation store that errored, and a resource
lookup that failed. None of them is a verdict on the caller, and during such an
outage every call takes that path — so auditing them would bury the probing
signal under an incident and amplify writes just as the database is least able
to absorb them. All three surface as an error/warn log and in the
`authserver_introspection_total{result="inactive"}` metric instead.

The other three are the client-authentication refusals a caller reaches
**without proving a credential**: an unrecognized `client_id`, a public client,
and an omitted `client_secret`. Audit writes are synchronous, so recording those
would let an anonymous loop drive one indexed `INSERT` per request. A public
`client_id` is no protection — it travels in the authorize URL and in browser
redirects — so an attacker who has seen one could aim the writes at a chosen
client's trail rather than merely at the table. They surface as a debug log and
in the `result="error"` metric.

The two client-authentication refusals that *are* recorded cost the caller
something: `invalid_client_secret` pays a full secret comparison, and
`client_not_active` is reached only once that secret verified.

## Constants not yet wired to an emit site

These action constants are declared in [`internal/domain/audit/entity.go`](../../internal/domain/audit/entity.go) but are not yet referenced by a production emit site (they are reserved for future wiring or are emitted only by tests). They are listed here so consumers of the audit log do not assume they will appear:

- `auth.denied`
- `key.rotated`
- `upstream.token.refreshed`
- `dcr.mode_updated`

## See also

- Schema: [`audit_events` table](../../migrations/postgres/) (Postgres) / [`audit_events` table](../../migrations/sqlite/) (SQLite).
- Query API: [`GET /admin/audit`](http-api.md#http-admin-audit-list).
- Domain entity: [`internal/domain/audit/entity.go`](../../internal/domain/audit/entity.go).
