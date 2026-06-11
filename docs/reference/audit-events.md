<!-- Hand-maintained reference. Keep in sync with internal/domain/audit/entity.go. -->

# Audit events

Every state-changing operation in the authorization server emits an audit record via the [`audit.Service`](../../internal/services/audit.go). Each record carries an `Action` (one of the constants declared in [`internal/domain/audit/entity.go`](../../internal/domain/audit/entity.go)), an `ActorID` (user id, client id, or `"system"` / `"admin"`), a `ClientID`, a source IP, a free-form `Detail` string (canonically `key=value key=value ...` so it is greppable), and the OTel trace id of the request that triggered the emit. This page is the authoritative catalog of every action name and the detail keys it carries.

The `Detail` column lists the keys you can expect to see in the canonical `key=value` payload. Optional keys are wrapped in square brackets. The `Source` column cites the emit site as `file:line` so you can verify the exact format string.

| Action | Detail keys | Emitted by | Example query |
| --- | --- | --- | --- |
| `token.issued` | `family` | `internal/services/token.go:272` | `WHERE action='token.issued'` |
| `token.refreshed` | `family` | `internal/services/token.go:429` | `WHERE action='token.refreshed'` |
| `token.revoked` | `family` \| `machine_token jti` \| `machine_jti` | `internal/services/revocation.go:138,193`, `internal/services/admin.go:611,632` | `WHERE action='token.revoked'` |
| `family.revoked` | `reuse_detection family` | `internal/services/token.go:695` | `WHERE action='family.revoked'` (refresh-token reuse alarm) |
| `token.introspected` | `(empty detail; actor blank, client_id carried)` | `internal/services/introspection.go:197` | `WHERE action='token.introspected'` |
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
| `user.login` | `(empty)` | `internal/services/user_auth.go:114` | `WHERE action='user.login'` |
| `user.login_failed` | `email` | `internal/services/user_auth.go:101` | `WHERE action='user.login_failed'` |
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

## Constants not yet wired to a service emit site

These action constants are declared in [`internal/domain/audit/entity.go`](../../internal/domain/audit/entity.go) but are not yet referenced by a production emit site (they are reserved for future wiring or are emitted only by tests). They are listed here so consumers of the audit log do not assume they will appear:

- `auth.denied`
- `auth.locked_out`
- `key.rotated`
- `upstream.token.refreshed`
- `dcr.mode_updated`

## See also

- Schema: [`audit_events` table](../../migrations/postgres/) (Postgres) / [`audit_events` table](../../migrations/sqlite/) (SQLite).
- Query API: [`GET /admin/audit`](http-api.md#http-admin-audit-list).
- Domain entity: [`internal/domain/audit/entity.go`](../../internal/domain/audit/entity.go).
