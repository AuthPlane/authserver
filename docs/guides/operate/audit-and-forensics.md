# Audit & forensics — reconstruct what happened
*Context: this is part of [Guides — Operate](README.md). Start with the primer if you haven't.*

Every security-relevant action emits a row in `audit_events`. This recipe shows how to query the trail by action, actor, client, and time window; how to decode the `detail` string each emit site produces; and how to assemble multi-row stories (delete-then-reconnect, exchange chains, family revocations).

## What you'll achieve in 10 minutes

- Run targeted audit queries by action / actor / client / time.
- Decode the `detail` key=value string for the common emit sites.
- Pull a forensic export into JSON for an incident report.

## Prereqs

- `AUTHPLANE_ADMIN_API_KEY` exported in your shell.
- `jq` installed for JSON post-processing.
- Direct DB access (`psql` / `sqlite3`) only for queries the HTTP filter cannot express. See the schema column reference below.

## The audit_events schema

The canonical schema lives in `migrations/sqlite/001_initial.up.sql:139` (and the equivalent `migrations/postgres/001_initial.up.sql`). Eight columns:

| Column | Type | Meaning |
|---|---|---|
| `id` | TEXT (UUID v7) | Primary key, monotonic. |
| `action` | TEXT | Canonical action name (see catalog below). |
| `actor_id` | TEXT | User ID, client ID, or `"admin"` / `"system"`. May be empty. |
| `client_id` | TEXT | OAuth client involved. May be empty. |
| `ip` | TEXT | Source IP at the HTTP boundary. May be empty. |
| `detail` | TEXT | Human-readable key=value pairs (per emit site). |
| `trace_id` | TEXT | OTel trace ID for correlation. May be empty. |
| `created_at` | TEXT (RFC 3339) | UTC. |

Three indexes are pre-built (`idx_audit_events_created_at`, `idx_audit_events_action`, `idx_audit_events_actor_id`, plus a partial `idx_audit_events_client_id`) so the four filters below are O(log N).

## Canonical action names

Full list lives in the `Action` constants in `internal/domain/audit/entity.go` (and in [`audit-events.md`](../../reference/audit-events.md)). The ones you query most often:

| Action | Emitted by | When |
|---|---|---|
| `token.issued` | `exchangeCode` in `internal/services/token.go` | First leg of auth-code flow lands a JWT. |
| `token.refreshed` | `refreshToken` in `internal/services/token.go` | Refresh-token rotation succeeded. |
| `token.revoked` | `RevokeToken` in `internal/services/revocation.go` | `POST /oauth/revoke` accepted. |
| `token.exchanged` | `internal/services/token_exchange.go:463` | RFC 8693 exchange minted a token. |
| `token.exchange_denied` | `internal/services/token_exchange.go:639` | Exchange refused (scope, allowlist, policy). |
| `auth_code.reused` | `handleCodeReuse` in `internal/services/token.go` | Authorization code replayed. Written on every replay, including the ones that revoke nothing. |
| `family.revoked` | `revokeFamilyHalf` in `internal/services/token.go` | Refresh-token **or** authorization-code reuse detected → family burnt. The detail prefix says which. |
| `family.revocation_failed` | `revokeFamilyHalf` in `internal/services/token.go` | Reuse detected but the family could **not** be revoked — it is still live; go to the [incident runbook](incident-runbook.md#incident-refresh-token-reuse-burst). |
| `family.denylist_failed` | `denylistFamilyJTIs` in `internal/services/token.go` | The family's access-token JTIs could not be denylisted; they pass introspection / exchange until `exp`. Always next to a `family.revoked` or `family.revocation_failed` row for the same family. |
| `client.registered` | DCR landing | New OAuth client created via DCR. |
| `client.created_admin` | Admin path | New client created via the admin API / CLI. |
| `client.suspended` / `client.revoked` | Admin path | State change on a client. |
| `consent.granted` / `consent.denied` | Consent UI | User decision on the consent screen. |
| `consent_grant.revoked_admin` | Admin path | Operator revoked a grant. |
| `broker_grant.created` / `broker_grant.revoked` | User self-service | `/connect/{provider}` flow. |
| `broker_grant.revoked_admin` | Admin path | Operator-forced upstream revoke. |
| `upstream.token.issued` | `internal/services/broker_issuer.go:346` | AS vended an upstream-format access token to an MCP. |
| `key.rotated` | `admin key rotate` | Signing key rotated. |
| `issuance.revoked_admin` | Admin path | Per-token revocation. |
| `user.force_logout` | Admin path | Every family for a user burnt. |
| `dcr.mode_updated` | Admin path | DCR runtime setting changed. |
| `fronting_link.created` / `…patched` / `…deleted` | Admin path | Cross-Mint fronting mutations. |
| `resource.policy.exchange.allowed_client.added` / `…removed` | Admin path | Per-field policy mutation (operator intent captured). |

## Steps

### 1. Time-windowed action query

HTTP route: [`GET /admin/audit`](../../reference/http-api.md#http-admin-audit-list).

```bash
# All exchanges denied in the last hour
curl -fsS "http://localhost:9001/admin/audit?action=token.exchange_denied&since=$(date -u -v-1H '+%Y-%m-%dT%H:%M:%SZ')&limit=200" \
  -H "Authorization: Bearer $AUTHPLANE_ADMIN_API_KEY" \
  | jq '.events[] | {at: .created_at, client: .client_id, detail}'
```

### 2. Drill into one user

```bash
# Everything a single user touched in the last 24h
curl -fsS "http://localhost:9001/admin/audit?actor_id=$USER_ID&since=$(date -u -v-1d '+%Y-%m-%dT%H:%M:%SZ')&limit=500" \
  -H "Authorization: Bearer $AUTHPLANE_ADMIN_API_KEY" \
  | jq '.events[] | {at: .created_at, action, client_id, detail}'
```

### 3. Drill into one client

```bash
# Every action where this client was the OAuth client
curl -fsS "http://localhost:9001/admin/audit?client_id=$CLIENT_ID&limit=500" \
  -H "Authorization: Bearer $AUTHPLANE_ADMIN_API_KEY" \
  | jq '.events | group_by(.action) | map({action: .[0].action, count: length})'
```

### 4. Decode the detail string

Each emit site stores key=value pairs in `detail`. Examples from source:

- **`token.issued`** (`exchangeCode` in `internal/services/token.go`) → `family=<family_id>`
- **`token.refreshed`** (`refreshToken` in `internal/services/token.go`) → `family=<family_id>`
- **`auth_code.reused`** (`handleCodeReuse` in `internal/services/token.go`) → `code_reuse session=<auth_session_id> verifier=valid|invalid` — `actor_id` / `client_id` name the user and client the code was issued to; the `client_id` the replayer presented is on the `token_issue.denied` row of the same request
- **`family.revoked`** (`revokeFamilyHalf` in `internal/services/token.go`) → `reuse_detection family=<family_id>` from refresh-token reuse, `code_reuse family=<family_id>` from authorization-code reuse
- **`family.revocation_failed`** (`reportReuseHalfFailure`, same file) → `reuse_detection family=<family_id> path=reuse half=family`, or `code_reuse family=<family_id> path=code_reuse half=family` — reuse was detected but the family could not be revoked; it is still live
- **`family.denylist_failed`** (`reportReuseHalfFailure`, same file) → `reuse_detection family=<family_id> path=reuse half=jti`, or `code_reuse family=<family_id> path=code_reuse half=jti` — the family's access-token JTIs could not be denylisted; written next to whichever family row the detection left
- **`token.exchanged` (mint dispatch)** (`internal/services/token_exchange.go:1115`) → `jti=… sub=… subject_client=… actor_client=… type=mint_dispatch resource=… scopes=… chain_kind=… via_link=…`
- **`token.exchanged` (broker dispatch)** (`internal/services/token_exchange.go:1434`) → `issuance_id=… sub=… subject_client=… type=broker_dispatch resource=… provider=… scopes=…`
- **`token.exchanged` (fronted broker)** (`internal/services/token_exchange.go:1636`) → `… type=broker_dispatch resource=… scopes=… chain_kind=fronted via_link=… target_kind=broker issuance_id=…`
- **`token.revoked` (machine)** (`tryRevokeMachineToken` in `internal/services/revocation.go`) → `machine_token jti=<jti>`
- **`token.revoked` (family)** (`RevokeToken` in `internal/services/revocation.go`) → `family=<family_id>`

The detail string is plain text — grep / `jq -r` / `awk -F= …` all work.

### 5. Forensic export to JSON

Pull everything for an incident window and dump to a file:

```bash
SINCE='2026-05-13T00:00:00Z'
UNTIL='2026-05-14T00:00:00Z'
OFFSET=0
> incident.ndjson
while : ; do
  page=$(curl -fsS "http://localhost:9001/admin/audit?since=$SINCE&until=$UNTIL&limit=500&offset=$OFFSET" \
    -H "Authorization: Bearer $AUTHPLANE_ADMIN_API_KEY")
  n=$(echo "$page" | jq '.events | length')
  [ "$n" = 0 ] && break
  echo "$page" | jq -c '.events[]' >> incident.ndjson
  OFFSET=$((OFFSET + n))
done
wc -l incident.ndjson
```

### 6. Direct SQL (when the HTTP filter is not enough)

The HTTP API filters by `action`, `actor_id`, `client_id`, `since`, `until`. Anything else — substring match on `detail`, JOIN onto `issuances`, etc. — needs SQL.

```sql
-- All exchanges of a specific JTI as the SUBJECT token (parses detail)
SELECT created_at, actor_id, client_id, detail
FROM audit_events
WHERE action = 'token.exchanged'
  AND detail LIKE '%jti=' || :subject_jti || '%'
ORDER BY created_at;

-- Every action against issuances tied to one resource
SELECT a.created_at, a.action, a.actor_id, a.client_id, a.detail
FROM audit_events a
WHERE a.action IN ('token.issued','token.exchanged','issuance.revoked_admin','token.revoked')
  AND a.created_at BETWEEN :since AND :until
ORDER BY a.created_at;

-- Family-reuse events in the last 7 days (correlate with token_families table)
SELECT created_at, detail
FROM audit_events
WHERE action = 'family.revoked'
  AND created_at > datetime('now', '-7 days');
```

## Common forensic patterns

### "Find every token I minted for user X in the last 24h"

```bash
curl -fsS "http://localhost:9001/admin/audit?action=token.issued&actor_id=$USER_ID&since=$(date -u -v-1d '+%Y-%m-%dT%H:%M:%SZ')" \
  -H "Authorization: Bearer $AUTHPLANE_ADMIN_API_KEY" | jq '.events[] | {created_at, client_id, family: (.detail|capture("family=(?<f>[^ ]+)").f)}'
```

### "All upstream-broker dispatches in the last 24h"

```bash
curl -fsS "http://localhost:9001/admin/audit?action=upstream.token.issued&since=$(date -u -v-1d '+%Y-%m-%dT%H:%M:%SZ')" \
  -H "Authorization: Bearer $AUTHPLANE_ADMIN_API_KEY" | jq '.events[] | {created_at, actor_id, client_id, detail}'
```

### "Was this token family ever reused?"

```bash
for action in family.revoked family.revocation_failed family.denylist_failed; do
  curl -fsS "http://localhost:9001/admin/audit?action=$action&limit=500" \
    -H "Authorization: Bearer $AUTHPLANE_ADMIN_API_KEY" | jq --arg f "$FAMILY_ID" --arg a "$action" '.events[] | select(.detail | contains($f)) | {action: $a, created_at, detail}'
done
```

Every detection leaves exactly one **family** row: `family.revoked` means the family was revoked; `family.revocation_failed` means it was not and **is still live** — go to the [incident runbook](incident-runbook.md#incident-refresh-token-reuse-burst). A `family.denylist_failed` row next to either means the family's already-issued access tokens were not denylisted and pass introspection / exchange until `exp`; it is additive, so `family.revoked + family.revocation_failed` still counts detections. Either row implies `authserver_refresh_token_reuse_total` (canonical: `RefreshTokenReuse` in `internal/observability/metrics.go`) also fired — confirm with Prometheus. Audit rows are written best-effort — a store failure logs the full event and increments `authserver_audit_events_dropped_total` (`AuditEventsDropped` in `internal/observability/metrics.go`) — so a metric count higher than the row count points at dropped events, not at undetected reuse.

### "Reconstruct a delete-then-reconnect cycle"

Broker grants soft-delete and reuse the same row on reconnect. The audit trail is three rows for a delete-then-reconnect cycle:

1. `broker_grant.revoked_admin` — operator DELETE.
2. `broker_grant.created` — user reconnect (same row, fresh `version`).
3. `broker_grant.revoked` — any subsequent self-service revoke.

```bash
curl -fsS "http://localhost:9001/admin/audit?actor_id=$USER_ID&limit=500" \
  -H "Authorization: Bearer $AUTHPLANE_ADMIN_API_KEY" | jq '.events[] | select(.action | startswith("broker_grant."))'
```

### "Trace an exchange chain"

For multi-hop delegation, follow `subject_client` → `actor_client` across consecutive `token.exchanged` rows for one user. The `chain_kind` field (`direct` or `fronted`) and `via_link` (source→target slug pair) make fronting hops explicit.

## Verify

- The HTTP endpoint returns `200 OK` with a JSON envelope `{ "events": [...] }`.
- `wc -l` on the NDJSON export ≥ the number of mutations you ran since the window opened.
- Pair each suspicious audit row with its OTel trace using the `trace_id` column.

## What can go wrong

| Symptom | Likely cause | Fix |
|---|---|---|
| Query returns empty / fewer rows than expected | `since`/`until` window too narrow; UTC vs. local time mismatch | Widen the window; always pass `Z` suffix (UTC). |
| `429 Too Many Requests` on a paged export | Admin rate limit hit | Sleep between pages or raise `admin.requests_per_second` ([`docs/reference/configuration.md`](../../reference/configuration.md)). |
| `detail` field is empty for `token.exchange_denied` | Some denial paths only emit a `reason` — see `internal/services/token_exchange.go:1695` | Filter by `action` + correlate to the trace span; the span carries more attributes. |
| Can't find a known mutation in the audit log | Mutation happened on a different instance with a separate database; or the YAML-seed path doesn't audit | Confirm `storage.driver` is the same across instances; YAML-seeded rows on first-start are deliberately not audited. |
| `actor_id` is empty for `family.revoked` | Reuse detection fires without an authenticated actor; the family ID is the only identifier | Read the `detail` (`family=<id>`) and join against `token_families`. |
| `trace_id` is empty | Tracing disabled or sampler dropped the span | Enable tracing in [`observability` config](../../reference/configuration.md). |

## Runbook

| Question | Query shape |
|---|---|
| "Has anyone changed the DCR mode this week?" | `?action=dcr.mode_updated&since=…` |
| "Who suspended this client?" | `?action=client.suspended&client_id=…` |
| "Forensic JSON dump for ticket #N" | Page through `since=…&until=…` (Step 5). |
| "Show me every action this user took" | `?actor_id=…&limit=500` |
| "Refresh-token reuse this month?" | `?action=family.revoked&since=…` **plus** `?action=family.revocation_failed&since=…` — every detection writes exactly one of the two; the second set is the families that were still live. Cross-check with Prometheus `authserver_refresh_token_reuse_total`. |

## See also

- [Admin CLI → Audit query](admin-cli.md#recipe-audit-query-cli-equivalent) — the same query, scripted.
- [Incident runbook](incident-runbook.md) — when an audit row triggers a response.
- [Token design (operator view)](token-design-internals.md) — what each emit site means semantically.
- [`docs/reference/http-api.md`](../../reference/http-api.md) — generated HTTP reference; [`docs/reference/audit-events.md`](../../reference/audit-events.md) — full catalog of audit actions.
- [Deploy → Observability](../deploy/observability-prometheus-otel.md) — wire `trace_id` to your tracing backend.
