# Incident runbook — five scenarios, alert to recovery
*Context: this is part of [Guides — Operate](README.md). Start with the primer if you haven't.*

This page lists five named incidents, each with the same Symptoms / Detect / Contain / Eradicate / Recover / Post-incident shape. Run the **Contain** column within 15 minutes of detection — the rest can follow business hours.

## What you'll achieve in 10 minutes (per incident)

- Recognise the signal (Symptoms).
- Confirm with a deterministic query (Detect).
- Stop the bleed without taking the service down (Contain).
- Burn the compromised credential / family / key (Eradicate).
- Bring users back online (Recover).
- File the postmortem inputs (Post-incident).

## Prereqs

- `AUTHPLANE_ADMIN_API_KEY` exported.
- Prometheus / OTel scrape pointed at the AS (see [Deploy → Observability](../deploy/observability-prometheus-otel.md)).
- An alerting rule pack subscribed to the metric thresholds called out below.

---

## Incident: signing-key compromise

A signing key (or HSM session) was exposed.

### Symptoms
- Vault Transit audit log shows unexpected `transit/sign/<key_name>` calls.
- Tokens with valid signatures appear from IPs that have never seen this AS.
- A backup of `data/keys/` was found outside its expected boundary.

### Detect
```bash
# Recent key.rotated rows (none expected unless you rotated)
curl -fsS "http://localhost:9001/admin/audit?action=key.rotated&limit=10" \
  -H "Authorization: Bearer $AUTHPLANE_ADMIN_API_KEY" | jq '.events'
```

Prometheus: `rate(authserver_tokens_issued_total[5m])` (canonical: `internal/observability/metrics.go:105`) spikes anomalously, or `authserver_key_rotation_total` (canonical: `internal/observability/metrics.go:210`) increments without an operator action.

### Contain
1. Rotate immediately. Every new JWT signs under a fresh `kid`:
   ```bash
   authserver admin key rotate
   ```
2. If the compromised key was on `keyfile`, drop `data/keys/rotated-<old>.pem` after step 4. If on Vault Transit, disable the old key version in Vault.
3. Force resource servers to re-fetch JWKS — restart them or wait one JWKS TTL.

See [Key rotation](key-rotation.md) for the full procedure.

### Eradicate
- Audit every issuance signed by the compromised `kid`. The HTTP API does not filter by `kid`, so query directly:
  ```sql
  SELECT id, subject_user_id, client_id, resource_id, issued_at
  FROM issuances WHERE jti IN (
    -- list of jtis you suspect; or scope to expires_at > now() if you must blanket-revoke
  );
  ```
- Revoke each issuance: `authserver admin issuance revoke --id <ID>`.
- Force-logout affected users: `authserver admin user force-logout --id <USER_ID>` (canonical action: `user.force_logout`).

### Recover
- Confirm `/.well-known/jwks.json` carries the new `kid` and resource servers accept new tokens.
- Re-enable user logins; old refresh tokens are unaffected (opaque, not JWTs), but revoked families will require re-auth.

### Post-incident
- Document: rotation timestamp, old/new `kid`, scope of revoked issuances.
- File: how the key left its boundary; was the storage backend appropriate (consider migrating to `vault_transit` if you were on `keyfile`).
- Tighten: shorten rotation cadence; add an alert on unexpected `key.rotated` audit rows.

---

## Incident: admin API key leak

`AUTHPLANE_ADMIN_API_KEY` was committed to a repo, posted in a chat, or left on a debug log.

### Symptoms
- The key shows up in a secret-scanning alert (GitHub, GitLab, custom).
- Anomalous admin mutations in `audit_events` from an IP / user-agent you do not recognise.
- `client.created_admin`, `dcr.mode_updated`, or `client.deleted` rows you cannot attribute to a known operator.

### Detect
```bash
# Suspicious admin actions in the last hour
curl -fsS "http://localhost:9001/admin/audit?action=client.created_admin&since=$(date -u -v-1H '+%Y-%m-%dT%H:%M:%SZ')" \
  -H "Authorization: Bearer $AUTHPLANE_ADMIN_API_KEY" | jq '.events[] | {created_at, actor_id, ip, detail}'

# Any DCR mode flip
curl -fsS "http://localhost:9001/admin/audit?action=dcr.mode_updated&since=$(date -u -v-1d '+%Y-%m-%dT%H:%M:%SZ')" \
  -H "Authorization: Bearer $AUTHPLANE_ADMIN_API_KEY" | jq '.events'
```

### Contain
1. Generate a fresh key and atomically swap it:
   ```bash
   NEW_KEY="$(openssl rand -hex 32)"
   # Update YAML or env source of truth
   ```
2. Restart the AS (or hot-reload if your deploy supports it). The old key now fails at the admin auth middleware.
3. Block the source IP at the network layer if you can identify it from the `ip` column.

### Eradicate
- Inventory every admin mutation since the leak window opened (Step "Detect" — widen `since` to leak time).
- Revert hostile mutations:
  - New clients (`client.created_admin`): `authserver admin client delete --id <CLIENT_ID> --force`.
  - Mode changes (`dcr.mode_updated`): `authserver admin dcr set --mode <previous>`.
  - New users (`user.created`): `authserver admin user delete --id <USER_ID>`.

### Recover
- Push the new key to your secret store and re-deploy operator credentials.
- Confirm `/admin/stats` reachable from your trusted bastion.

### Post-incident
- Move secret to a managed store (Vault, AWS SM, sealed-secrets) if it was env-only.
- Add a network policy: `:9001` reachable from operator subnet only.
- Subscribe an alert on `client.created_admin`, `dcr.mode_updated`, `client.deleted` from unknown actor_ids.

---

## Incident: refresh-token reuse burst

A wave of refresh-token reuse detections — possible token-theft campaign or buggy client.

### Symptoms
- `authserver_refresh_token_reuse_total` (canonical: `RefreshTokenReuse` in `internal/observability/metrics.go`) rate is non-zero for more than 5 minutes.
- Users report "logged out unexpectedly" support tickets.
- `family.revoked` rows accumulate (canonical action: `ActionFamilyRevoked` in `internal/domain/audit/entity.go`).
- `authserver_revocation_failures_total{path="reuse"}` is non-zero (`RevocationFailures` in `internal/observability/metrics.go`): `half="family"` → the family is **still active** (log `failed to revoke family during reuse detection`); `half="jti"` → the family's access tokens introspect as active until `exp` (log `JTI denylist failed during reuse detection`, audit row `family.denylist_failed`; each half reports its own failure, so when both failed both ERROR lines and both rows appear for the same `family_id` and both alerts fire together). Outcome table: [token design → reuse detection](token-design-internals.md#refresh-token-rotation-and-reuse-detection).

### Detect
```bash
# All family revocations in the last hour
curl -fsS "http://localhost:9001/admin/audit?action=family.revoked&since=$(date -u -v-1H '+%Y-%m-%dT%H:%M:%SZ')&limit=500" \
  -H "Authorization: Bearer $AUTHPLANE_ADMIN_API_KEY" | jq '.events[] | {created_at, detail}'
# Detections whose revocation failed — these families are still live
curl -fsS "http://localhost:9001/admin/audit?action=family.revocation_failed&since=$(date -u -v-1H '+%Y-%m-%dT%H:%M:%SZ')&limit=500" \
  -H "Authorization: Bearer $AUTHPLANE_ADMIN_API_KEY" | jq '.events[] | {created_at, detail}'
# Families whose access tokens were not denylisted — they introspect as active until exp
curl -fsS "http://localhost:9001/admin/audit?action=family.denylist_failed&since=$(date -u -v-1H '+%Y-%m-%dT%H:%M:%SZ')&limit=500" \
  -H "Authorization: Bearer $AUTHPLANE_ADMIN_API_KEY" | jq '.events[] | {created_at, detail}'
```

Prometheus:
```
sum(rate(authserver_refresh_token_reuse_total[5m])) > 0.1
```

### Contain
1. If `RefreshReuseRevocationFailed` fired (`half="family"`): the family in the `failed to revoke family during reuse detection` log line (`family_id`) is **still live**. Revoke it directly, before the rest of the triage:
   ```bash
   curl -fsS -X DELETE -H "Authorization: Bearer $AUTHPLANE_ADMIN_API_KEY" \
     "http://localhost:9001/admin/tokens/$FAMILY_ID"        # family id → revokes the family + denylists its JTIs
   ```
   If that fails too, the database is the incident — the same failure hits every revocation until it is fixed. Once you know the user, `authserver admin user force-logout --id $USER_ID` burns every family they own.

   If only `RefreshReuseDenylistFailed` fired (`half="jti"`): the family is already dead; run the same `DELETE` to retry the denylist (the insert is idempotent), or accept that its access tokens expire on their own within `exp` (15 min default).

   A `204` confirms the family row and its refresh tokens are revoked; on this admin path the JTI-denylist half is still best-effort (a failure there is logged, not returned), so before standing down, introspect one of the family's recent access tokens and confirm it reports `active: false`.
2. If one client dominates the burst: suspend it.
   ```bash
   authserver admin client list --status active --limit 200      # find the culprit
   curl -X PATCH -H "Authorization: Bearer $AUTHPLANE_ADMIN_API_KEY" \
     "http://localhost:9001/admin/clients/$CLIENT_ID/suspend"
   ```
3. If users are concentrated under one identity provider: pause that IDP at your enterprise IdP layer.

### Eradicate
- Force-logout affected users (the family is already burnt; this also revokes any other family they own):
  ```bash
  authserver admin user force-logout --id $USER_ID
  ```
- Audit each `family.revoked` row's `detail` (`reuse_detection family=<id>`) and join to `token_families` for the originating client+user.

### Recover
- Affected users re-authenticate. With DPoP enabled, the replayed token was already useless without the proof key — log and move on.
- Reactivate the suspended client only after the bug (or compromise) is closed.

### Post-incident
- Buggy client? Patch the client SDK to never persist refresh tokens that another instance has consumed.
- Real theft? Recommend [DPoP](../../concepts/dpop-and-proof-of-possession.md) for that client; sender-constrained tokens defeat replay.
- Alert: page on `rate(authserver_refresh_token_reuse_total[5m]) > 0` for any contiguous 5-minute window.

---

## Incident: upstream broker-secret leak

`CONNECTOR_*_SECRET` (the OAuth client secret you registered with GitHub/Google/Slack/etc.) leaked.

### Symptoms
- Secret-scanning alert from your code host.
- Provider security team contact.
- Anomalous `upstream.token.issued` rows (canonical: `internal/domain/audit/entity.go:60`) for users who never used the integration.

### Detect
```bash
# Upstream issuances in the last 24h
curl -fsS "http://localhost:9001/admin/audit?action=upstream.token.issued&since=$(date -u -v-1d '+%Y-%m-%dT%H:%M:%SZ')&limit=500" \
  -H "Authorization: Bearer $AUTHPLANE_ADMIN_API_KEY" | jq '.events[] | {created_at, actor_id, client_id, detail}'
```

Prometheus: `rate(authserver_upstream_token_issued_total[5m])` (canonical: `internal/observability/metrics.go:224`) — spike for one provider.

### Contain
1. **Rotate the upstream secret at the provider.** GitHub: regenerate the OAuth app secret. Google: rotate the OAuth client. Slack: regenerate the app credentials.
2. Update the env var that the provider's `client_secret_ref` points at (e.g. `CONNECTOR_GITHUB_SECRET`). The secret value is **never stored in the AS database** — only the env-var **name** lives in `broker_providers.config_data` — so updating the env source and restarting is sufficient.
3. Restart the AS.

### Eradicate
- Existing upstream access tokens you already vended are NOT AS-revocable (the AS does not own the upstream's revocation surface). Treat them as compromised until the upstream's natural TTL expires.
- For maximum safety, revoke all broker grants for this provider:
  ```bash
  # Find broker grants tied to the provider, then revoke each
  authserver admin grant list-user-grants --user $USER_ID
  authserver admin grant revoke-broker --id $GRANT_ID
  ```
  Note: revoking a broker grant is forensic-only; it stops future AS-side vending but does not revoke tokens already in the agent's hands. Coordinate with the upstream for token-level revocation (e.g. GitHub's per-token revoke API).

### Recover
- Users will be prompted to re-connect on next use of the integration; the soft-delete + revival path (`broker_grant.created` after `broker_grant.revoked_admin`) handles this cleanly.

### Post-incident
- Move provider secrets to a managed store if they were env-only.
- Adopt provider-side IP allowlists where supported.
- Watch `authserver_connection_connect_total` (canonical: `internal/observability/metrics.go:241`) for a flood of reconnects in the recovery window — that's expected.

---

## Incident: suspected DPoP-replay attack

A bearer-of-DPoP-token attack — replaying a stolen DPoP proof with a stolen token.

### Symptoms
- `authplane_dpop_proofs_rejected_total` (canonical: `internal/observability/metrics.go:270`) rate climbs.
- Operators see `nonce`-mismatch or `jti`-collision messages in the structured log.
- Customer reports of "weird tool calls" from one user's MCP server.

### Detect
```bash
# AS-side token issuance for the affected user; correlate with their reported window
curl -fsS "http://localhost:9001/admin/audit?actor_id=$USER_ID&action=token.issued&since=$(date -u -v-1d '+%Y-%m-%dT%H:%M:%SZ')" \
  -H "Authorization: Bearer $AUTHPLANE_ADMIN_API_KEY" | jq '.events'
```

Prometheus:
```
sum by (reason) (rate(authplane_dpop_proofs_rejected_total[5m])) > 0
```

The MCP server itself is the primary enforcement point for DPoP — the AS only checks the proof at the token endpoint. Pull the MCP server's structured logs for the replay window in parallel.

### Contain
1. Force-logout the affected user:
   ```bash
   authserver admin user force-logout --id $USER_ID
   ```
2. Revoke individual issuances tied to the suspect window (`admin issuance list --user --jti --since` then `admin issuance revoke`).
3. If a specific client is implicated, suspend it (`PATCH /admin/clients/$CLIENT_ID/suspend`).

### Eradicate
- Confirm the affected user's keypair was indeed stolen (device theft, browser exfil). Push them to re-enroll their DPoP key.
- For the suspect client, force a fresh key on the next session by reactivating after suspension.

### Recover
- User re-authenticates; the new DPoP key produces a fresh `cnf.jkt` on every issued token.
- Reactivate the client once the user is back online.

### Post-incident
- Confirm DPoP is mandatory (not optional) for high-sensitivity clients; see [DPoP and proof of possession](../../concepts/dpop-and-proof-of-possession.md).
- Alert: `rate(authplane_dpop_proofs_rejected_total[5m]) > 0.1` for ≥ 5 minutes.
- Consider shortening `dpop.nonce_ttl` (currently 60s — see [`docs/reference/configuration.md`](../../reference/configuration.md)) for the affected resource server family.

---

## What can go wrong (cross-cutting)

| Symptom | Likely cause | Fix |
|---|---|---|
| `admin key rotate` succeeds but resource servers still reject new tokens | Verifier cache TTL not yet elapsed | Wait one TTL (default 5 min) or restart verifiers. |
| `force-logout` reports 0 families revoked but user is still logged in | User holds a stale access token (still in JWT TTL) | Revoke per-issuance, or wait for token TTL (`dcr.default_token_expiry`, default 15m). |
| `revoke-broker` does not stop the agent from using the upstream | Already-vended upstream tokens are not AS-revocable | Coordinate with the upstream provider's revocation API. |
| Suspended client's tokens still work | Suspend blocks new issuance; existing tokens valid until `exp` | Revoke at issuance level with `admin issuance revoke` for each `JTI`. |
| Audit log misses the mutation you ran | The mutation hit a different instance / database; or you ran against a config that doesn't audit | Confirm `storage.driver` is shared; check `audit.enabled`. |

## Related

- [Audit & forensics](audit-and-forensics.md) — the queries above, deeper.
- [Key rotation](key-rotation.md) — the rotation procedure called out here.
- [Token design (operator view)](token-design-internals.md) — what gets revoked when.
- [Concepts → Threat model](../../concepts/threat-model.md) — the failure modes these incidents instantiate.
- [Deploy → Observability](../deploy/observability-prometheus-otel.md) — wire the Prometheus alerts.
