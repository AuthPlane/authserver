# Token design (operator view) — what to monitor, when things get revoked
*Context: this is part of [Guides — Operate](README.md). Start with the primer if you haven't.*

For the concept-level coverage of token claims, see [Concepts → Tokens and claims](../../concepts/tokens-and-claims.md). This page is the **operator's** view: which lifetimes are tunable, what gets revoked when, which metric to alert on, and how `cnf.jkt` propagates across exchange.

## What you'll achieve in 8 minutes

- Know which config knobs control each token's TTL and what each default is.
- Trace what gets revoked when a user/client/grant/key is touched.
- Wire the right Prometheus alert per token kind.

## Prereqs

- Read access to [`docs/reference/configuration.md`](../../reference/configuration.md) for the schema citations.
- Prometheus scraping `/metrics` (see [Deploy → Observability](../deploy/observability-prometheus-otel.md)).

## The five token kinds

| Token | Format | Default TTL | TTL config key | Stored server-side |
|---|---|---|---|---|
| Access token (user-bound) | JWT `at+jwt` | 15 min | [`dcr.default_token_expiry`](../../reference/configuration.md) | No (JTI optionally tracked) |
| Refresh token | Opaque random | 7 days (168h) | [`dcr.default_refresh_expiry`](../../reference/configuration.md) | Yes (SHA-256 hash + family row) |
| Machine token (client_credentials) | JWT `at+jwt` | 1 hour | [`client_credentials.token_expiry`](../../reference/configuration.md) | Yes (by JTI, for individual revoke) |
| Exchanged token (RFC 8693) | JWT `at+jwt` | 1 hour | [`token_exchange.token_expiry`](../../reference/configuration.md) | No (immutable `issuances` row) |
| Auth code | Opaque random | 10 min | Hard-coded | Yes (SHA-256 hash, single-use) |

Source-of-truth defaults: `internal/config/loader.go` (the `DefaultTokenExpiry`, `TokenExpiry` defaults). Wire-shape doc: [Concepts → Tokens and claims](../../concepts/tokens-and-claims.md).

## What gets revoked when

| Operator action | Immediate effect | Tokens that survive |
|---|---|---|
| `admin user force-logout` (`user.force_logout`) | Every token-family for the user → `revoked`; refresh tokens unusable | In-flight access tokens valid until `exp` (max 15 min default) |
| `admin client revoke` (`client.revoked`) | Client deactivated; existing families revoked | In-flight access tokens until `exp` |
| `admin client suspend` (`client.suspended`) | New issuance blocked | Every previously issued token until `exp`; refresh tokens still rotate |
| `admin grant revoke-consent` (`consent_grant.revoked_admin`) | Soft-delete grant; cascade revokes live Mint issuances for `(user, client, resource)` | A few in-flight tokens if cascade failed (audit row carries `cascade=failed`) |
| `admin grant revoke-broker` (`broker_grant.revoked_admin`) | Soft-delete broker grant; **no issuance cascade** | Already-vended upstream tokens (NOT AS-revocable) |
| `admin issuance revoke` (`issuance.revoked_admin`) | One issuance row marked revoked; future verifies against the JTI table fail (if introspection is enabled) | Any access tokens not yet checked against the JTI table; until `exp` if MCP only does local-verify |
| `POST /oauth/revoke` family path | Family revoked; all refresh tokens in the family invalid | In-flight access tokens until `exp` |
| `POST /oauth/revoke` machine-token JTI | That JTI marked revoked | None (machine tokens are revocable by JTI) |
| `admin key rotate` (`key.rotated`) | New `kid` signs immediately; previous key kept in JWKS for verify | None — old tokens keep verifying against the retained key |
| Refresh-token reuse detected | Family revoked first (`family.revoked`), then its tracked access-token JTIs denylisted; both the legit client and the attacker lose refresh access | In-flight access tokens until `exp` (15 min default) for resource servers that verify locally — the JTIs are denylisted, so introspection reports them inactive; tokens **exchanged** from them (RFC 8693, 1 h default) until their own `exp` — family revocation never reaches exchanged issuances |
| Authorization-code reuse detected **with a valid `code_verifier`** | Same two halves as refresh reuse, on the family that code produced: family revoked (`family.revoked`, detail prefix `code_reuse`), then its tracked access-token JTIs denylisted | In-flight access tokens until `exp` for resource servers that verify locally — the JTIs are denylisted, so introspection reports them inactive. A replay **without** a valid verifier revokes nothing: it is recorded (`auth_code.reused`) and counted, but the code was never redeemable without the verifier, so acting on it would let anyone holding a spent code log its owner out. |

The asymmetry is deliberate: **revocation is instant for stateful credentials** (refresh tokens, machine-token JTIs, grants) and **expiry-bounded for stateless JWTs** (user access tokens, exchanged tokens). Tighten `dcr.default_token_expiry` if your blast-radius budget is smaller than 15 minutes.

## Refresh-token rotation and reuse detection

Every login spawns a `token_family`. The family carries a chain of consumed → current refresh tokens.

1. On `/oauth/token` with `grant_type=refresh_token`, the AS atomically marks the current token consumed and emits the next one.
2. The audit row is `token.refreshed` with `detail=family=<family_id>` (`refreshToken` in `internal/services/token.go`).
3. If a refresh token is presented **after** it was consumed, the family is burnt. The bullets below are the success path — if either half of the revocation fails, the audit row and the counters differ; the outcome table below is authoritative.
   - All refresh tokens in the family are revoked atomically (`RevokeFamily` is atomic on its own: the family row and its refresh tokens commit together).
   - `family.revoked` audit row written with `detail=reuse_detection family=<family_id>` (`revokeFamilyOnReuse` in `internal/services/token.go`) — `family.revocation_failed` instead if that half failed.
   - Metric `authserver_refresh_token_reuse_total` increments (canonical: `RefreshTokenReuse` in `internal/observability/metrics.go`) — in every outcome: the detection itself was real.
   - Metric `authserver_tokens_revoked_total{reason="family_revocation"}` increments (`revokeFamilyOnReuse` in `internal/services/token.go`) — only once the family is actually revoked.

**Revocation runs family first, denylist always — not as one transaction.** The two halves are not worth the same. `RevokeFamily` (family row + every refresh token in it) ends the session: without it, whoever holds the family's *current* refresh token keeps rotating — refresh lifetime is a 7-day sliding window with no absolute cap — until an operator intervenes. `RevokeByFamily` (denylist of the family's tracked access-token JTIs) only shortens the life of access tokens already issued, and only for callers that introspect; it is worth at most one `exp` (15 min default). Wrapping both in one transaction would let a failure in the 15-minute half undo the whole-session half, and it made the backends disagree (PostgreSQL aborts a transaction on any failed statement; SQLite commits what succeeded). Neither half is held hostage by the other: the denylist insert reads `access_token_jtis`, not `token_families`, so it runs even when the family half failed — if the replayer is holding a stolen access token rather than the family's current refresh token, that is the token it cuts. Run separately, they produce the same four outcomes on both backends, each half reporting its own failure — log line, counter and audit row — so the family row (`family.revoked` / `family.revocation_failed`, exactly one per detection) says whether the session is dead and a `family.denylist_failed` row next to it says whether its access tokens outlive it (`revokeFamilyOnReuse` in `internal/services/token.go`):

| Outcome | Client sees | Audit row | Counters | Log |
|---|---|---|---|---|
| Family revoked, JTIs denylisted | `400 invalid_grant`, *token family revoked due to reuse detection* | `family.revoked` | `reuse_total` +1, `tokens_revoked_total` +1 | WARN `refresh token reuse detected — family revoked` |
| Family revoked, denylist **failed** | same as above — the family *is* revoked | `family.revoked` + `family.denylist_failed` | + `revocation_failures_total{path="reuse",half="jti"}` +1 | WARN `refresh token reuse detected — family revoked`, then ERROR `JTI denylist failed during reuse detection` |
| Family revocation **failed**, JTIs denylisted | `400 invalid_grant`, *token family revoked due to reuse detection* — same text as above, on purpose: the presenter must not learn the family is live | `family.revocation_failed` | `reuse_total` +1 (the detection was real), `revocation_failures_total{path="reuse",half="family"}` +1, `tokens_revoked_total` unchanged | ERROR `failed to revoke family during reuse detection` |
| Family revocation **failed**, denylist **failed** — nothing revoked | same as above | `family.revocation_failed` + `family.denylist_failed` | as above + `revocation_failures_total{path="reuse",half="jti"}` +1 | ERROR `failed to revoke family during reuse detection` + ERROR `JTI denylist failed during reuse detection` (each half logs its own) |
| Family revoked **by another caller** between the status check and the UPDATE — a concurrent detection, an admin revoke, a force-logout | `400 invalid_grant`, *token family revoked due to reuse detection* | none from this detection (whoever revoked it wrote its own row) | `reuse_total` +1 only; `tokens_revoked_total` unchanged | INFO `family already revoked …`; the denylist half still runs |

The last two rows are the ones to page on: that family is live until an operator revokes it (`DELETE /admin/tokens/$FAMILY_ID`, or `admin user force-logout`). A `half="jti"` failure on its own (second row) is a warning: the same admin call re-runs the denylist insert (idempotent), or the tokens expire on their own. Alert rules for both are in [Observability → Alerts](../deploy/observability-prometheus-otel.md#alerts-you-should-never-deploy-without). What is given up is crash-atomicity between the two statements: a process death between them leaves the second-row state with no log, bounded by `exp` and repaired by the same admin call. In normal operation that same state exists for the milliseconds between the two commits; introspection and token exchange consult only the denylist, so an access token presented in that window passes exactly as it did one request before detection — the gap delays the cut, it does not widen what was exposed.

**What detection does not reach.** The family's already-issued access tokens stay valid until `exp` (15 min by default) for any resource server that verifies JWTs locally — the denylist is consulted only by introspection and by token exchange. A token obtained by **exchanging** one of those access tokens (RFC 8693, 1 h by default via `token_exchange.token_expiry`) is a separate issuance with no link back to the family and is never revoked by reuse detection; only the *next* exchange that presents the denylisted access token is refused. Client-credentials tokens have no refresh token and no family, so reuse detection does not apply to them at all. Size your blast-radius budget on the 1 h figure if you run token exchange, not on the 15 min one.

This is the rotation-with-reuse-detection pattern recommended by RFC 9700 §4.14.2 (the OAuth 2.0 Security Best Current Practice); the OAuth 2.1 effort — still an Internet-Draft, not a published standard — folds the same recommendation in. Wire an alert:

```promql
sum(rate(authserver_refresh_token_reuse_total[5m])) > 0.1
```

Non-zero for ≥ 5 minutes → real campaign or buggy client. See [Incident runbook → Refresh-token reuse burst](incident-runbook.md#incident-refresh-token-reuse-burst).

### Refresh tokens never carry a `cnf.jkt`

DPoP binds **access tokens**, not refresh tokens. A stolen refresh token alone produces a fresh access token without the DPoP key — but the moment the next refresh hits the AS, the reuse detector fires. Defense-in-depth: the access token still requires a valid DPoP proof at every protected-resource call.

## Authorization-code reuse detection

Authorization codes are single-use. `ConsumeByCodeHash` atomically marks the code's `auth_sessions` row consumed on first exchange. RFC 6749 §4.1.2 requires denying a second redemption of the same code and recommends (SHOULD) revoking the tokens issued from the first; RFC 9700 §4.2.4 restates the same requirement. Denying the replay is not new — every second redemption has always answered `400 invalid_grant`. What changed is that the AS now also acts on the replay, conditionally.

1. On `/oauth/token` with `grant_type=authorization_code`, `ConsumeByCodeHash` finds the row already consumed and returns it alongside `ErrCodeConsumed` instead of erroring "not found" — that is what lets `exchangeCode` tell a replay from a code that never existed at all, and hand it to `handleCodeReuse` (`internal/services/token.go`).
2. Detection is recorded unconditionally: an `auth_code.reused` audit row (`detail=code_reuse session=<session_id> verifier=valid|invalid`) and `authserver_auth_code_reuse_total{verifier}` increment on every replay, whether or not the code was ever redeemable.
3. Revocation — the same family-revoke-then-denylist pair used for refresh-token reuse, run against the family the *original* redemption produced (`GetFamilyByAuthSessionID`, keyed by the replayed session, not the replayed code) — runs only when the replay also presents a `code_verifier` that matches the session's stored `code_challenge` **and** a `client_id` that matches the session's.

**Why revocation is gated on the verifier and the client_id.** PKCE is mandatory on this server: every authorization request carries a `code_challenge`, and every code exchange is checked against it. A replayer who cannot produce the matching verifier could not have redeemed this code themselves — they found the code value somewhere (a log line, a `Referer` header, browser history) but never held the client-side secret that proves they were the party it was issued to. The same reasoning applies to the client_id: a caller presenting a different client than the one the session was issued to could never have redeemed this code either. Revoking on either replayer's say-so would turn any spent authorization code an attacker can merely *read* into a credential-free way to log the code's legitimate owner out. So the AS records every replay, but only acts on the ones where the replayer proves they could plausibly have been the original client.

The client-visible response never varies with the outcome: it is always the same `400 invalid_grant`, *authorization code has already been used* — that text predates this feature and does not depend on whether anything was revoked. Both halves of revocation report their own outcome the same way the refresh path's do (see the outcome table above for why they are not one transaction):

| Outcome | Client sees | Audit row | Counters | Log |
|---|---|---|---|---|
| Replay, verifier invalid/missing or client_id mismatched | `400 invalid_grant` | `auth_code.reused` (`verifier=invalid`) | `auth_code_reuse_total{verifier="invalid"}` +1 | WARN `authorization code reuse detected — replayer not credentialed, nothing revoked` |
| Replay, verifier valid, family revoked, JTIs denylisted | `400 invalid_grant` | `auth_code.reused` (`verifier=valid`) + `family.revoked` (detail prefix `code_reuse`) | `auth_code_reuse_total{verifier="valid"}` +1, `tokens_revoked_total{reason="code_reuse"}` +1 | WARN `authorization code reuse detected — family revoked` |
| Replay, verifier valid, family revoked, denylist **failed** | `400 invalid_grant` | + `family.denylist_failed` | + `revocation_failures_total{path="code_reuse",half="jti"}` +1 | + ERROR `JTI denylist failed during code reuse detection` |
| Replay, verifier valid, family revocation **failed** | `400 invalid_grant` | `family.revocation_failed` (no `family.revoked`) | `revocation_failures_total{path="code_reuse",half="family"}` +1 | ERROR `failed to revoke family during code reuse detection` |
| Replay, verifier valid, family revocation **failed**, denylist **failed** | `400 invalid_grant` | `family.revocation_failed` + `family.denylist_failed` | both failure counters above | both ERROR lines |
| Replay, verifier valid, family **already revoked** by an earlier replay | `400 invalid_grant` | `auth_code.reused` (`verifier=valid`); no second `family.revoked` | `auth_code_reuse_total{verifier="valid"}` +1; `tokens_revoked_total` unchanged | WARN `authorization code reuse detected — family already revoked`. The denylist half still runs (idempotent), so a `family.denylist_failed` from an earlier replay is retried here |
| Replay, verifier valid, family revoked **by another caller** between the status check and the UPDATE — a concurrent replay, an admin revoke, a force-logout | `400 invalid_grant` | `auth_code.reused` (`verifier=valid`) only — no `family.revoked` from this detection | `auth_code_reuse_total{verifier="valid"}` +1; `tokens_revoked_total` unchanged | INFO `family already revoked …`; the denylist half still runs |

One more case produces no revocation attempt and is not a failure: a credentialed replay for which no family is linked to the session (`GetFamilyByAuthSessionID` finds nothing). Detection still records the audit row and the metric, then WARNs `authorization code reuse detected — credentialed replay, no family linked to the session, nothing revoked`. The line says what was observed, not that there was nothing to revoke, because the server cannot tell two causes apart:

- **The first redemption aborted before the family was created** — the code burned without issuing anything. The most ordinary cause is that the code had already expired when it arrived: a slow client's first exchange is consumed at step 1 and rejected at step 2, and its retry with the genuine verifier lands here. The others are a failed PKCE, DPoP, subject lookup or mint. When the replay arrives *with* the genuine verifier and the code was not expired, the likely story is that someone holding only the code redeemed it first with a wrong verifier, and this "replay" is the legitimate client's own exchange: the code leaked, the verifier did not, nothing was issued to anyone, and the user answers `400 invalid_grant` and has to authorize again. `verifier="valid"` fires in both cases even though nothing was revoked.
- **The first redemption is still in flight** and has not committed its family yet — tokens are about to exist and this replay did not revoke them. Correlate against a `tokens issued` line carrying the same `auth_session_id`: one committed moments later names the family to revoke by hand. Closing this window is tracked separately.

**The gate is a floor, not an identity check.** The verifier and the client_id prove the replayer *could* have been the original client; they cannot prove it was not. A legitimate client that re-submits the same `code` + `code_verifier` — a double-submitted callback, a retry after the first response was lost while the client still held the verifier, a user returning to a callback URL the client has not yet forgotten — passes the gate and revokes the family it was just issued. That is what RFC 6749 §4.1.2 asks for: a second redemption of a code is reuse, and the server has no way to distinguish the owner retrying from an attacker who captured the whole request. Recovery is a fresh authorization. Clients avoid it by discarding the verifier and `state` as soon as the exchange returns, which the PKCE RFC and BCP 240 already expect of them; a client that keeps them alive across retries will see its own sessions revoked.

Wire the alert on the credentialed case only:

```promql
rate(authserver_auth_code_reuse_total{verifier="valid"}[5m]) > 0
```

`verifier="valid"` means the replayer produced the matching PKCE verifier *and* the session's own client_id — everything needed to redeem the code. Three stories produce it, and the server cannot tell them apart:

- the whole token request was captured and replayed — a proxy or log-shipper re-sending the POST it recorded, a compromised client — so the code *and* its verifier leaked, and revocation ran against the tokens the first redemption issued;
- the code was burned without issuing anything — by the legitimate client itself arriving after the code expired, or by someone who held only the code and redeemed it first with a wrong verifier — and this is the legitimate client's own exchange arriving second: nothing was issued and nothing revoked (the no-family case above);
- the legitimate client re-submitted its own exchange while still holding the verifier, and revoked the family it was just issued (the floor-not-identity case above).

Page on it: the first is an incident, the second is either an incident (code stolen) or a slow client (code expired), and the third is a broken client that is logging its own users out. Then read the two lines the detection leaves behind — `tokens_revoked_total{reason="code_reuse"}` with the WARN `family revoked` say revocation ran; the WARN `no family linked` says the code was burned before anything was issued, by expiry or by someone else's failed redemption — and look at *which* client repeats: one `client_id` producing `verifier="valid"` steadily over days is a client retrying its exchanges, not an attacker.

`verifier="invalid"` is noise-grade: whoever sent it never held the verifier, or presented a different client_id, so they could not have redeemed the code — a code value lifted from a log line, a `Referer` header or browser history and submitted on its own; a client that already discarded its verifier resubmitting a callback. Revoking nothing there is correct, not a gap.

**The detection window depends on the operator's purge schedule, not on server-side cleanup.** Detection requires the code's `auth_sessions` row to still exist — that row is what makes the second exchange look "already consumed" instead of "not found." The row survives until `authserver purge --only=sessions` deletes it (see [Backup & purge](../deploy/backup-and-purge.md)); `authserver serve` never deletes it on its own, so the purge schedule is entirely the operator's to set. With no purge scheduled, spent-session rows accumulate — harmless for detection, though it costs storage. With an aggressive purge schedule, a replay that lands after the row is gone answers the same `400 invalid_grant` but via the "not found" path — no audit row, no metric, nothing detected, indistinguishable from a code that never existed. Set the purge interval against how long you need replay detection to reach, not only against storage growth.

## `cnf.jkt` propagation across token exchange

When a client presents a DPoP-bound subject token at `/oauth/token` with `grant_type=urn:ietf:params:oauth:grant-type:token-exchange`, the AS validates:

1. The subject token carries `cnf.jkt`.
2. The DPoP proof on the exchange request matches that `jkt`.

What happens next depends on the dispatch path (see the `detail` strings in [Audit & forensics](audit-and-forensics.md#4-decode-the-detail-string)):

| Dispatch | Output token `cnf` | Output `token_type` | Audit detail |
|---|---|---|---|
| `mint_dispatch` (Mint → Mint) | Same `cnf.jkt` as subject | `DPoP` | `type=mint_dispatch resource=… chain_kind=direct\|fronted` |
| `broker_dispatch` (direct broker) | N/A — the response is an upstream-format token, not a JWT issued by the AS | `Bearer` (upstream-format) | `type=broker_dispatch resource=… provider=…` |
| `broker_dispatch` (fronted) | N/A — same as direct broker | `Bearer` | `type=broker_dispatch chain_kind=fronted target_kind=broker via_link=src->tgt` |

**Operator takeaway:** for Mint-to-Mint chains, the `cnf.jkt` is preserved at every hop — a token theft up-chain is useless without the original keypair. For broker-dispatched chains, the upstream provider owns the credential, so AS-level `cnf.jkt` enforcement ends at the broker boundary.

The chain depth is capped by `max_chain_depth`; exceeding it returns `ErrTokenExchangeChainTooDeep` and emits `token.exchange_denied`.

## What to monitor (canonical metric names)

All names below come from `internal/observability/metrics.go`. Use them verbatim in PromQL.

| Metric | Source line | Why monitor |
|---|---|---|
| `authserver_tokens_issued_total` | `metrics.go:105` | Baseline issuance rate; anomalous spike → enumeration or runaway client. |
| `authserver_tokens_refreshed_total` | `metrics.go:110` | Should track issued tokens scaled by refresh cadence. |
| `authserver_tokens_revoked_total` | `metrics.go:115` | Spike → operator action or family-revocation burst. |
| `authserver_refresh_token_reuse_total` | `RefreshTokenReuse` in `metrics.go` | **Critical alert.** Non-zero for > 5 min → IR. |
| `authserver_auth_code_reuse_total` | `AuthCodeReuse` in `metrics.go` | **Critical alert on `{verifier="valid"}`** — the replayer held the verifier and the client_id: a captured request, a code someone else burned first, or the legitimate client re-submitting its own exchange (see the three stories above). `{verifier="invalid"}` is noise-grade: a spent code was replayed by someone who could not have redeemed it. |
| `authserver_token_issuance_duration_seconds` | `metrics.go:147` | Latency budget; tail spikes → DB contention. |
| `authserver_key_rotation_total` | `metrics.go:210` | Unexpected increment → unauthorised rotation. |
| `authserver_upstream_token_issued_total` | `metrics.go:224` | Broker-dispatch volume per upstream provider. |
| `authserver_upstream_token_refresh_total` | `metrics.go:236` | Background upstream refreshes; flat-zero may mean upstream secrets expired. |
| `authplane_dpop_proofs_validated_total` | `metrics.go:265` | DPoP adoption gauge. |
| `authplane_dpop_proofs_rejected_total` | `metrics.go:270` | Reject rate; sustained non-zero → replay attempt or clock skew. |
| `authplane_token_exchange_total` | `metrics.go:277` | RFC 8693 volume; baseline for delegation-heavy deployments. |
| `authplane_token_exchange_denied_total` | `metrics.go:282` | Denied exchanges; chain-depth, allowlist, scope-coverage failures. |
| `authplane_client_credentials_issued_total` | `metrics.go:253` | Machine-token issuance baseline. |
| `authserver_active_clients` | `metrics.go:325` | Gauge; mutation by `client.created_admin` / `client.deleted`. |
| `authserver_active_token_families` | `ActiveTokenFamilies` in `metrics.go` | Gauge. Families are never purged today, so growth is expected, not a fault. |
| `authserver_introspection_total` | `metrics.go:203` | Reverse-validation volume; non-zero only if resource servers do real-time revocation checks. |

## Verify

```bash
# Pull current values for the high-value counters
curl -s http://localhost:9000/metrics \
  | grep -E '^authserver_(tokens_issued_total|refresh_token_reuse_total|key_rotation_total)|^authplane_(dpop_proofs_rejected_total|token_exchange_denied_total)'
```

## What can go wrong

| Symptom | Likely cause | Fix |
|---|---|---|
| `token_families` grows without bound | Expected: no purge target trims families; one row per authorization-code exchange since install | Nothing to wire today — a family purge is a tracked follow-up. Plan the migration-003 index build for it (see [systemd → Migrations on upgrade](../deploy/systemd.md#migrations-on-upgrade)). |
| Tokens expire much faster than expected | `dcr.default_token_expiry` lowered without operator awareness | Re-check effective config; YAML + env + DCR-per-client all compose. |
| `cnf.jkt` missing on tokens from an exchange | Client did not send a DPoP proof at the exchange call | Validate the client SDK; DPoP must be present on both the subject-token leg and the exchange leg. |
| `family.revoked` rate >0 with no user reports | One client is reusing refresh tokens across instances (load balancer flapping) | Fix the client to coordinate refresh; AS behaviour is correct. |
| `authserver_introspection_total` is zero | Resource servers do local JWT verify only | Expected — only enable introspection if you need real-time revocation. |
| `upstream.token.issued` continues for a revoked broker grant | The revocation is forensic-only; upstream-vended tokens linger until upstream TTL | Coordinate with the upstream provider for token-level revocation. |

## Runbook

| Operator question | How to answer |
|---|---|
| "What's our token-issuance baseline?" | `rate(authserver_tokens_issued_total[1h])` over 7 days; eyeball median. |
| "Is anyone reusing refresh tokens?" | Alert on `authserver_refresh_token_reuse_total > 0` over 5 min. |
| "Is anyone replaying authorization codes?" | Alert on `authserver_auth_code_reuse_total{verifier="valid"} > 0` — the replayer held the verifier, so it pages; then tell a captured request from a broken client re-submitting by which `client_id` repeats. `{verifier="invalid"}` is expected background noise (a bare code value submitted without its verifier); do not page on it. |
| "Are we vending more upstream tokens than usual?" | `rate(authserver_upstream_token_issued_total[5m])` by `provider` label. |
| "Did the key rotation propagate?" | Compare `/.well-known/jwks.json` across instances; both `kid`s present. |
| "Should we tighten access-token TTL?" | Decide blast-radius budget; lower `dcr.default_token_expiry` from `15m`; affects every JWT-only verifier (resource servers will still validate against `exp`). |

## See also

- [Concepts → Tokens and claims](../../concepts/tokens-and-claims.md) — the wire-shape doc.
- [Concepts → DPoP and proof of possession](../../concepts/dpop-and-proof-of-possession.md) — full `cnf.jkt` treatment.
- [Audit & forensics](audit-and-forensics.md) — decode the audit `detail` strings.
- [Incident runbook](incident-runbook.md) — when a metric crosses a threshold.
- [Key rotation](key-rotation.md) — the lifecycle of the `kid`.
- [Deploy → Observability](../deploy/observability-prometheus-otel.md) — Prometheus / OTel setup.
