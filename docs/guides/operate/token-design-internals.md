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
| Refresh-token reuse detected | Entire family revoked atomically (`family.revoked`) | None — both the legit client and the attacker lose access |

The asymmetry is deliberate: **revocation is instant for stateful credentials** (refresh tokens, machine-token JTIs, grants) and **expiry-bounded for stateless JWTs** (user access tokens, exchanged tokens). Tighten `dcr.default_token_expiry` if your blast-radius budget is smaller than 15 minutes.

## Refresh-token rotation and reuse detection

Every login spawns a `token_family`. The family carries a chain of consumed → current refresh tokens.

1. On `/oauth/token` with `grant_type=refresh_token`, the AS atomically marks the current token consumed and emits the next one.
2. The audit row is `token.refreshed` with `detail=family=<family_id>` (`internal/services/token.go:429`).
3. If a refresh token is presented **after** it was consumed, the family is burnt:
   - All refresh tokens in the family are revoked atomically.
   - `family.revoked` audit row written with `detail=reuse_detection family=<family_id>` (`internal/services/token.go:695`).
   - Metric `authserver_refresh_token_reuse_total` increments (canonical: `internal/observability/metrics.go:140`).
   - Metric `authserver_tokens_revoked_total{reason="family_revocation"}` increments (`internal/services/token.go:691`).

This is the OAuth 2.1 required rotation-with-reuse-detection pattern. Wire an alert:

```promql
sum(rate(authserver_refresh_token_reuse_total[5m])) > 0.1
```

Non-zero for ≥ 5 minutes → real campaign or buggy client. See [Incident runbook → Refresh-token reuse burst](incident-runbook.md#incident-refresh-token-reuse-burst).

### Refresh tokens never carry a `cnf.jkt`

DPoP binds **access tokens**, not refresh tokens. A stolen refresh token alone produces a fresh access token without the DPoP key — but the moment the next refresh hits the AS, the reuse detector fires. Defense-in-depth: the access token still requires a valid DPoP proof at every protected-resource call.

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
| `authserver_refresh_token_reuse_total` | `metrics.go:140` | **Critical alert.** Non-zero for > 5 min → IR. |
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
| `authserver_active_token_families` | `metrics.go:330` | Gauge; alert on monotonic growth (cleanup not running). |
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
| `authserver_active_token_families` grows unbounded | Expired-token cleanup not scheduled | Wire `authserver purge` (see [Backup & purge](../deploy/backup-and-purge.md)). |
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
