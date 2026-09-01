<!-- Hand-maintained reference. Keep in sync with internal/observability/metrics.go. -->

# Metrics

The authorization server registers all metric instruments at startup in [`internal/observability/metrics.go`](../../internal/observability/metrics.go). Metrics are exported via the Prometheus endpoint (`GET /metrics` on the admin port) and / or pushed via OTLP, depending on `observability.metrics.provider` (see [configuration.md](configuration.md)).

Histograms use a sub-second latency bucket layout — `0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10` seconds — declared as `latencyBuckets` in [`internal/observability/metrics.go`](../../internal/observability/metrics.go).

The `Labels` column lists the OTel attributes that emit sites attach via `metric.WithAttributes(...)`. Where the registration itself attaches no labels, the column shows `(none)`; emit sites may still add request-scoped attributes (e.g. `grant_type`, `outcome`, `reason`) — grep the emit sites in `internal/services/` and `internal/observability/httpmw.go` to see the full label set in production exports.

## Counters

| Name | Type | Labels (emit-site) | Description | Source |
| --- | --- | --- | --- | --- |
| `authserver_tokens_issued_total` | counter | grant_type | Total tokens issued | `TokensIssued` in `internal/observability/metrics.go` |
| `authserver_tokens_refreshed_total` | counter | (none) | Total tokens refreshed | `TokensRefreshed` in `internal/observability/metrics.go` |
| `authserver_tokens_revoked_total` | counter | reason (`family_revocation` / `code_reuse` / `explicit` / `explicit_machine`) | Total tokens revoked. `family_revocation` is refresh-token reuse, `code_reuse` is authorization-code reuse; both increment only once the family row is actually revoked | `TokensRevoked` in `internal/observability/metrics.go` |
| `authserver_auth_denied_total` | counter | reason | Total auth requests denied | `AuthDenied` in `internal/observability/metrics.go` |
| `authserver_audit_events_dropped_total` | counter | action (the dropped event's audit action) | Audit events that could not be persisted (the audit store is best-effort; the full event is emitted to the structured log instead) | `AuditEventsDropped` in `internal/observability/metrics.go` |
| `authserver_clients_registered_total` | counter | source (`dcr` / `admin`) | Total clients registered | `ClientsRegistered` in `internal/observability/metrics.go` |
| `authserver_consent_decisions_total` | counter | decision (`granted` / `denied`) | Total consent decisions | `ConsentDecisions` in `internal/observability/metrics.go` |
| `authserver_login_attempts_total` | counter | outcome | Total login attempts | `LoginAttempts` in `internal/observability/metrics.go` |
| `authserver_refresh_token_reuse_total` | counter | (none) | Total refresh token reuse detections | `RefreshTokenReuse` in `internal/observability/metrics.go` |
| `authserver_auth_code_reuse_total` | counter | verifier (`valid` / `invalid`) | Authorization-code replay detections, counted on every replay before any credential is proved. The label is on the CAUSE, not the outcome: `valid` means the replayer proved PKCE **and** presented the session's own `client_id`, so revocation was attempted; `invalid` covers a wrong verifier, a mismatched `client_id`, or both — the replay could never have been redeemed and nothing is revoked. Whether an attempted revocation succeeded is reported by `authserver_tokens_revoked_total{reason="code_reuse"}` and `authserver_revocation_failures_total{path="code_reuse"}` | `AuthCodeReuse` in `internal/observability/metrics.go` |
| `authserver_revocation_failures_total` | counter | path (`reuse` / `code_reuse`), half (`family` / `jti`) | Token revocations where a half failed: `family` — nothing revoked, family still live; `jti` — access-token JTIs not denylisted. Each half reports only itself (one detection can emit both), so `jti` alone does not say the family was revoked — check `half="family"`. Both reuse-detection paths emit it: `reuse` is refresh-token reuse, `code_reuse` is authorization-code reuse | `RevocationFailures` in `internal/observability/metrics.go` |
| `authserver_oidc_jwks_cache_hits_total` | counter | (none) | Total OIDC JWKS cache hits | `OIDCJWKSCacheHits` in `internal/observability/metrics.go` |
| `authserver_oidc_jwks_cache_misses_total` | counter | (none) | Total OIDC JWKS cache misses | `OIDCJWKSCacheMisses` in `internal/observability/metrics.go` |
| `authserver_introspection_total` | counter | active (bool) | Total token introspections | `IntrospectionTotal` in `internal/observability/metrics.go` |
| `authserver_key_rotation_total` | counter | (none) | Total signing key rotations | `KeyRotationTotal` in `internal/observability/metrics.go` |
| `authserver_upstream_token_issued_total` | counter | provider, resource | Total upstream-format access tokens vended to MCP clients | `UpstreamTokenIssuedTotal` in `internal/observability/metrics.go` |
| `authserver_upstream_token_refresh_total` | counter | provider, outcome | Total upstream auto-refresh operations against persisted credentials | `UpstreamTokenRefreshTotal` in `internal/observability/metrics.go` |
| `authserver_connection_connect_total` | counter | provider | Total upstream-connection connect operations | `ConnectionConnectTotal` in `internal/observability/metrics.go` |
| `authserver_connection_disconnect_total` | counter | provider | Total upstream-connection disconnect operations | `ConnectionDisconnectTotal` in `internal/observability/metrics.go` |
| `authplane_client_credentials_issued_total` | counter | (none) | Total client credentials tokens issued | `ClientCredentialsIssued` in `internal/observability/metrics.go` |
| `authplane_client_credentials_denied_total` | counter | reason | Total client credentials requests denied | `ClientCredentialsDenied` in `internal/observability/metrics.go` |
| `authplane_dpop_proofs_validated_total` | counter | (none) | Total DPoP proofs validated | `DPoPProofsValidated` in `internal/observability/metrics.go` |
| `authplane_dpop_proofs_rejected_total` | counter | reason | Total DPoP proofs rejected | `DPoPProofsRejected` in `internal/observability/metrics.go` |
| `authplane_token_exchange_total` | counter | kind, source, target | Total token exchange operations | `TokenExchangeTotal` in `internal/observability/metrics.go` |
| `authplane_token_exchange_denied_total` | counter | reason | Total token exchange operations denied | `TokenExchangeDenied` in `internal/observability/metrics.go` |
| `authplane_agent_tokens_issued_total` | counter | (none) | Total tokens issued with agent identity claims | `AgentTokensIssued` in `internal/observability/metrics.go` |
| `authplane_xaa_policy_evaluation_total` | counter | outcome | Total XAA policy evaluations | `XAAPolicyEvaluationTotal` in `internal/observability/metrics.go` |
| `authplane_xaa_idp_operations_total` | counter | op | Total XAA IdP management operations | `XAAIDPOperationsTotal` in `internal/observability/metrics.go` |
| `authplane_xaa_subject_resolutions_total` | counter | outcome | Total XAA subject mapping resolutions | `XAASubjectResolutions` in `internal/observability/metrics.go` |
| `authplane_resource_server_ops_total` | counter | op | Total resource server admin operations | `ResourceServerOps` in `internal/observability/metrics.go` |
| `authplane_allowlist_ops_total` | counter | op | Total cross-client allowlist admin operations | `AllowlistOps` in `internal/observability/metrics.go` |
| `authserver_http_requests_total` | counter | method, path, status | Total HTTP requests | `HTTPRequestsTotal` in `internal/observability/metrics.go` |

## Histograms (seconds)

| Name | Type | Labels | Description | Source |
| --- | --- | --- | --- | --- |
| `authserver_token_issuance_duration_seconds` | histogram | (none) | Token issuance duration | `TokenIssuanceDuration` in `internal/observability/metrics.go` |
| `authserver_auth_flow_duration_seconds` | histogram | (none) | Authorization flow duration | `AuthFlowDuration` in `internal/observability/metrics.go` |
| `authserver_cimd_fetch_duration_seconds` | histogram | outcome | CIMD document fetch duration | `CIMDFetchDuration` in `internal/observability/metrics.go` |
| `authserver_db_operation_duration_seconds` | histogram | op | Database operation duration | `DBOperationDuration` in `internal/observability/metrics.go` |
| `authserver_oidc_exchange_duration_seconds` | histogram | outcome | OIDC code exchange and ID token verification duration | `OIDCExchangeDuration` in `internal/observability/metrics.go` |
| `authserver_introspection_duration_seconds` | histogram | (none) | Token introspection duration | `IntrospectionDuration` in `internal/observability/metrics.go` |
| `authserver_key_reload_duration_seconds` | histogram | (none) | JWKS cache reload duration | `KeyReloadDuration` in `internal/observability/metrics.go` |
| `authserver_upstream_token_issuance_duration_seconds` | histogram | provider | Upstream-format token issuance duration | `UpstreamTokenIssuanceDuration` in `internal/observability/metrics.go` |
| `authserver_http_request_duration_seconds` | histogram | method, path, status | HTTP request duration | `HTTPRequestDuration` in `internal/observability/metrics.go` |

## Gauges (UpDownCounters)

| Name | Type | Labels | Description | Source |
| --- | --- | --- | --- | --- |
| `authserver_active_clients` | gauge | (none) | Current active client count | `ActiveClients` in `internal/observability/metrics.go` |
| `authserver_active_token_families` | gauge | (none) | Current active token family count | `ActiveTokenFamilies` in `internal/observability/metrics.go` |

## See also

- Provider selection (`prometheus`, `otel`, `both`, `none`): [configuration.md → observability](configuration.md).
- Prometheus scrape & Grafana dashboards: [guides/deploy/observability-prometheus-otel.md](../guides/deploy/observability-prometheus-otel.md).
