<!-- Hand-maintained reference. Keep in sync with internal/observability/metrics.go. -->

# Metrics

The authorization server registers all metric instruments at startup in [`internal/observability/metrics.go`](../../internal/observability/metrics.go). Metrics are exported via the Prometheus endpoint (`GET /metrics` on the admin port) and / or pushed via OTLP, depending on `observability.metrics.provider` (see [configuration.md](configuration.md)).

Histograms use a sub-second latency bucket layout — `0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10` seconds — declared at [`internal/observability/metrics.go:96`](../../internal/observability/metrics.go).

The `Labels` column lists the OTel attributes that emit sites attach via `metric.WithAttributes(...)`. Where the registration itself attaches no labels, the column shows `(none)`; emit sites may still add request-scoped attributes (e.g. `grant_type`, `outcome`, `reason`) — grep the emit sites in `internal/services/` and `internal/observability/httpmw.go` to see the full label set in production exports.

## Counters

| Name | Type | Labels (emit-site) | Description | Source |
| --- | --- | --- | --- | --- |
| `authserver_tokens_issued_total` | counter | grant_type | Total tokens issued | `internal/observability/metrics.go:105` |
| `authserver_tokens_refreshed_total` | counter | (none) | Total tokens refreshed | `internal/observability/metrics.go:110` |
| `authserver_tokens_revoked_total` | counter | (none) | Total tokens revoked | `internal/observability/metrics.go:115` |
| `authserver_auth_denied_total` | counter | reason | Total auth requests denied | `internal/observability/metrics.go:120` |
| `authserver_clients_registered_total` | counter | source (`dcr` / `admin`) | Total clients registered | `internal/observability/metrics.go:125` |
| `authserver_consent_decisions_total` | counter | decision (`granted` / `denied`) | Total consent decisions | `internal/observability/metrics.go:130` |
| `authserver_login_attempts_total` | counter | outcome | Total login attempts | `internal/observability/metrics.go:135` |
| `authserver_refresh_token_reuse_total` | counter | (none) | Total refresh token reuse detections | `internal/observability/metrics.go:140` |
| `authserver_oidc_jwks_cache_hits_total` | counter | (none) | Total OIDC JWKS cache hits | `internal/observability/metrics.go:184` |
| `authserver_oidc_jwks_cache_misses_total` | counter | (none) | Total OIDC JWKS cache misses | `internal/observability/metrics.go:189` |
| `authserver_introspection_total` | counter | active (bool) | Total token introspections | `internal/observability/metrics.go:203` |
| `authserver_key_rotation_total` | counter | (none) | Total signing key rotations | `internal/observability/metrics.go:210` |
| `authserver_upstream_token_issued_total` | counter | provider, resource | Total upstream-format access tokens vended to MCP clients | `internal/observability/metrics.go:224` |
| `authserver_upstream_token_refresh_total` | counter | provider, outcome | Total upstream auto-refresh operations against persisted credentials | `internal/observability/metrics.go:236` |
| `authserver_connection_connect_total` | counter | provider | Total upstream-connection connect operations | `internal/observability/metrics.go:241` |
| `authserver_connection_disconnect_total` | counter | provider | Total upstream-connection disconnect operations | `internal/observability/metrics.go:246` |
| `authplane_client_credentials_issued_total` | counter | (none) | Total client credentials tokens issued | `internal/observability/metrics.go:253` |
| `authplane_client_credentials_denied_total` | counter | reason | Total client credentials requests denied | `internal/observability/metrics.go:258` |
| `authplane_dpop_proofs_validated_total` | counter | (none) | Total DPoP proofs validated | `internal/observability/metrics.go:265` |
| `authplane_dpop_proofs_rejected_total` | counter | reason | Total DPoP proofs rejected | `internal/observability/metrics.go:270` |
| `authplane_token_exchange_total` | counter | kind, source, target | Total token exchange operations | `internal/observability/metrics.go:277` |
| `authplane_token_exchange_denied_total` | counter | reason | Total token exchange operations denied | `internal/observability/metrics.go:282` |
| `authplane_agent_tokens_issued_total` | counter | (none) | Total tokens issued with agent identity claims | `internal/observability/metrics.go:289` |
| `authplane_xaa_policy_evaluation_total` | counter | outcome | Total XAA policy evaluations | `internal/observability/metrics.go:296` |
| `authplane_xaa_idp_operations_total` | counter | op | Total XAA IdP management operations | `internal/observability/metrics.go:301` |
| `authplane_xaa_subject_resolutions_total` | counter | outcome | Total XAA subject mapping resolutions | `internal/observability/metrics.go:306` |
| `authplane_resource_server_ops_total` | counter | op | Total resource server admin operations | `internal/observability/metrics.go:313` |
| `authplane_allowlist_ops_total` | counter | op | Total cross-client allowlist admin operations | `internal/observability/metrics.go:318` |
| `authserver_http_requests_total` | counter | method, path, status | Total HTTP requests | `internal/observability/metrics.go:344` |

## Histograms (seconds)

| Name | Type | Labels | Description | Source |
| --- | --- | --- | --- | --- |
| `authserver_token_issuance_duration_seconds` | histogram | (none) | Token issuance duration | `internal/observability/metrics.go:147` |
| `authserver_auth_flow_duration_seconds` | histogram | (none) | Authorization flow duration | `internal/observability/metrics.go:154` |
| `authserver_cimd_fetch_duration_seconds` | histogram | outcome | CIMD document fetch duration | `internal/observability/metrics.go:161` |
| `authserver_db_operation_duration_seconds` | histogram | op | Database operation duration | `internal/observability/metrics.go:168` |
| `authserver_oidc_exchange_duration_seconds` | histogram | outcome | OIDC code exchange and ID token verification duration | `internal/observability/metrics.go:177` |
| `authserver_introspection_duration_seconds` | histogram | (none) | Token introspection duration | `internal/observability/metrics.go:196` |
| `authserver_key_reload_duration_seconds` | histogram | (none) | JWKS cache reload duration | `internal/observability/metrics.go:215` |
| `authserver_upstream_token_issuance_duration_seconds` | histogram | provider | Upstream-format token issuance duration | `internal/observability/metrics.go:229` |
| `authserver_http_request_duration_seconds` | histogram | method, path, status | HTTP request duration | `internal/observability/metrics.go:337` |

## Gauges (UpDownCounters)

| Name | Type | Labels | Description | Source |
| --- | --- | --- | --- | --- |
| `authserver_active_clients` | gauge | (none) | Current active client count | `internal/observability/metrics.go:325` |
| `authserver_active_token_families` | gauge | (none) | Current active token family count | `internal/observability/metrics.go:330` |

## See also

- Provider selection (`prometheus`, `otel`, `both`, `none`): [configuration.md → observability](configuration.md).
- Prometheus scrape & Grafana dashboards: [guides/deploy/observability-prometheus-otel.md](../guides/deploy/observability-prometheus-otel.md).
