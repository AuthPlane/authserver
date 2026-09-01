*Context: this is part of [Guides — Deploy](README.md). Start with the primer if you haven't.*

# Observability — Prometheus + OpenTelemetry

authserver exposes Prometheus metrics on the **admin port**, structured JSON logs to stdout, and optional OTLP export for logs, metrics, and traces. This recipe wires that into Prometheus + a Grafana LGTM stack and lists the alerts every operator should run.

## What you'll achieve in 10 minutes

- Prometheus scraping `/metrics` on the admin port.
- OTLP export for logs and traces wired into Tempo/Loki/Mimir.
- Three concrete alerts you should never deploy without.

## Prereqs

- An already-running authserver (any deploy target).
- Prometheus 2.50+ and Grafana 10+ — or use the bundled LGTM stack via [`deploy/observability/docker-compose.observability.yml`](../../../deploy/observability/docker-compose.observability.yml).
- Read [Configuration → Observability](configuration.md) for the env-var names.

## What the AS exposes (where + how)

| Surface | Where | Configured by |
| --- | --- | --- |
| Prometheus metrics | `GET /metrics` on the **admin port** (default `:9001`) | [`observability.metrics.provider: prometheus`](../../reference/configuration.md#config-observability) (default), [`observability.metrics.path: /metrics`](../../reference/configuration.md#config-observability) |
| Structured logs | stdout, JSON | [`observability.logging.format: json`](../../reference/configuration.md#config-observability) (default), level via [`AUTHPLANE_LOG_LEVEL`](../../reference/env-vars.md) |
| OTLP logs | `observability.logging.outputs.otel: true` + endpoint | [`AUTHPLANE_LOG_OTEL`](../../reference/env-vars.md), [`AUTHPLANE_LOG_OTEL_ENDPOINT`](../../reference/env-vars.md) |
| OTLP traces | `observability.tracing.enabled: true` + endpoint | [`AUTHPLANE_TRACING_ENABLED`](../../reference/env-vars.md), [`AUTHPLANE_TRACING_ENDPOINT`](../../reference/env-vars.md) |
| OTLP metrics (in parallel with Prometheus) | `observability.metrics.provider: both` | [`AUTHPLANE_METRICS_PROVIDER`](../../reference/env-vars.md), [`AUTHPLANE_METRICS_OTEL_ENDPOINT`](../../reference/env-vars.md) |

`/metrics` is bound on the admin port so it is **not** publicly exposed by default. Make sure your scraper can reach it (same cluster network in Kubernetes; loopback for systemd).

## Steps

### 1. Scrape `/metrics`

```yaml
# prometheus.yml — verified against deploy/prometheus.yml
scrape_configs:
  - job_name: authserver
    scrape_interval: 15s
    metrics_path: /metrics
    static_configs:
      - targets: ["authserver:9001"]   # admin port
```

In Kubernetes via the [Helm chart](helm.md): `serviceMonitor.enabled: true` already points at the admin port.

### 2. Enable OTLP traces

```yaml
observability:
  tracing:
    enabled: true                # AUTHPLANE_TRACING_ENABLED
    endpoint: otel-collector:4317 # AUTHPLANE_TRACING_ENDPOINT
    insecure: true               # AUTHPLANE_TRACING_INSECURE (TLS off for local)
    sample_rate: 1.0             # AUTHPLANE_TRACING_SAMPLE_RATE; lower for prod
```

Drop the sample rate (e.g. `0.1`) once you've validated traces; high cardinality at full sample is expensive.

### 3. Enable OTLP logs

```yaml
observability:
  logging:
    level: info                  # AUTHPLANE_LOG_LEVEL
    format: json
    outputs:
      stdout: true               # keep stdout; pod-logs are forever
      otel: true                 # AUTHPLANE_LOG_OTEL
      otel_endpoint: otel-collector:4317
      insecure: true
```

Each log line includes `trace_id`, `span_id`, `request_id`, `client_id`, and the grant name — click a trace in Grafana Tempo to pivot to logs in Loki.

### 4. Use the bundled LGTM stack (optional)

[`deploy/observability/docker-compose.observability.yml`](../../../deploy/observability/docker-compose.observability.yml) runs Alloy (OTLP gateway), Tempo, Loki, Mimir, Prometheus, and Grafana. Run it alone:

```bash
docker compose -f deploy/observability/docker-compose.observability.yml up -d
# Grafana at http://localhost:3000 (admin/admin)
```

Or `include:` it from your own compose (this is what [`deploy/docker-compose.yml`](../../../deploy/docker-compose.yml) does — point both at `alloy:4317`).

## Metrics catalogue (selected)

Names come straight from `internal/observability/metrics.go`. The prefix is currently mixed: `authserver_*` for the OAuth core, `authplane_*` for newer subsystems (DPoP, token exchange, client credentials, XAA). Both are live.

**Counters — security-critical**

| Metric | Why operators care |
| --- | --- |
| `authserver_tokens_issued_total{grant_type}` | Throughput baseline, anomaly detection. |
| `authserver_refresh_token_reuse_total` | Stolen-token reuse (RFC 6749 §10.4). Page on any non-zero increase. |
| `authserver_auth_denied_total{reason}` | Why an authentication was refused. The login path emits `user_not_found`, `user_disabled`, `user_not_local`, `invalid_credentials` and `unusable_stored_hash`; the OIDC callback emits `user_disabled`. A sustained `user_not_found` rate is address enumeration or credential stuffing against a list. `unusable_stored_hash` means an account whose stored password hash cannot be derived against — a broken row, not a bad password; alert on any non-zero value. |
| `authserver_tokens_revoked_total{reason}` | Family-level revocations propagating through. |
| `authserver_login_attempts_total{result}` | Login success/failure ratio. |
| `authplane_dpop_proofs_rejected_total` | Token-binding violations. |
| `authplane_token_exchange_denied_total` | Cross-client policy denials. |

**Histograms — latency / health**

| Metric | Why |
| --- | --- |
| `authserver_token_issuance_duration_seconds{grant_type}` | Per-grant p99 latency. |
| `authserver_http_request_duration_seconds{method,path,status}` | Full HTTP-surface SLO. |
| `authserver_db_operation_duration_seconds{operation,store}` | Backstop for DB-bound regressions. |
| `authserver_cimd_fetch_duration_seconds` | Upstream CIMD-document health. |
| `authserver_introspection_duration_seconds` | `/oauth/introspect` latency — used by resource servers. |

**Gauges — capacity**

| Metric | Why |
| --- | --- |
| `authserver_active_clients` | Drift detection on registered clients. |
| `authserver_active_token_families` | Outstanding token-family count. No purge target trims families today, so it grows with every authorization-code exchange. |

The exhaustive list lives in [`docs/reference/metrics.md`](../../reference/metrics.md), generated from `internal/observability/metrics.go` (the source-of-truth on conflicts).

## Alerts you should never deploy without

```yaml
groups:
  - name: authserver
    rules:
      - alert: RefreshTokenReuse                 # page-worthy
        expr: increase(authserver_refresh_token_reuse_total[5m]) > 0
        for: 1m
        labels: { severity: critical }
        annotations:
          summary: "Refresh token reuse — possible theft"

      - alert: RefreshReuseRevocationFailed      # page-worthy: detection fired, family still live (its access tokens are denylisted unless the jti alert fired too)
        expr: increase(authserver_revocation_failures_total{path="reuse",half="family"}[5m]) > 0
        for: 0m
        labels: { severity: critical }
        annotations:
          summary: "Reuse detected but the family could not be revoked — revoke it now (runbook)"

      - alert: RefreshReuseDenylistFailed        # the family's access tokens outlive detection until exp; alone it means the family is dead
        expr: increase(authserver_revocation_failures_total{path="reuse",half="jti"}[5m]) > 0
        for: 0m
        labels: { severity: warning }
        annotations:
          summary: "JTI denylist failed on reuse — family dead only if RefreshReuseRevocationFailed did not also fire; re-run the admin revoke or wait exp"

      - alert: HighAuthDenialRate                # likely an attack or a regression
        expr: rate(authserver_auth_denied_total[5m]) > 10
        for: 5m
        labels: { severity: warning }
        annotations:
          summary: "auth_denied rate >10/s for 5m"

      - alert: TokenP99Slow                      # something's wrong with signing or DB
        expr: histogram_quantile(0.99, rate(authserver_token_issuance_duration_seconds_bucket[5m])) > 2
        for: 5m
        labels: { severity: warning }
        annotations:
          summary: "Token issuance p99 > 2s"
```

For the Vault-Transit deploy, also alert on `WARN vault renewal failed` log occurrences (Loki query) — once the in-flight Vault token expires, signing stops. See [Vault Transit → Runbook](hashicorp-vault-transit.md#runbook).

## Verify

```bash
# Scrape the admin port — sanity-check metric names
curl -fsS http://localhost:9001/metrics | grep -E '^authserver_tokens_issued_total|^authplane_dpop_proofs_validated_total' | head -5

# Confirm tracing is exporting (look for the OTLP grpc connection log line)
journalctl -u authserver --since '1 minute ago' | grep -iE 'otlp|tracer'   # systemd
kubectl logs deploy/authplane | grep -iE 'otlp|tracer'                     # k8s

# In Grafana: pivot from a token-issuance trace to the matching log lines via trace_id
```

## What can go wrong

| Symptom | Likely cause | Fix |
| --- | --- | --- |
| Prometheus says `up=0` for authserver | Scraper pointed at the public port (9000) where `/metrics` does not exist | Point at `:9001`. The Helm `serviceMonitor` already does. |
| No traces in Tempo | `observability.tracing.enabled` false or endpoint unreachable | Set [`AUTHPLANE_TRACING_ENABLED=true`](../../reference/env-vars.md) and confirm the collector is reachable from the AS network. |
| `WARN CORS is disabled` after enabling otel logs | Unrelated — `server.allowed_origins` is empty | Set [`AUTHPLANE_SERVER_ALLOWED_ORIGINS`](../../reference/env-vars.md) (independent of observability). |
| High cardinality blowing up Mimir | `sample_rate: 1.0` and `metrics.provider: both` in prod | Drop `sample_rate` to `0.1`; pick one of `prometheus` or `otel` for metrics, not both. |
| `request_id` missing from logs | Logs collected before the request enters the HTTP middleware (e.g. boot logs) | Expected; correlation only applies to request-scoped logs. |
| Metric names look unfamiliar | Mixed `authserver_*` / `authplane_*` prefixes | Both are live — see catalogue above. |

## See also

- [Configuration → Observability](configuration.md) — the YAML knobs.
- [`docs/reference/configuration.md#config-observability`](../../reference/configuration.md#config-observability) — full schema.
- [`docs/reference/env-vars.md`](../../reference/env-vars.md) — every `AUTHPLANE_LOG_*`, `AUTHPLANE_METRICS_*`, `AUTHPLANE_TRACING_*`.
- [`internal/observability/metrics.go`](../../../internal/observability/metrics.go) — source of truth for metric names + labels.
- [Threat model](../../concepts/threat-model.md) — which metrics correspond to which threat.
