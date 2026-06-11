# Guides — Operate

**For:** Operators.
**Prereqs:** A deployed authserver (see [Deploy guides](../deploy/)) with `admin.enabled: true` and an admin API key. Concept background: [Architecture](../../concepts/architecture.md), [Threat model](../../concepts/threat-model.md).

Day-2 operations: clients, users, resources, grants, signing keys, forensic queries, incident response.

## Shared setup

- Export the admin API key once per shell. `export AUTHPLANE_ADMIN_API_KEY="$(openssl rand -hex 32)"` if you are bootstrapping; otherwise copy it from your secret store.
- The admin server listens on `admin.address` (default `:9001`). **Never expose this port to the internet.** Keep it behind a VPN, an internal LB with allowlisted source IPs, or an mTLS terminator.
- The Admin UI lives at `http://<admin-host>:9001/admin/ui/`. CLI, REST, and UI share the same service layer — every mutation emits the same audit row regardless of surface.

## Reading order

1. [**Admin CLI**](admin-cli.md) — the operator's daily driver. Every `authserver admin …` subcommand, cross-linked to [`docs/reference/cli.md`](../../reference/cli.md).
2. [**Admin UI tour**](admin-ui-tour.md) — the visual surface at `:9001/admin/ui/`; page-by-page map to the scripted commands.
3. [**Key rotation**](key-rotation.md) — signing-key lifecycle, keyfile vs. `postgres_key` vs. Vault Transit, JWKS propagation.
4. [**Audit & forensics**](audit-and-forensics.md) — query the audit log for incident reconstruction; covers the canonical action names and detail-string format.
5. [**Token design (operator view)**](token-design-internals.md) — what the AS emits, what to monitor, lifetimes per token kind, refresh-token reuse detection.
6. [**Incident runbook**](incident-runbook.md) — five named scenarios with Symptoms / Detect / Contain / Eradicate / Recover / Post-incident.

## Conventions

- Every CLI subcommand cited inline cross-links to [`docs/reference/cli.md`](../../reference/cli.md).
- Every HTTP route cross-links to [`docs/reference/http-api.md`](../../reference/http-api.md).
- Every audit-action name is the canonical string from `internal/domain/audit/entity.go`.
- Every metric name is the canonical instrument name from `internal/observability/metrics.go`.

## Related

- [Deploy → Backup & purge](../deploy/backup-and-purge.md) — scheduled cleanup (a deploy-time decision).
- [Deploy → Observability](../deploy/observability-prometheus-otel.md) — wire Prometheus / OTel before going to production.
- [Concepts → Threat model](../../concepts/threat-model.md) — the failure modes the audit log lets you investigate.
