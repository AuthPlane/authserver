# Guides — Deploy — get authserver running in your environment

**Audience: Operators.** You already know what an OAuth Authorization Server is; you want uptime, a clean security posture, working observability, predictable rotation, and a backup story. These recipes are the shortest path from "container image" to "production".

## What you'll find here

- **Recipes**, not concepts. Each page has a verifiable [Verify] step and a [What can go wrong] table. Concept context lives in [`docs/concepts/`](../../concepts/).
- **Verified references.** Every env var, YAML key, and CLI flag links to the generated reference under [`docs/reference/`](../../reference/). If a doc and the source disagree, the source wins — file a bug.
- **Reproducible artifacts.** Compose files live at [`deploy/`](../../../deploy/); the Helm chart lives at [`charts/authplane/`](../../../charts/authplane/). Recipes point at those files, not inline copies.

## Reading order

1. [**Verifying releases**](verifying-releases.md) — confirm the binary or image you are about to install was built by this repository's release workflow. Do this before the first install, not after an incident.
2. [**Configuration**](configuration.md) — operator prose for the knobs that matter in production. Pick storage, signing-key store, and data-encryption driver here, before you copy a recipe.
3. Pick a deploy target:
   - [**Docker Compose**](docker-compose.md) — single-host, three flavors (SQLite, Postgres+LGTM, Postgres+Vault).
   - [**systemd**](systemd.md) — single Linux host, single binary, Caddy/nginx in front.
   - [**Kubernetes**](kubernetes.md) — overview + decision tree (Helm vs raw vs kind).
     - [**Helm**](helm.md) — recommended production path.
     - [**Raw manifests**](kubernetes-raw.md) — for GitOps without Helm.
     - [**kind**](kind-local-testing.md) — local end-to-end on your laptop.
4. [**HashiCorp Vault Transit**](hashicorp-vault-transit.md) — delegate signing keys (and optionally data-at-rest encryption) to Vault.
5. [**Observability — Prometheus + OpenTelemetry**](observability-prometheus-otel.md) — scrape config, OTLP, suggested alerts.
6. [**Backup & purge**](backup-and-purge.md) — `authserver purge` schedule + DB/keys backup. Day-2 not-optional.
7. [**Hardened deployment**](hardened-deployment.md) — production-posture knobs (`oauth.require_scope`, `session.fail_closed`, …): what each defaults to, the trade-off, and the env var to flip.

## Cross-cutting rules

- **Issuer URL** (`server.issuer`, [`env-vars.md#AUTHPLANE_SERVER_ISSUER`](../../reference/env-vars.md)) must equal the public URL clients reach. No trailing slash. Validation flips when this is not localhost — see [configuration.md](configuration.md).
- **Admin port** (`:9001`) hosts the Admin API, the Admin UI at `/admin/ui/`, and `/metrics`. Never expose it on the public internet. Keep it on loopback, an internal subnet, or behind a separate ingress with an IP allowlist.
- **`authserver purge` is not automatic.** Schedule it (systemd timer, CronJob, sidecar). See [backup-and-purge.md](backup-and-purge.md). Skip this and your DB grows unbounded.
- **Three health endpoints on the public port, and they are not interchangeable.** `GET /livez` checks nothing and answers "is the process serving HTTP" — point your **liveness** probe here, never at one that touches the database, or an outage restarts pods that cannot start (the server migrates at boot) and holds them down on backoff past the recovery. `GET /ready` pings the database and reports whether this pod can serve a database-backed request — useful for an uptime check, but **not** what the Kubernetes readiness probe should gate on. Readiness is all-or-nothing per pod, and JWKS and discovery are served from config, so removing a pod during a database outage takes down the key set resource servers fetch to *validate* tokens. Point **readiness** at `/livez` too and let `/oauth/token` answer 500 on its own. `GET /health` also pings the database and returns detail; it is the one for humans, dashboards and uptime checks. **Metrics** are `GET /metrics` on the admin port. All are documented in [`http-api.md`](../../reference/http-api.md).

## Related

- [Operate](../operate/) — day-2 tasks (key rotation, audit log, admin CLI).
- [Topologies](../../topologies/) — named shapes (Side-by-Side AS, Vault-backed AS, HA-Postgres).
- [Reference](../../reference/) — generated schemas: [config](../../reference/configuration.md), [env vars](../../reference/env-vars.md), [CLI](../../reference/cli.md), [HTTP API](../../reference/http-api.md).
