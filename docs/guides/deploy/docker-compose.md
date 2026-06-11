*Context: this is part of [Guides — Deploy](README.md). Start with the primer if you haven't.*

# Docker Compose — the fastest production-shaped deploy

The repo ships three reference Compose files under [`deploy/`](../../../deploy/). Each is a working stack you can `docker compose up`. Pick the one whose storage / observability / Vault posture matches your target.

| File | Storage | Observability | Vault | Use it for |
| --- | --- | --- | --- | --- |
| [`deploy/docker-compose.sqlite.yml`](../../../deploy/docker-compose.sqlite.yml) | SQLite (volume) | none | none | One-host dev / smoke tests / homelab. |
| [`deploy/docker-compose.yml`](../../../deploy/docker-compose.yml) | PostgreSQL 18 | LGTM (Tempo+Loki+Mimir+Grafana+Prometheus+Alloy) | none | Production-shaped single host with full observability. |
| [`deploy/docker-compose.vault.yml`](../../../deploy/docker-compose.vault.yml) | PostgreSQL 18 | LGTM | Vault dev mode | Validating the Vault Transit signing path before Helm. |

The LGTM observability stack is factored into [`deploy/observability/docker-compose.observability.yml`](../../../deploy/observability/docker-compose.observability.yml) and pulled in via the `include:` directive. You do not need a separate "observability-only" compose file — start the LGTM stack alone with `docker compose -f deploy/observability/docker-compose.observability.yml up -d`.

## What you'll achieve in 5 minutes

- A running authserver on `:9000` (public) + `:9001` (admin).
- A persisted DB (SQLite volume or Postgres container).
- A working `/.well-known/oauth-authorization-server` response.

## Prereqs

- Docker Engine 24+ with the Compose v2 plugin (`docker compose`, not `docker-compose`).
- `openssl` and `jq` on the host.
- 1.5 GB free RAM for the full-observability stack (Grafana + LGTM are not tiny).
- Read [Configuration](configuration.md) first — decide storage + secrets before you run anything non-localhost.

---

## Recipe A — SQLite, no observability

Use [`deploy/docker-compose.sqlite.yml`](../../../deploy/docker-compose.sqlite.yml). It binds `:9000` + `:9001` directly and writes the DB to the `authserver-data` named volume.

### 1. Mint required secrets

```bash
# Verified against docs/reference/env-vars.md (AUTHPLANE_SESSION_SECRET, AUTHPLANE_ADMIN_API_KEY)
export AUTHPLANE_SESSION_SECRET="$(openssl rand -hex 32)"
export AUTHPLANE_ADMIN_API_KEY="$(openssl rand -hex 32)"
```

Both are validated at boot when the issuer is non-localhost. The compose file uses `${VAR:?...}` syntax so missing values fail fast with a readable error.

### 2. Bring the stack up

```bash
# Verified against deploy/docker-compose.sqlite.yml
docker compose -f deploy/docker-compose.sqlite.yml up --build -d
```

### 3. Provision a demo client (optional)

To exercise the running AS end-to-end (register a Resource, register an OAuth client, mint a token, call a protected MCP endpoint), pick one of the runnable examples and follow its README:

- [`examples/go/01-mcp-server-basic/`](../../../examples/go/01-mcp-server-basic/)
- [`examples/python/01-mcp-server-basic/`](../../../examples/python/01-mcp-server-basic/)
- [`examples/typescript/01-mcp-server-basic/`](../../../examples/typescript/01-mcp-server-basic/)

Each example's `make verify` drives the full admin-API + token + tool-call flow against the AS already running here.

## Verify

```bash
# Public discovery endpoint — issuer should match server.issuer
curl -fsS http://localhost:9000/.well-known/oauth-authorization-server | jq -r .issuer

# Health probe (public port)
curl -fsS http://localhost:9000/health | jq .

# Admin stats (requires the API key)
curl -fsS -H "Authorization: Bearer $AUTHPLANE_ADMIN_API_KEY" \
  http://localhost:9001/admin/stats | jq .
```

---

## Recipe B — PostgreSQL + LGTM observability

Use [`deploy/docker-compose.yml`](../../../deploy/docker-compose.yml). It runs Postgres 18, authserver, and the full Grafana LGTM stack.

### 1. Same secrets, plus Postgres password

```bash
export AUTHPLANE_SESSION_SECRET="$(openssl rand -hex 32)"
export AUTHPLANE_ADMIN_API_KEY="$(openssl rand -hex 32)"
# Postgres password is baked into the compose file as "authserver" — change it for any
# non-local use by editing the POSTGRES_PASSWORD and AUTHPLANE_STORAGE_POSTGRES_DSN
# values in deploy/docker-compose.yml.
```

### 2. Start everything

```bash
# Verified against deploy/docker-compose.yml
docker compose -f deploy/docker-compose.yml up --build -d
docker compose -f deploy/docker-compose.yml ps
```

Migrations run automatically on first boot — `authserver serve` calls `Migrate(ctx)` before binding the listener. See [systemd → Boot-time behavior](systemd.md#migrations-on-upgrade).

### 3. Open Grafana

Default at `http://localhost:3000` (admin/admin on first login). Prometheus is scraping `authserver:9001/metrics`; logs and traces flow through Alloy at `:4317` (OTLP gRPC).

## Verify

```bash
# Same probes as Recipe A
curl -fsS http://localhost:9000/.well-known/oauth-authorization-server | jq -r .issuer

# Confirm metrics scraping works — see internal/observability/metrics.go for names
curl -fsS http://localhost:9001/metrics | grep -E '^authserver_|^authplane_' | head -5
```

The metric name prefix is currently mixed: `authserver_*` for the OAuth core, `authplane_*` for newer subsystems (DPoP, token exchange, client credentials, XAA). Treat both as live. See [Observability](observability-prometheus-otel.md) for the full table.

---

## Recipe C — PostgreSQL + Vault Transit (signing)

Use [`deploy/docker-compose.vault.yml`](../../../deploy/docker-compose.vault.yml). It adds a Vault container (dev mode, root token: `root`) and a one-shot `vault-init` that enables the Transit engine and creates an `ecdsa-p256` key.

### 1. Secrets + bring up

```bash
export AUTHPLANE_SESSION_SECRET="$(openssl rand -hex 32)"
export AUTHPLANE_ADMIN_API_KEY="$(openssl rand -hex 32)"
# Verified against deploy/docker-compose.vault.yml
docker compose -f deploy/docker-compose.vault.yml up --build -d
```

The compose file sets [`AUTHPLANE_SIGNING_KEY_STORE=vault_transit`](../../reference/env-vars.md), [`AUTHPLANE_VAULT_ADDR=http://vault:8200`](../../reference/env-vars.md), and `AUTHPLANE_VAULT_TOKEN=root`. For non-dev, follow [HashiCorp Vault Transit](hashicorp-vault-transit.md).

### 2. Confirm Vault is signing tokens

```bash
docker compose -f deploy/docker-compose.vault.yml logs vault-init
# Should end with: "vault-init: transit engine enabled and key created"

curl -fsS http://localhost:9000/.well-known/jwks.json | jq -r '.keys[].kid'
# Each key id corresponds to a Vault Transit key version.
```

---

## Reverse proxy with Caddy (any recipe)

Drop in alongside any of the three. Caddy terminates TLS on `:443`, reverse-proxies to authserver on `:9000`, and never touches the admin port.

```yaml
# Add to any of the compose files
  caddy:
    image: caddy:2-alpine
    ports: ["80:80", "443:443"]
    volumes:
      - ./Caddyfile:/etc/caddy/Caddyfile
      - caddy-data:/data
    depends_on: [authserver]

volumes:
  caddy-data:
```

`Caddyfile`:

```
auth.example.com {
    reverse_proxy authserver:9000
}
```

Set [`AUTHPLANE_SERVER_ISSUER`](../../reference/env-vars.md) to `https://auth.example.com` and [`AUTHPLANE_SESSION_SECURE`](../../reference/env-vars.md) to `true` once TLS is live.

## Grace-period & purge ops

- **`stop_grace_period`** — set ≥ `server.shutdown_wait` (default `10s`, env [`AUTHPLANE_SERVER_SHUTDOWN_WAIT`](../../reference/env-vars.md)) on the `authserver` service; otherwise `docker stop` SIGKILLs in-flight requests. See [systemd → SIGTERM](systemd.md#graceful-shutdown).
- **Purge scheduling** — `authserver purge` is not automatic. Add a sidecar service (see [Backup & purge → Docker Compose sidecar](backup-and-purge.md#docker-compose-sidecar)).

## Healthcheck note — the authserver image is distroless

The published `authplane/authserver:latest` image is built on
`gcr.io/distroless/static-debian12:nonroot`. It has no shell, no `wget`,
no `curl`, no `ls` — only the `authserver` binary. A naive Compose
healthcheck like `test: ["CMD", "wget", "--spider", "..."]` will report
the container unhealthy because `wget` doesn't exist, and dependent
services using `depends_on: { authserver: { condition: service_healthy } }`
will never start.

If you need a healthcheck on the authserver service, use a **TCP
probe** from the dependent service (Compose's `depends_on` does NOT
support TCP probes — orchestrate this via your dependent app's own
retry loop) or skip the in-container healthcheck and trust
`depends_on: [authserver]` plus the SDK's own startup retry. The
reference compose files in `deploy/` deliberately do not add a
healthcheck for this reason.

## What can go wrong

| Symptom | Likely cause | Fix |
| --- | --- | --- |
| `set AUTHPLANE_SESSION_SECRET to a strong random value` on `compose up` | Required env var unset (compose uses `${VAR:?...}`) | Export both `AUTHPLANE_SESSION_SECRET` and `AUTHPLANE_ADMIN_API_KEY` before `compose up`. |
| Dependent container won't start; healthcheck on `authserver` reports unhealthy | Healthcheck uses `wget` / `curl` against a distroless image (binaries don't exist) | Remove the healthcheck, or replace with a TCP probe from the dependent service. See "Healthcheck note" above. |
| `pg_isready` retries forever / authserver never boots | Postgres password mismatch between `POSTGRES_PASSWORD` and `AUTHPLANE_STORAGE_POSTGRES_DSN` | Edit the compose file so both match, or move the DSN into the env. |
| Tokens issued but JWKS is empty | Vault recipe with `vault-init` not yet completed | `docker compose logs vault-init` — wait for the success line; restart `authserver` if needed. |
| Browser-based MCP client returns 403 on `/oauth/token` | `AUTHPLANE_SERVER_ALLOWED_ORIGINS` empty → CORS preflight rejected (startup `WARN` is emitted) | Set it to your app origin (or `*` for local dev) in the compose env block. |
| `docker stop` clips in-flight requests | `stop_grace_period` < `server.shutdown_wait` | Set `stop_grace_period: 30s` on the `authserver` service. |
| Tables grow forever in production | No purge scheduler wired | Add the sidecar from [Backup & purge → Docker Compose sidecar](backup-and-purge.md#docker-compose-sidecar). |

## Runbook

- **Upgrade**: `docker compose pull authserver && docker compose up -d`. Migrations are forward-only and idempotent (see [systemd → Boot-time behavior](systemd.md#migrations-on-upgrade)).
- **Backup**: Recipe A — stop authserver, tar the `authserver-data` volume. Recipes B/C — see [Backup & purge → PostgreSQL](backup-and-purge.md#postgresql-backup).
- **Rotate signing keys**: `docker compose exec authserver authserver admin key rotate` (verified against [`cli.md#cli-admin-key-rotate`](../../reference/cli.md#cli-admin-key-rotate)). Zero-downtime; previous key remains in JWKS until expiry.

## See also

- [systemd / standalone binary](systemd.md) — same workloads without Docker.
- [Helm](helm.md) — Kubernetes path with the same patterns.
- [Backup & purge](backup-and-purge.md) — sidecar / cron schedules for the purge command.
- [`docs/reference/configuration.md`](../../reference/configuration.md) and [`docs/reference/env-vars.md`](../../reference/env-vars.md) — full schemas.
