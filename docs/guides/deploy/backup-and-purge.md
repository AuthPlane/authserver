*Context: this is part of [Guides — Deploy](README.md). Start with the primer if you haven't.*

# Backup & purge — day-2 not-optional

`authserver serve` does **not** purge expired data. Schedule `authserver purge` externally — without it, `dpop_nonces`, `refresh_tokens`, `sessions`, and assertion JTI tables grow unbounded. This recipe wires the schedule for every deploy target and shows the backup procedures for SQLite, PostgreSQL, and signing keys.

## What you'll achieve in 15 minutes

- A scheduled `authserver purge` on systemd, Docker Compose, or Kubernetes.
- A working backup procedure for the storage and signing-key paths you chose.
- Alerts on purge failure (exit-code non-zero → page).

## Prereqs

- A running authserver (any deploy target). This recipe schedules cleanup; it does not deploy the AS.
- Knowledge of which storage driver you picked — see [Configuration](configuration.md).
- Read the [purge command reference](../../reference/cli.md#cli-purge) for the flag definitions cited below.

## What `authserver purge` does

Each pass deletes expired rows from these tables (the `--only` names are exact, validated against `purgeOpFactories` in `cmd/authserver/purge.go` and surfaced by [`cli.md#cli-purge`](../../reference/cli.md#cli-purge)):

| `--only` name | Table cleaned |
| --- | --- |
| `assertion-jti` | XAA / JWT-bearer assertion JTIs (replay defence) |
| `connect-pending-states` | Broker upstream-connect pending states |
| `dpop-nonces` | DPoP proof JTIs and server nonces |
| `jti` | Revoked-token JTIs (RFC 7009) |
| `machine-tokens` | Expired client-credentials tokens |
| `refresh-tokens` | Expired refresh tokens. Families are **not** purged: `token_families` keeps one row per authorization-code exchange since install (rows leave only when their client or user is deleted) |
| `sessions` | Expired user sessions |

Default: all targets. `--timeout` defaults to `10m`; pass `--timeout=0` to disable the deadline (still aborts on SIGINT/SIGTERM). Cited from [`docs/reference/cli.md#cli-purge`](../../reference/cli.md#cli-purge).

A daily run handles most deployments; busy DPoP / machine-token issuers should run hourly. The DELETE queries are lightweight and do not block OAuth traffic.

---

## systemd timer

`/etc/systemd/system/authserver-purge.service`:

```ini
[Unit]
Description=authserver expired-data purge
After=network-online.target

[Service]
Type=oneshot
User=authserver
Group=authserver
EnvironmentFile=/etc/authserver/secrets.env
ExecStart=/usr/local/bin/authserver purge --config /etc/authserver/config.yaml
```

`/etc/systemd/system/authserver-purge.timer`:

```ini
[Unit]
Description=Run authserver purge hourly

[Timer]
OnCalendar=hourly
RandomizedDelaySec=5m
Persistent=true

[Install]
WantedBy=timers.target
```

```bash
systemctl daemon-reload
systemctl enable --now authserver-purge.timer
systemctl list-timers authserver-purge.timer
journalctl -u authserver-purge.service --since '1 day ago'
```

Wire `OnFailure=alert-shim.service` (or your wrapper) so the journal exit code becomes a pageable signal.

---

## Docker Compose sidecar

Add a second service that reuses the same image and storage env. The `profiles: ["purge"]` key keeps it out of the default `compose up`:

```yaml
# Append to deploy/docker-compose.yml (or your own compose file)
services:
  authserver-purge:
    image: authplane/authserver:latest
    command: ["purge"]                  # see docs/reference/cli.md#cli-purge
    environment:
      AUTHPLANE_STORAGE_DRIVER: postgres
      AUTHPLANE_STORAGE_POSTGRES_DSN: postgres://authserver:${POSTGRES_PASSWORD}@postgres:5432/authserver?sslmode=disable
    depends_on:
      postgres: { condition: service_healthy }
    restart: "no"
    profiles: ["purge"]
```

Trigger from the host cron (preferred — keeps failures visible to standard host monitoring):

```cron
# crontab -e — runs hourly
0 * * * * cd /opt/authserver && docker compose run --rm authserver-purge >> /var/log/authserver-purge.log 2>&1
```

For SQLite-on-volume deployments, mount the same `authserver-data` volume into the sidecar.

---

## Kubernetes CronJob

```yaml
apiVersion: batch/v1
kind: CronJob
metadata: { name: authserver-purge, namespace: authplane }
spec:
  schedule: "0 * * * *"             # hourly
  concurrencyPolicy: Forbid          # never overlap
  successfulJobsHistoryLimit: 3
  failedJobsHistoryLimit: 3
  jobTemplate:
    spec:
      backoffLimit: 1
      template:
        spec:
          restartPolicy: OnFailure
          containers:
            - name: purge
              image: authplane/authserver:latest
              args: ["purge", "--timeout=5m"]   # docs/reference/cli.md#cli-purge
              envFrom:
                - configMapRef: { name: authplane-config }
                - secretRef:    { name: authplane-secrets }
              resources:
                requests: { cpu: 50m,  memory: 64Mi }
                limits:   { cpu: 500m, memory: 256Mi }
```

The CronJob **must** share the same storage env (`AUTHPLANE_STORAGE_*`) as the `serve` Deployment — it talks to the same database. For alerting, hook a Job-failure handler (Argo CD `failed` event, kube-state-metrics `kube_job_failed`, Cloud-provider equivalent).

---

## Selective purging

`--only=name1,name2` runs a subset. Run high-churn tables hourly, the rest daily:

```bash
# Hourly — high-churn tables; verified against docs/reference/cli.md#cli-purge
authserver purge --only=dpop-nonces,assertion-jti,jti --config /etc/authserver/config.yaml

# Daily — everything else
authserver purge --config /etc/authserver/config.yaml
```

## Exit codes and alerting

`authserver purge` exits non-zero if any target fails or the context is cancelled. Per-table failures log at `ERROR` with a `table=<name>` attribute; the command continues with remaining tables and fails at the end. Wire the exit status into your alerting:

- systemd → `OnFailure=` directive.
- Docker / cron → wrapper script that pages on non-zero.
- Kubernetes → `kube_job_failed` Prometheus alert.

---

## Backup

### SQLite

Online backup, no downtime:

```bash
sqlite3 /var/lib/authserver/authserver.db \
  ".backup /var/backups/authserver-$(date +%Y%m%d).db"
tar czf /var/backups/keys-$(date +%Y%m%d).tar.gz -C /var/lib/authserver keys
```

For Compose, snapshot the volume:

```bash
docker compose stop authserver
docker run --rm -v authserver-data:/data -v "$PWD/backup:/backup" alpine \
  tar czf /backup/authserver-$(date +%Y%m%d).tar.gz -C /data .
docker compose start authserver
```

### PostgreSQL backup

```bash
# Hot dump from a primary or read replica
pg_dump --format=custom \
  "$AUTHPLANE_STORAGE_POSTGRES_DSN" \
  > /var/backups/authplane-$(date +%Y%m%d).pgdump
```

For Kubernetes, use a CronJob with the `postgres:18-alpine` image and the same DSN secret. For managed Postgres (RDS / Cloud SQL), rely on the provider's PITR snapshots and verify they cover the `signing_keys` table when [`signing.key_store: postgres_key`](../../reference/configuration.md#config-signing) is in use.

### Signing keys

The keyfile store writes to `signing.key_path` (default `/var/lib/authserver/keys`). **Lose this directory and every outstanding JWT becomes unverifiable.** Back it up alongside the DB, on the same cadence:

```bash
tar czf /var/backups/keys-$(date +%Y%m%d).tar.gz -C /var/lib/authserver keys
```

For Vault Transit (`signing.key_store: vault_transit`): the keys live in Vault; back up Vault storage on its own schedule and confirm the Transit key version is recoverable. See [HashiCorp Vault Transit → Runbook](hashicorp-vault-transit.md#runbook).

For Postgres-backed keys (`signing.key_store: postgres_key`): a normal `pg_dump` is sufficient — the keys are AES-encrypted rows in `signing_keys`. Back up the master key (in `data_encryption.aes_master.key_env`) **separately**; if you lose the master, the rows are unrecoverable.

## Verify

```bash
# Manual one-shot — should print INFO purge completed lines per target
authserver purge --timeout=5m --config /etc/authserver/config.yaml

# Confirm tables shrink
psql "$AUTHPLANE_STORAGE_POSTGRES_DSN" -c \
  "SELECT relname, n_live_tup FROM pg_stat_user_tables WHERE relname IN ('dpop_nonces','refresh_tokens','sessions','jti');"

# Confirm the schedule is enabled
systemctl is-enabled authserver-purge.timer            # systemd
kubectl get cronjob authserver-purge -n authplane      # kubernetes
```

## What can go wrong

| Symptom | Likely cause | Fix |
| --- | --- | --- |
| DB grows forever despite Job running | CronJob/timer points at a different DSN than `serve` | Diff the env: same `AUTHPLANE_STORAGE_*` values must be present in both. |
| Purge exits with `context deadline exceeded` | Default `--timeout=10m` insufficient on a backlog | Run once with `--timeout=0` to clear the backlog; restore the default afterwards. |
| `connect-pending-states` table grows even when not using broker | Broker resource registered earlier, never deregistered | Either remove the resource, or include `connect-pending-states` in the daily run (it's in the default set). |
| Signing-key backup restore yields unverifiable tokens | Master key (`data_encryption.aes_master.key_env`) not restored alongside the DB | Back up master key separately and restore both atomically. |
| Vault Transit signing fails after DR | Vault snapshot not current, or Transit key min-decryption-version raised | Restore Vault snapshot; verify with `vault read transit/keys/authserver-signing`. See [Vault Transit → Runbook](hashicorp-vault-transit.md#runbook). |
| Alerting silent on purge failure | No `OnFailure=` / Job-failure handler | Wire systemd `OnFailure=` or Kubernetes `kube_job_failed` alert. |

## See also

- [`docs/reference/cli.md#cli-purge`](../../reference/cli.md#cli-purge) — `--only`, `--timeout`, exit semantics.
- [`docs/reference/configuration.md#config-storage`](../../reference/configuration.md#config-storage) — storage driver options.
- [HashiCorp Vault Transit](hashicorp-vault-transit.md) — Vault DR / rotation runbook.
- [Operate → Key rotation](../operate/key-rotation.md) — pair with rotation policy.
