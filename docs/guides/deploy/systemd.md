*Context: this is part of [Guides — Deploy](README.md). Start with the primer if you haven't.*

# systemd — single-binary deployment on a Linux host

The simplest production path: one `authserver` binary, one systemd unit, one reverse proxy in front. Suitable for single-instance deployments with SQLite or single-instance Postgres. For multi-node, see [Helm](helm.md) or [Raw manifests](kubernetes-raw.md).

## What you'll achieve in 15 minutes

- A hardened systemd unit running `authserver serve`.
- TLS terminated by Caddy (auto) or nginx (Let's Encrypt).
- A systemd timer running `authserver purge` (see [Backup & purge](backup-and-purge.md)).

## Prereqs

- Linux host with systemd 245+ (Ubuntu 22.04 / Debian 12 / RHEL 9 or newer).
- `openssl`; `curl`; a publicly resolvable DNS name pointing at the host.
- Reverse-proxy binary: Caddy 2 (simplest TLS) or nginx + certbot.
- Read [Configuration](configuration.md) first — pick storage / signing-key store.

---

## Steps

### 1. Install the binary

```bash
# Verified against the GitHub Releases asset naming
curl -fsSL https://github.com/authplane/authserver/releases/latest/download/authserver-linux-amd64 \
  -o /usr/local/bin/authserver
chmod +x /usr/local/bin/authserver
authserver version  # see docs/reference/cli.md#cli-version
```

### 2. Create the service user and directories

```bash
useradd --system --no-create-home --shell /usr/sbin/nologin authserver
mkdir -p /var/lib/authserver/keys /etc/authserver
chown -R authserver:authserver /var/lib/authserver
chmod 700 /var/lib/authserver/keys
```

### 3. Write `/etc/authserver/config.yaml`

Minimum viable production config (verified against [`docs/reference/configuration.md`](../../reference/configuration.md)):

```yaml
server:
  issuer: https://auth.example.com      # AUTHPLANE_SERVER_ISSUER
  address: ":9000"
  shutdown_wait: 20s                    # match TimeoutStopSec below

storage:
  driver: sqlite                        # or "postgres" — see configuration.md
  sqlite:
    path: /var/lib/authserver/authserver.db
    wal: true

signing:
  algorithm: ES256
  key_store: keyfile
  key_path: /var/lib/authserver/keys

session:
  secret: ""                            # injected via systemd EnvironmentFile
  secure: true
  same_site: lax

admin:
  enabled: true
  address: "127.0.0.1:9001"             # loopback-only; reverse proxy never touches it
  api_key: ""                           # injected via systemd EnvironmentFile

observability:
  logging:  { level: info, format: json }
  metrics:  { provider: prometheus, path: /metrics }

server:
  allowed_origins: ["https://app.example.com"]   # required for browser MCP clients
```

Lock the file down (it does not contain secrets, but it does contain the resource layout):

```bash
chown authserver:authserver /etc/authserver/config.yaml
chmod 600 /etc/authserver/config.yaml
```

### 4. Inject secrets via an EnvironmentFile

```bash
cat >/etc/authserver/secrets.env <<EOF
AUTHPLANE_SESSION_SECRET=$(openssl rand -hex 32)
AUTHPLANE_ADMIN_API_KEY=$(openssl rand -hex 32)
EOF
chown root:authserver /etc/authserver/secrets.env
chmod 640 /etc/authserver/secrets.env
```

Env var names verified against [`docs/reference/env-vars.md`](../../reference/env-vars.md).

### 5. Write the systemd unit

`/etc/systemd/system/authserver.service`:

```ini
[Unit]
Description=Authplane MCP Authorization Server
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=authserver
Group=authserver
EnvironmentFile=/etc/authserver/secrets.env
ExecStart=/usr/local/bin/authserver serve --config /etc/authserver/config.yaml
Restart=on-failure
RestartSec=5
LimitNOFILE=65536

# Match server.shutdown_wait + a small margin
TimeoutStopSec=30s
KillSignal=SIGTERM

# Hardening
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/lib/authserver
PrivateTmp=true
PrivateDevices=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true

[Install]
WantedBy=multi-user.target
```

Enable and start:

```bash
systemctl daemon-reload
systemctl enable --now authserver
journalctl -u authserver -f
```

### 6. Reverse proxy

**Caddy** — TLS handled automatically via Let's Encrypt:

```caddyfile
auth.example.com {
    reverse_proxy 127.0.0.1:9000
}
```

**nginx** — TLS via certbot:

```nginx
server {
    listen 443 ssl http2;
    server_name auth.example.com;
    ssl_certificate     /etc/letsencrypt/live/auth.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/auth.example.com/privkey.pem;
    location / {
        proxy_pass http://127.0.0.1:9000;
        proxy_set_header Host              $host;
        proxy_set_header X-Real-IP         $remote_addr;
        proxy_set_header X-Forwarded-For   $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

The admin port (`:9001`) stays on loopback — access the Admin UI via `ssh -L 9001:127.0.0.1:9001` then visit `http://localhost:9001/admin/ui/`.

### 7. Firewall

```bash
ufw allow 443/tcp
ufw deny  9000/tcp
ufw deny  9001/tcp
```

### 8. Schedule the purge timer

`authserver purge` is **not** run automatically by `serve`. Wire a `systemd.timer` — see [Backup & purge → systemd timer](backup-and-purge.md#systemd-timer).

## Verify

```bash
# Public discovery (through the reverse proxy)
curl -fsS https://auth.example.com/.well-known/oauth-authorization-server | jq -r .issuer

# Health probe
curl -fsS https://auth.example.com/health | jq .

# Admin (loopback only)
source /etc/authserver/secrets.env
curl -fsS -H "Authorization: Bearer $AUTHPLANE_ADMIN_API_KEY" \
  http://127.0.0.1:9001/admin/stats | jq .

# systemd state
systemctl is-active authserver && echo OK
```

## Runbook — day-2 operations

### Graceful shutdown

`authserver serve` traps `SIGTERM` / `SIGINT`, drains the public server then the admin server, bounded by [`server.shutdown_wait`](../../reference/configuration.md#config-server) (default `10s`, env [`AUTHPLANE_SERVER_SHUTDOWN_WAIT`](../../reference/env-vars.md)). Keep `TimeoutStopSec` in the unit ≥ `shutdown_wait` + a small margin; the systemd default of 90s is comfortably above the authserver default.

### Signing-key reload (SIGHUP)

```bash
systemctl kill -s HUP authserver
journalctl -u authserver --since '1 minute ago' | grep 'signing keys reloaded'
```

Useful after rotating on-disk keys out of band (e.g. Vault Transit token roll, manual key file replacement). No connections are dropped.

### Signing-key rotation

```bash
# Verified against docs/reference/cli.md#cli-admin-key-rotate
sudo -u authserver authserver admin key rotate --config /etc/authserver/config.yaml
```

Zero-downtime. The previous key stays in the JWKS until its tokens expire; the new key becomes `current` and is signed-with immediately. See [Operate → Key rotation](../operate/key-rotation.md) for policy guidance.

### Migrations on upgrade

`serve` runs `Migrate(ctx)` on boot before binding listeners — no manual step is required for a normal upgrade. If you want a pre-flight gate:

```bash
sudo -u authserver authserver migrate --config /etc/authserver/config.yaml
# Verified against docs/reference/cli.md#cli-migrate
```

Migrations are idempotent — repeated runs no-op when the schema is current.

### Upgrade procedure

```bash
systemctl stop authserver
cp /usr/local/bin/authserver /usr/local/bin/authserver.bak
curl -fsSL https://github.com/authplane/authserver/releases/latest/download/authserver-linux-amd64 \
  -o /usr/local/bin/authserver
chmod +x /usr/local/bin/authserver
systemctl start authserver
```

### Backup

SQLite — online backup, no downtime:

```bash
sqlite3 /var/lib/authserver/authserver.db ".backup /var/backups/authserver-$(date +%Y%m%d).db"
tar czf /var/backups/keys-$(date +%Y%m%d).tar.gz -C /var/lib/authserver keys
```

Signing keys must be backed up — without them every outstanding JWT is unverifiable. For full coverage (Postgres, Vault) see [Backup & purge](backup-and-purge.md).

## What can go wrong

| Symptom | Likely cause | Fix |
| --- | --- | --- |
| `boot rejected: admin.api_key is required` in journal | `AUTHPLANE_ADMIN_API_KEY` missing from `secrets.env` or < 16 chars | Regenerate (`openssl rand -hex 32`), restart unit. Default-blocklist tokens (`changeme`, `dev-admin-key`, etc.) are also rejected. |
| `Permission denied` on `/var/lib/authserver/keys` | wrong owner after `chown` step skipped | `chown -R authserver:authserver /var/lib/authserver && chmod 700 /var/lib/authserver/keys`. |
| In-flight requests SIGKILLed on `systemctl restart` | `TimeoutStopSec` < `server.shutdown_wait` | Raise `TimeoutStopSec` to match, or lower `shutdown_wait`. |
| Browser MCP client fails CORS preflight | startup `WARN CORS is disabled` because [`server.allowed_origins`](../../reference/configuration.md#config-server) is empty | Set [`AUTHPLANE_SERVER_ALLOWED_ORIGINS`](../../reference/env-vars.md) to your origin list (or `*` for dev). |
| All clients get `invalid_token` after rotate | JWKS-cache TTL on the verifier (SDKs default to 1 h) | Wait for the verifier's cache, or force-refresh; rotation itself is zero-downtime on the authserver side. |
| DB tables grow unbounded | No purge timer wired | Follow [Backup & purge → systemd timer](backup-and-purge.md#systemd-timer). |

## See also

- [Docker Compose](docker-compose.md) — same workloads in containers.
- [Helm](helm.md) — Kubernetes path.
- [HashiCorp Vault Transit](hashicorp-vault-transit.md) — replace the keyfile store with Vault.
- [Backup & purge](backup-and-purge.md) — purge timer + SQLite/Postgres backup recipes.
- [`docs/reference/cli.md`](../../reference/cli.md) — every subcommand and flag.
