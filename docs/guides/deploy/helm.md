*Context: this is part of [Guides — Deploy](README.md). Start with the primer if you haven't.*

# Helm — the recommended Kubernetes path

The Helm chart at [`charts/authplane/`](../../../charts/authplane/) is the production-shaped Kubernetes deployment. It wires Postgres, secret management, init-container DB wait, Vault Transit, ingress (separate paths for public + admin), HPA, PDB, NetworkPolicy, and ServiceMonitor.

## What you'll achieve in 15 minutes

- An authserver Deployment with replicas + ServiceMonitor scrape.
- Separate Ingress for the public OAuth surface and the admin surface (IP-allowlist friendly).
- Secrets sourced from a pre-created Kubernetes `Secret` (GitOps-friendly).

## Prereqs

- Kubernetes 1.26+.
- Helm 3.8+.
- A reachable Postgres (managed service, in-cluster, or the chart's Bitnami subchart for dev).
- TLS termination (cert-manager + ingress-nginx is the assumed default).
- Read [Configuration](configuration.md) for the values you're about to set.

## Steps

### 1. Install the chart

From source (recommended while iterating):

```bash
git clone https://github.com/authplane/authserver.git
cd authserver
helm dependency update charts/authplane
```

From OCI:

```bash
helm install authplane oci://ghcr.io/authplane/charts/authplane \
  --version 0.3.0 -f values-production.yaml
```

### 2. Pre-create the secrets (production)

Auto-generated `secrets.*` values **rotate on every `helm upgrade`** — never use them outside dev. Mint once and reference:

```bash
kubectl create secret generic authplane-secrets \
  --from-literal=session-secret=$(openssl rand -hex 32) \
  --from-literal=admin-api-key=$(openssl rand -hex 32)
```

Both keys are validated at boot — `admin-api-key` < 16 chars or in the default blocklist (`changeme`, `dev-admin-key`, …) is rejected. See [Configuration → Secrets](configuration.md#secrets-you-must-mint).

### 3. Production values

```yaml
# values-production.yaml
replicaCount: 3

image:
  repository: authplane/authserver
  tag: ""        # default to .Chart.AppVersion; pin for repeatability

config:
  server:
    issuer: https://auth.example.com    # AUTHPLANE_SERVER_ISSUER
    shutdown_wait: 20s
    allowed_origins:                     # required for browser-based MCP clients
      - https://app.example.com
  storage:
    driver: postgres                     # AUTHPLANE_STORAGE_DRIVER
    postgres:
      max_conns: 25
  signing:
    algorithm: ES256
    key_store: postgres_key              # multi-replica safe; needs data_encryption
  data_encryption:
    driver: aes_master
  session:
    secure: true
    same_site: lax
  admin:
    address: ":9001"
  client_credentials:
    enabled: true                        # most MCP integrations need this
  observability:
    logging:  { level: info, format: json }
    metrics:  { provider: prometheus }

externalDatabase:
  host: postgres.prod.svc
  port: 5432
  database: authplane
  sslmode: require
  existingSecret: authplane-db
  existingSecretKey: dsn                  # full DSN in one secret key

secrets:
  existingSecret: authplane-secrets       # contains session-secret + admin-api-key

resources:
  requests: { cpu: 100m, memory: 128Mi }
  limits:   { cpu: 1,    memory: 512Mi }

autoscaling:
  enabled: true
  minReplicas: 3
  maxReplicas: 8
  targetCPUUtilizationPercentage: 70

podDisruptionBudget:
  enabled: true
  minAvailable: 2

networkPolicy:
  enabled: true

serviceMonitor:
  enabled: true
  interval: 15s

ingress:
  enabled: true
  className: nginx
  annotations:
    cert-manager.io/cluster-issuer: letsencrypt-prod
  hosts:
    - host: auth.example.com
      paths: [{ path: /, pathType: Prefix }]
  tls:
    - secretName: auth-tls
      hosts: [auth.example.com]

adminIngress:
  enabled: true
  className: nginx
  annotations:
    cert-manager.io/cluster-issuer: letsencrypt-prod
    nginx.ingress.kubernetes.io/whitelist-source-range: 10.0.0.0/8
  hosts:
    - host: auth-admin.internal.example.com
      paths: [{ path: /, pathType: Prefix }]
  tls:
    - secretName: auth-admin-tls
      hosts: [auth-admin.internal.example.com]
```

Pre-create the Postgres-DSN secret:

```bash
kubectl create secret generic authplane-db \
  --from-literal=dsn="postgres://authplane:$PASS@postgres.prod.svc:5432/authplane?sslmode=require"
```

### 4. Install

```bash
helm install authplane charts/authplane -f values-production.yaml --create-namespace -n authplane
kubectl -n authplane rollout status deploy/authplane --timeout=120s
```

Migrations run automatically inside the main container (`authserver serve` calls `Migrate(ctx)` before binding); the chart's init container only waits for Postgres to be reachable.

## Verify

```bash
# Public surface via Ingress
curl -fsS https://auth.example.com/.well-known/oauth-authorization-server | jq -r .issuer
curl -fsS https://auth.example.com/health | jq .

# Admin surface (allowlisted source)
ADMIN_KEY=$(kubectl -n authplane get secret authplane-secrets -o jsonpath='{.data.admin-api-key}' | base64 -d)
curl -fsS -H "Authorization: Bearer $ADMIN_KEY" \
  https://auth-admin.internal.example.com/admin/stats | jq .

# Prometheus is scraping
kubectl -n authplane get servicemonitor authplane -o yaml | grep -A2 endpoints

# PDB honoured
kubectl -n authplane get pdb authplane
```

## Vault Transit signing

Set [`vault.signing.enabled: true`](../../../charts/authplane/values.yaml) and the chart flips [`AUTHPLANE_SIGNING_KEY_STORE`](../../reference/env-vars.md) to `vault_transit` and injects the connection env vars:

```yaml
vault:
  signing:
    enabled: true
    address: https://vault.vault.svc:8200
    mount: transit
    keyName: authserver-signing
    auth:
      method: approle
      existingSecret: vault-signing-creds   # keys: vault-approle-role-id, vault-approle-secret-id
```

Vault is not vendored — bring your own. For setup, see [HashiCorp Vault Transit](hashicorp-vault-transit.md).

## OIDC federation (Google / Okta / Dex)

```yaml
config:
  oidc:
    enabled: true
    issuer: https://accounts.google.com
    client_id: "YOUR_CLIENT_ID"
    client_secret_ref: CONNECTOR_OIDC_CLIENT_SECRET   # secret injected via extraEnv

extraEnv:
  - name: AUTHPLANE_OIDC_CLIENT_SECRET
    valueFrom: { secretKeyRef: { name: oidc-creds, key: client-secret } }
```

Required-when rules: `oidc.issuer`, `oidc.client_id`, `oidc.client_secret`, and `oidc.redirect_uri` must all be HTTPS in production. Verified against [`docs/reference/configuration.md#config-oidc`](../../reference/configuration.md#config-oidc).

## Scaling and shutdown

- **Stateless on Postgres** — scale horizontally with HPA. Tune `config.storage.postgres.max_conns × replicas` against your Postgres connection limit (RDS / Cloud SQL caps are easy to hit).
- **Sessions are signed cookies** — no affinity needed.
- **`terminationGracePeriodSeconds`** — Helm inherits the cluster default (30 s). If you raise `config.server.shutdown_wait` above that, patch the Deployment via a post-render kustomize overlay; otherwise kubelet SIGKILLs the pod mid-drain. See [systemd → SIGTERM](systemd.md#graceful-shutdown).

## Runbook

- **Upgrade**: `helm upgrade authplane charts/authplane -f values-production.yaml --atomic --timeout 5m`. Migrations apply on pod boot. `--atomic` rolls back on failure.
- **Rotate signing key**: `kubectl exec deploy/authplane -- authserver admin key rotate` (verified against [`cli.md#cli-admin-key-rotate`](../../reference/cli.md#cli-admin-key-rotate)). With `signing.key_store: postgres_key`, NOTIFY propagates to all replicas in milliseconds.
- **Purge schedule**: deploy the CronJob from [Backup & purge → Kubernetes CronJob](backup-and-purge.md#kubernetes-cronjob).
- **Uninstall**: `helm uninstall authplane -n authplane`. PVCs are not deleted automatically — `kubectl delete pvc -l app.kubernetes.io/instance=authplane` if you want a clean slate.

## What can go wrong

| Symptom | Likely cause | Fix |
| --- | --- | --- |
| Pods stuck `Init:0/1` | Init container can't reach Postgres | Check `externalDatabase.host`, NetworkPolicy egress, DSN secret. `kubectl describe pod` shows DNS / TCP errors. |
| `helm upgrade` rotates secrets unexpectedly | Inline `secrets.sessionSecret` / `secrets.adminApiKey` regenerate each upgrade | Switch to `secrets.existingSecret: authplane-secrets`. |
| New replicas miss key rotations | Single-PVC `keyfile` store with `ReadWriteOnce` | Switch `config.signing.key_store` to `postgres_key` (or `vault_transit`); RWO PVCs can't be shared across nodes. |
| Browser MCP clients fail OAuth | `config.server.allowed_origins` empty (startup `WARN` emitted) | Add your app origins; see [Configuration → cross-cutting](configuration.md). |
| `terminationGracePeriodSeconds` clips drains | Cluster default (30 s) < `shutdown_wait` | Post-render-patch the Deployment to set `terminationGracePeriodSeconds: <shutdown_wait>+10`. |
| Admin UI accessible from the public internet | `adminIngress` shares hostname with public ingress | Use a distinct hostname + IP allowlist annotation; or set `adminIngress.enabled: false` and `kubectl port-forward`. |

## See also

- [Kubernetes overview](kubernetes.md) — Helm vs raw vs kind decision tree.
- [Raw manifests](kubernetes-raw.md) — same shape without Helm.
- [kind local testing](kind-local-testing.md) — reproduce the chart on a laptop.
- [`charts/authplane/values.yaml`](../../../charts/authplane/values.yaml) — every configurable value.
- [`docs/reference/configuration.md`](../../reference/configuration.md), [`docs/reference/env-vars.md`](../../reference/env-vars.md), [`docs/reference/cli.md`](../../reference/cli.md).
