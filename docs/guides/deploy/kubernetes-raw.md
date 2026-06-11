*Context: this is part of [Guides — Deploy](README.md). Start with the primer if you haven't.*

# Kubernetes — raw manifests (Helm-free)

For GitOps pipelines (Argo CD with Kustomize, Flux + Jsonnet, hand-rolled YAML) where Helm isn't on the path. The manifests below mirror what the [Helm chart](helm.md) renders, minus templating.

## What you'll achieve in 10 minutes

- A `Deployment` + dual `Service` + dual `Ingress` topology, plus a PDB.
- Secrets sourced from a `Secret`, config from a `ConfigMap`, DB DSN from another `Secret`.
- A working multi-replica deploy when paired with `signing.key_store: postgres_key`.

## Prereqs

- Kubernetes 1.26+ with a TLS-terminating Ingress controller and cert-manager.
- A reachable Postgres (`pg_isready` from inside the cluster).
- Read [Configuration](configuration.md) — pick storage + signing-key store before you copy YAML.
- Read [Kubernetes overview](kubernetes.md) — confirm raw manifests are actually what you want.

## Steps

### 1. Namespace

```yaml
apiVersion: v1
kind: Namespace
metadata: { name: authplane }
```

### 2. Secrets

```bash
# Verified against docs/reference/env-vars.md (AUTHPLANE_SESSION_SECRET, AUTHPLANE_ADMIN_API_KEY)
kubectl create secret generic authplane-secrets -n authplane \
  --from-literal=session-secret=$(openssl rand -hex 32) \
  --from-literal=admin-api-key=$(openssl rand -hex 32) \
  --from-literal=postgres-dsn="postgres://authplane:$PG_PASS@postgres.prod.svc:5432/authplane?sslmode=require"
```

For real GitOps use SealedSecrets / SOPS / External Secrets Operator.

### 3. ConfigMap

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: authplane-config
  namespace: authplane
data:
  config.yaml: |
    server:
      issuer: https://auth.example.com   # AUTHPLANE_SERVER_ISSUER
      address: ":9000"
      shutdown_wait: 20s
      allowed_origins:
        - https://app.example.com
    storage:
      driver: postgres                   # AUTHPLANE_STORAGE_DRIVER
    signing:
      algorithm: ES256
      key_store: postgres_key            # multi-replica safe
      postgres_key:
        encryption_key_env: AUTHPLANE_SIGNING_KEY_ENC
    data_encryption:
      driver: aes_master
      aes_master:
        key_env: AUTHPLANE_DATA_ENC_KEY
    session:
      secure: true
      same_site: lax
    admin:
      enabled: true
      address: ":9001"
    client_credentials:
      enabled: true
    observability:
      logging: { level: info, format: json }
      metrics: { provider: prometheus, path: /metrics }
```

### 4. Deployment

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: authplane
  namespace: authplane
spec:
  replicas: 3
  selector: { matchLabels: { app: authplane } }
  template:
    metadata:
      labels: { app: authplane }
      annotations:
        prometheus.io/scrape: "true"
        prometheus.io/port:   "9001"        # /metrics lives on the admin port
        prometheus.io/path:   "/metrics"
    spec:
      terminationGracePeriodSeconds: 30      # >= server.shutdown_wait
      securityContext:
        runAsNonRoot: true
        runAsUser: 65534
        fsGroup: 65534
      containers:
        - name: authserver
          image: authplane/authserver:latest   # pin to a released tag (e.g. :0.1.0-rc1) in production
          args: ["serve", "--config", "/config/config.yaml"]
          ports:
            - { name: http,  containerPort: 9000 }
            - { name: admin, containerPort: 9001 }
          env:
            - name: AUTHPLANE_SESSION_SECRET
              valueFrom: { secretKeyRef: { name: authplane-secrets, key: session-secret } }
            - name: AUTHPLANE_ADMIN_API_KEY
              valueFrom: { secretKeyRef: { name: authplane-secrets, key: admin-api-key } }
            - name: AUTHPLANE_STORAGE_POSTGRES_DSN
              valueFrom: { secretKeyRef: { name: authplane-secrets, key: postgres-dsn } }
            - name: AUTHPLANE_SIGNING_KEY_ENC
              valueFrom: { secretKeyRef: { name: authplane-secrets, key: signing-key-enc } }
            - name: AUTHPLANE_DATA_ENC_KEY
              valueFrom: { secretKeyRef: { name: authplane-secrets, key: data-enc-key } }
          volumeMounts:
            - { name: config, mountPath: /config, readOnly: true }
          livenessProbe:
            httpGet: { path: /health, port: 9000 }
            initialDelaySeconds: 5
            periodSeconds: 10
          readinessProbe:
            httpGet: { path: /health, port: 9000 }
            initialDelaySeconds: 3
            periodSeconds: 5
          resources:
            requests: { cpu: 100m, memory: 128Mi }
            limits:   { cpu: 1,    memory: 512Mi }
      volumes:
        - name: config
          configMap: { name: authplane-config }
```

The init container shown in earlier docs (running `authserver migrate`) is optional — `authserver serve` migrates on boot. Keep an init container only if you want to gate the rollout on Postgres reachability separately from the main container's startup probe.

### 5. Services

```yaml
apiVersion: v1
kind: Service
metadata: { name: authplane, namespace: authplane }
spec:
  selector: { app: authplane }
  ports: [{ name: http, port: 9000, targetPort: http }]
---
apiVersion: v1
kind: Service
metadata: { name: authplane-admin, namespace: authplane }
spec:
  type: ClusterIP                            # never expose externally
  selector: { app: authplane }
  ports: [{ name: admin, port: 9001, targetPort: admin }]
```

### 6. Ingress (public only)

```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: authplane
  namespace: authplane
  annotations:
    cert-manager.io/cluster-issuer: letsencrypt-prod
spec:
  tls: [{ hosts: [auth.example.com], secretName: authplane-tls }]
  rules:
    - host: auth.example.com
      http:
        paths:
          - path: /
            pathType: Prefix
            backend: { service: { name: authplane, port: { number: 9000 } } }
```

Access the Admin UI via `kubectl -n authplane port-forward svc/authplane-admin 9001:9001`. If you must expose admin via Ingress, use a separate hostname + an IP-allowlist annotation — see [Helm → ingress](helm.md#3-production-values) for the pattern.

### 7. Pod Disruption Budget

```yaml
apiVersion: policy/v1
kind: PodDisruptionBudget
metadata: { name: authplane, namespace: authplane }
spec:
  minAvailable: 2
  selector: { matchLabels: { app: authplane } }
```

### 8. Schedule the purge CronJob

`authserver purge` is **not** automatic. See [Backup & purge → Kubernetes CronJob](backup-and-purge.md#kubernetes-cronjob) for the manifest.

## Verify

```bash
kubectl -n authplane rollout status deploy/authplane --timeout=120s
kubectl -n authplane port-forward svc/authplane 9000:9000 &

curl -fsS http://localhost:9000/.well-known/oauth-authorization-server | jq -r .issuer
curl -fsS http://localhost:9000/health | jq .

ADMIN_KEY=$(kubectl -n authplane get secret authplane-secrets -o jsonpath='{.data.admin-api-key}' | base64 -d)
kubectl -n authplane port-forward svc/authplane-admin 9001:9001 &
curl -fsS -H "Authorization: Bearer $ADMIN_KEY" http://localhost:9001/admin/stats | jq .
```

## Scaling

- **Replicas**: stateless when `storage.driver: postgres` AND `signing.key_store ∈ {postgres_key, vault_transit}`. Scale via HPA.
- **Connection budget**: total open connections = `storage.postgres.max_conns × replicas`. RDS / Cloud SQL plans cap on a few hundred — tune.
- **No session affinity needed**: sessions are signed cookies, not server-side.

## Runbook

- **Rolling update**: `kubectl set image deploy/authplane authserver=...`. Migrations apply on each new pod's startup. Old pods drain bounded by `terminationGracePeriodSeconds` (≥ `server.shutdown_wait`).
- **Rotate signing key**: `kubectl exec deploy/authplane -- authserver admin key rotate` (verified against [`cli.md#cli-admin-key-rotate`](../../reference/cli.md#cli-admin-key-rotate)). With `postgres_key`, NOTIFY propagates within milliseconds.
- **Backup**: see [Backup & purge → PostgreSQL](backup-and-purge.md#postgresql-backup).

## What can go wrong

| Symptom | Likely cause | Fix |
| --- | --- | --- |
| Pods CrashLoopBackOff with `admin.api_key is required` | `AUTHPLANE_ADMIN_API_KEY` env not injected from the Secret | Confirm `valueFrom.secretKeyRef` paths match Secret keys; re-roll. |
| Multi-replica JWKS inconsistent | Replicas using `keyfile` with a `ReadWriteOnce` PVC on different nodes | Switch `signing.key_store` to `postgres_key` (or `vault_transit`); remove the PVC. |
| In-flight requests aborted on rollout | `terminationGracePeriodSeconds` too low | Bump to ≥ `server.shutdown_wait` + LB drain. |
| Browser MCP client fails CORS | `server.allowed_origins` empty (startup `WARN`) | Add origins to the ConfigMap; bounce pods. |
| Admin Service receives external traffic | Admin Service typed `LoadBalancer` or behind public Ingress | Set `type: ClusterIP`; expose only via `kubectl port-forward` or a private ingress. |
| DB tables grow unbounded | No purge CronJob | Deploy from [Backup & purge → Kubernetes CronJob](backup-and-purge.md#kubernetes-cronjob). |

## See also

- [Helm](helm.md) — same shape, generated.
- [Kubernetes overview](kubernetes.md).
- [kind local testing](kind-local-testing.md).
- [`docs/reference/configuration.md`](../../reference/configuration.md), [`docs/reference/env-vars.md`](../../reference/env-vars.md).
