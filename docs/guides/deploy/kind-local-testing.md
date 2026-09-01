*Context: this is part of [Guides — Deploy](README.md). Start with the primer if you haven't.*

# kind — reproduce the Helm chart on your laptop

Run the production Helm chart end-to-end on a local kind cluster: Postgres, OIDC federation, MCP Inspector flows. Useful for pre-release validation and for repro-ing a customer's Helm setup on your machine.

## What you'll achieve in 20 minutes

- A kind cluster running the [Helm chart](helm.md) with either SQLite or Postgres.
- A working OIDC login (Google or Okta) routed through the local cluster.
- An OAuth flow driven by MCP Inspector against a demo MCP server.

## Prereqs

- Docker Desktop (or any Docker daemon) running.
- [`kind`](https://kind.sigs.k8s.io/), [`helm`](https://helm.sh/) 3.8+, [`kubectl`](https://kubernetes.io/docs/tasks/tools/), `jq`, `openssl`.
- Go 1.26.6+ if you want to build the image from source (matches `go.mod`).
- Read [Helm](helm.md) first — this page deliberately leaves chart values shallow.

## Steps

### 1. Create the cluster

```bash
kind create cluster --name authplane-test
kubectl cluster-info --context kind-authplane-test
```

### 2. Build and load the image into kind

kind does not pull from registries that require auth by default. Build locally and side-load:

```bash
docker build -f build/Dockerfile -t authplane/authserver:dev .
kind load docker-image authplane/authserver:dev --name authplane-test
```

### 3. Update chart dependencies

```bash
helm dependency update charts/authplane
```

If the Bitnami Postgres image pull fails inside kind, pre-pull and side-load it the same way:

```bash
docker pull bitnami/postgresql:17.2.0-debian-12-r10
kind load docker-image bitnami/postgresql:17.2.0-debian-12-r10 --name authplane-test
```

The exact tag is in `charts/authplane/charts/postgresql-*.tgz`.

### 4. Install — SQLite (simplest)

```bash
helm install authplane charts/authplane \
  --set image.tag=dev \
  --set image.pullPolicy=IfNotPresent \
  --set config.server.issuer=http://localhost:9000 \
  --set config.storage.driver=sqlite \
  --set config.session.secure=false \
  --set persistence.enabled=true \
  --set persistence.size=256Mi \
  --set replicaCount=1 \
  --set secrets.sessionSecret=$(openssl rand -hex 32) \
  --set secrets.adminApiKey=$(openssl rand -hex 32)

kubectl wait --for=condition=ready pod -l app.kubernetes.io/name=authplane --timeout=120s
kubectl port-forward svc/authplane 9000:9000 9001:9001 &
```

### 4b. Install — Postgres (closer to prod)

```bash
helm install authplane charts/authplane \
  --set image.tag=dev \
  --set image.pullPolicy=IfNotPresent \
  --set config.server.issuer=http://localhost:9000 \
  --set config.storage.driver=postgres \
  --set config.session.secure=false \
  --set postgresql.enabled=true \
  --set postgresql.auth.password=testpassword \
  --set secrets.sessionSecret=$(openssl rand -hex 32) \
  --set secrets.adminApiKey=$(openssl rand -hex 32)
```

Init container waits for Postgres; `kubectl get pods -w` should show the main container start once the DB is ready.

### 5. Run helm tests

```bash
helm test authplane
```

The test pod calls `/.well-known/oauth-authorization-server` and asserts a `200`. See [`http-api.md#http-public-well-known-oauth-authorization-server`](../../reference/http-api.md).

## Verify

```bash
curl -fsS http://localhost:9000/.well-known/oauth-authorization-server | jq -r .issuer
curl -fsS http://localhost:9000/health | jq .

ADMIN_KEY=$(kubectl get secret authplane-secrets -o jsonpath='{.data.admin-api-key}' | base64 -d)
curl -fsS -H "Authorization: Bearer $ADMIN_KEY" http://localhost:9001/admin/stats | jq .
```

## Enable OIDC federation (Google)

1. Create an OAuth 2.0 Client in [Google Cloud Console](https://console.cloud.google.com/) → APIs & Services → Credentials.
2. Authorized redirect URI: `http://localhost:9000/oidc/callback`.
3. `helm upgrade` with OIDC values:

<!-- gate1-skip: requires Google Cloud Console OAuth client credentials (interactive setup, per-user secrets) -->
```bash
GOOGLE_CLIENT_ID=...
GOOGLE_CLIENT_SECRET=...

helm upgrade authplane charts/authplane \
  --set image.tag=dev \
  --set image.pullPolicy=IfNotPresent \
  --set config.server.issuer=http://localhost:9000 \
  --set config.storage.driver=sqlite \
  --set config.session.secure=false \
  --set persistence.enabled=true \
  --set replicaCount=1 \
  --set secrets.sessionSecret=$(openssl rand -hex 32) \
  --set secrets.adminApiKey=$(openssl rand -hex 32) \
  --set config.oidc.enabled=true \
  --set config.oidc.issuer=https://accounts.google.com \
  --set config.oidc.client_id="$GOOGLE_CLIENT_ID" \
  --set config.oidc.client_secret="$GOOGLE_CLIENT_SECRET" \
  --set config.oidc.display_name="Google Workspace" \
  --set config.oidc.include_groups_scope=false \
  --set config.client_credentials.enabled=true \
  --set 'config.server.allowed_origins[0]=*'

# kubectl port-forward dies on pod restart — restart it
pkill -f "kubectl port-forward" 2>/dev/null
kubectl wait --for=condition=ready pod -l app.kubernetes.io/name=authplane --timeout=120s
kubectl port-forward svc/authplane 9000:9000 9001:9001 &
```

Open `http://localhost:9000/login` in an **incognito window** (avoids stale session cookies). You should see a "Continue with Google Workspace" button.

Field names verified against [`docs/reference/configuration.md#config-oidc`](../../reference/configuration.md#config-oidc).

## End-to-end with MCP Inspector

### 1. Start a demo MCP server

Pick a language and follow its example README to bring up an MCP server that points at the kind-deployed AS. The simplest path is one of the tier-01 examples:

- [`examples/go/01-mcp-server-basic/`](../../../examples/go/01-mcp-server-basic/)
- [`examples/python/01-mcp-server-basic/`](../../../examples/python/01-mcp-server-basic/)
- [`examples/typescript/01-mcp-server-basic/`](../../../examples/typescript/01-mcp-server-basic/)

Each example assumes the AS is reachable on the host; with the `kubectl port-forward` above that holds. Override `AUTHPLANE_ISSUER=http://localhost:9000` if it isn't already the example's default.

### 2. Register it as a unified resource

```bash
ADMIN_KEY=$(kubectl get secret authplane-secrets -o jsonpath='{.data.admin-api-key}' | base64 -d)

curl -fsS -X POST http://localhost:9001/admin/resources \
  -H "Authorization: Bearer $ADMIN_KEY" -H "Content-Type: application/json" \
  -d '{
    "slug": "demo-mcp",
    "display_name": "Demo MCP Server",
    "uri": "http://localhost:8080/mcp",
    "backend_kind": "mint",
    "scopes": [{"name": "mcp:echo"}, {"name": "mcp:greet"}]
  }' | jq .
```

The example tier-01 servers serve on `:8080` at `/mcp` — if you changed `MCP_PORT` or the mount path in the example, mirror that here byte-for-byte.

### 3. Launch MCP Inspector

```bash
npx @modelcontextprotocol/inspector
```

Inspector UI at `http://localhost:6274`. Point it at `http://localhost:8080/mcp`. Use an incognito browser window. Inspector will discover PRM, follow `authorization_server` to authplane, perform DCR, run the auth-code flow.

## Cleanup

```bash
pkill -f "kubectl port-forward" 2>/dev/null
# stop the demo MCP server with the example's `make clean`
kind delete cluster --name authplane-test
```

## What can go wrong

| Symptom | Likely cause | Fix |
| --- | --- | --- |
| Pod stuck `Init:0/1` | Postgres subchart not ready (or image not in kind) | `kubectl logs -l app.kubernetes.io/name=postgresql`; pre-pull + side-load image. |
| `ErrImagePull` for authserver | image not loaded into kind | `kind load docker-image authplane/authserver:dev --name authplane-test`. |
| `kubectl port-forward` dies silently after `helm upgrade` | Pod replaced; old port-forward is gone | Restart: `pkill -f port-forward && kubectl port-forward svc/authplane 9000:9000 9001:9001 &`. |
| OIDC login loops back to the login page | Stale session cookie from previous run | Use a fresh incognito window. |
| Browser MCP client fails CORS | `config.server.allowed_origins` empty | Set `--set 'config.server.allowed_origins[0]=*'` for local testing. |
| `helm test` returns 502 | Pod isn't ready yet; test pod ran too early | `kubectl wait --for=condition=ready pod -l app.kubernetes.io/name=authplane --timeout=120s` then retry. |

## See also

- [Helm](helm.md) — the chart you're testing.
- [Docker Compose](docker-compose.md) — non-Kubernetes local path.
- [`docs/reference/configuration.md`](../../reference/configuration.md), [`docs/reference/cli.md`](../../reference/cli.md).
