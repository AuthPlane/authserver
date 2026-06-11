# Authplane Helm Chart

[Authplane](https://github.com/authplane/authserver) is a self-hosted OAuth 2.1 Authorization Server for the Model Context Protocol (MCP).

## Prerequisites

- Kubernetes 1.26+
- Helm 3.8+
- PostgreSQL (recommended) or SQLite for storage

## Quick Start

### With built-in PostgreSQL

```bash
helm dependency update charts/authplane

helm install authplane ./charts/authplane \
  --set config.server.issuer=https://auth.example.com \
  --set postgresql.enabled=true \
  --set postgresql.auth.password=changeme \
  --set secrets.sessionSecret=$(openssl rand -hex 32) \
  --set secrets.adminApiKey=$(openssl rand -hex 32)
```

### From OCI registry

```bash
helm install authplane oci://ghcr.io/authplane/charts/authplane \
  --version 0.1.0 \
  -f values-production.yaml
```

## Configuration

See [values.yaml](values.yaml) for all configurable parameters.

> **Warning:** Auto-generated secrets change on every `helm upgrade`. For production, always set explicit values or use `secrets.existingSecret`.

## Full Documentation

For complete deployment guides — including PostgreSQL/SQLite setup, OIDC federation (Google, Okta), Vault Transit, ingress, secrets management, observability, production checklist, and local testing with kind — see:

- **[Helm Chart Deployment Guide](../../docs/deployment/kubernetes/helm-chart.md)** — Full reference
- **[Local Testing with kind](../../docs/deployment/kubernetes/kind-testing.md)** — Step-by-step local development
- **[Kubernetes Overview](../../docs/deployment/kubernetes/index.md)** — All Kubernetes deployment approaches

## Uninstallation

```bash
helm uninstall authplane
```

> **Note:** PVCs are not deleted automatically. Remove them manually if no longer needed.
