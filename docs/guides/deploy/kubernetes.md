*Context: this is part of [Guides — Deploy](README.md). Start with the primer if you haven't.*

# Kubernetes — pick a path

Three ways to run authserver on Kubernetes. None are mutually exclusive — many teams run kind locally, then Helm in staging/prod.

## What you'll achieve in 2 minutes

- Decide between Helm, raw manifests, and kind for your situation.
- Know which page to read next.

## Prereqs

- Kubernetes 1.26+ for any production target.
- A TLS termination story (Ingress controller, service mesh, or LoadBalancer with cert-manager).
- Read [Configuration](configuration.md) — you'll be setting the same knobs regardless of path.

## Decision matrix

| Path | Best for | What you get | Read next |
| --- | --- | --- | --- |
| [**Helm**](helm.md) | Production deployments | Postgres subchart, init-container wait, Vault Transit, HPA, PDB, NetworkPolicy, ServiceMonitor, dual ingresses for public/admin | [Helm](helm.md) |
| [**Raw manifests**](kubernetes-raw.md) | GitOps pipelines that don't use Helm (Argo, Flux + Kustomize, Jsonnet) | Copy-paste YAML, no chart dependency, full control over every object | [Raw manifests](kubernetes-raw.md) |
| [**kind**](kind-local-testing.md) | Local end-to-end testing | Run the Helm chart on your laptop; reproduce OIDC + MCP Inspector flows | [kind local testing](kind-local-testing.md) |

## Recommended path

- **Production** → Helm. The chart already encodes the answers to "do you want NetworkPolicy?", "how do I keep the admin port internal?", and "how do I pre-create the secrets so `helm upgrade` doesn't rotate them?". Start [here](helm.md).
- **GitOps without Helm** → start from the [raw manifests](kubernetes-raw.md), wrap in Kustomize / Jsonnet, commit the rendered YAML.
- **Pre-prod validation** → use [kind](kind-local-testing.md) to reproduce the production Helm chart locally before each release.

## Cross-cutting concerns (all paths)

- **Admin port stays internal.** The admin surface (`:9001`) hosts the Admin API + UI + `/metrics`. Never expose it via the public Ingress. Use a separate `adminIngress` with an IP allowlist (Helm) or `ClusterIP` + `kubectl port-forward` (raw).
- **Signing keys across replicas.** A single PVC with `ReadWriteOnce` only works when all replicas land on one node. For real multi-node, use [`signing.key_store: postgres_key`](../../reference/configuration.md#config-signing) or [`vault_transit`](hashicorp-vault-transit.md).
- **Graceful shutdown.** Set `terminationGracePeriodSeconds` ≥ [`server.shutdown_wait`](../../reference/configuration.md#config-server) + LB drain time. See [systemd → SIGTERM](systemd.md#graceful-shutdown).
- **Purge as a CronJob.** `authserver purge` is **not** automatic. Deploy the CronJob in [Backup & purge → Kubernetes CronJob](backup-and-purge.md#kubernetes-cronjob).

## Verify (works on any path)

```bash
# Same probes regardless of how you deployed
kubectl -n <ns> port-forward svc/authplane 9000:9000 &
curl -fsS http://localhost:9000/.well-known/oauth-authorization-server | jq -r .issuer
curl -fsS http://localhost:9000/health | jq .
```

## What can go wrong

| Symptom | Likely cause | Fix |
| --- | --- | --- |
| Two replicas, signing keys diverge | `keyfile` store with `ReadWriteOnce` PVC; pods on different nodes | Switch to `postgres_key` or `vault_transit`. |
| Admin endpoints reachable from internet | Admin path mounted on the public Ingress | Move to a separate hostname + IP-allowlist; or keep `ClusterIP` only. |
| In-flight requests aborted on rolling update | `terminationGracePeriodSeconds` < `shutdown_wait` | Raise grace period; default is 30 s. |
| Browser-based MCP clients fail CORS preflight against the public Ingress | [`server.allowed_origins`](../../reference/configuration.md#config-server) empty (boot logs `WARN`) | Set [`AUTHPLANE_SERVER_ALLOWED_ORIGINS`](../../reference/env-vars.md) on the Deployment / values. |
| Tables grow unbounded over weeks | No `authserver purge` CronJob wired | Deploy from [Backup & purge → Kubernetes CronJob](backup-and-purge.md#kubernetes-cronjob). |

## See also

- [Helm](helm.md) — recommended production deploy.
- [Raw manifests](kubernetes-raw.md) — Helm-free path.
- [kind local testing](kind-local-testing.md) — laptop end-to-end.
- [`charts/authplane/values.yaml`](../../../charts/authplane/values.yaml) — every Helm value.
