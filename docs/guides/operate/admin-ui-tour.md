# Admin UI tour — click-driven day-2 ops
*Context: this is part of [Guides — Operate](README.md). Start with the primer if you haven't.*

The Admin UI is a React SPA embedded in the `authserver` binary, served from the admin port (default `:9001`) at `/admin/ui/`. It shares its service layer with the REST API and CLI — every click emits the same audit row that the equivalent `curl` would.

## What you'll achieve in 5 minutes

- Open the UI and authenticate.
- Locate every operational page and its CLI counterpart.
- Know which two operations the UI deliberately does not cover.

## Prereqs

- `admin.enabled: true` and `admin.api_key` set. See [`admin` in configuration.md](../../reference/configuration.md).
- A reachable `:9001` (firewall / port-publish / kube-port-forward).
- A browser. The UI ships static — no external network calls.

## Steps

### 1. Set the API key

Prefer the env var so the secret never lands in YAML:

```bash
export AUTHPLANE_ADMIN_API_KEY="$(openssl rand -hex 32)"
```

See [`AUTHPLANE_ADMIN_API_KEY` in env-vars.md](../../reference/env-vars.md).

### 2. Open the UI

```
http://<admin-host>:9001/admin/ui/
```

For a local instance: `http://localhost:9001/admin/ui/`. For a kubectl-port-forward path:

```bash
kubectl -n authplane port-forward svc/authserver 9001:9001
```

### 3. Paste the API key when prompted

The UI stores it in `sessionStorage` — cleared when the browser tab closes, never written to disk. The same key works as `Authorization: Bearer …` for the REST API.

> **Never expose `:9001` to the internet.** The admin surface has full management access. Keep it behind a VPN, an internal LB with allowlisted source IPs, or an mTLS terminator.

## Verify

- The Overview page renders four counters (clients, users, active tokens, revoked tokens) without an auth error.
- A trivial mutation (e.g. toggling a user enabled/disabled) shows up immediately in the Audit Log page.

## The 12 pages

Each page maps 1:1 to a CLI / REST counterpart documented in [Admin CLI](admin-cli.md) and the route catalog in [`docs/reference/http-api.md`](../../reference/http-api.md).

| Page | What you can do | CLI / API counterpart |
|---|---|---|
| **Overview** | Server snapshot — totals for clients, users, active tokens (24h), revoked tokens. | `GET /admin/stats` |
| **Clients** | Create, edit, suspend, revoke, reactivate OAuth clients; rotate client secrets. | [`authserver admin client …`](admin-cli.md#recipe-clients) |
| **Users** | List, enable, disable users. **User creation is CLI / REST only.** | [`authserver admin user …`](admin-cli.md#recipe-users) |
| **Resources** | Manage unified Mint + Broker resources, scopes, policies. | [`authserver admin resource …`](admin-cli.md#recipe-resources-mint--broker) |
| **Fronting** | Manage cross-Mint fronting links (declare which source covers which target scopes). | [`authserver admin fronting …`](admin-cli.md#recipe-fronting-links) |
| **Providers** | Configure upstream Broker providers (GitHub, Slack, Google, …). | [`authserver admin provider …`](admin-cli.md#recipe-broker-providers) |
| **Grants** | View and revoke consent grants and broker grants. | [`authserver admin grant …`](admin-cli.md#recipe-grants-admin-consent--broker) |
| **Issuances** | Audit and revoke individual tokens — forensic search by user / client / JTI. | [`authserver admin issuance …`](admin-cli.md#recipe-issuance-admin) |
| **Tokens** | Browse issued tokens; inspect JWTs (Issued and Inspector tabs). | `GET /admin/issuances` + JWKS verification |
| **Signing Keys** | View the current key set; test the JWKS endpoint. **Rotation is CLI / REST only.** | [`authserver admin key …`](admin-cli.md#recipe-signing-keys) + [Key rotation](key-rotation.md) |
| **Audit Log** | Browse audit events; filter by action / actor. | [`GET /admin/audit`](admin-cli.md#recipe-audit-query-cli-equivalent) |
| **System** | View runtime configuration and server status. | Schema in [`docs/reference/configuration.md`](../../reference/configuration.md). |

### UI preferences

Dark / light theme, collapsible sidebar, three font sizes. Stored in browser `localStorage` (per-browser, per-origin — they do not sync across machines).

## When to reach for the UI vs the CLI / API

| Task | Surface |
|---|---|
| Routine browsing — "what clients exist?", "audit events for the last hour" | UI |
| Single mutation with operator review — suspend a suspicious client, revoke a grant | UI |
| Scripted setup — seed clients / resources / providers from CI | CLI ([admin-cli.md](admin-cli.md)) |
| Bulk operation — rotate every client secret in an environment | CLI in a shell loop |
| Forensic export — pull every matching audit row into JSON | REST (`GET /admin/audit?…`) |
| Signing key rotation | CLI ([Key rotation](key-rotation.md)) |
| User creation | CLI / REST |

## What can go wrong

| Symptom | Likely cause | Fix |
|---|---|---|
| `401 Unauthorized` on every UI call | Wrong API key pasted | Check the env / YAML value matches what was pasted. |
| UI won't load at `:9001` | Browser cannot reach the admin port | Check firewall; in Docker, ensure `-p 9001:9001`; in k8s, port-forward. |
| UI reachable but pages are blank | Admin server disabled at config layer | Set `admin.enabled: true` ([`admin` in configuration.md](../../reference/configuration.md)). |
| UI shows stale data after a CLI mutation | UI local React state; some pages need refresh | Hit reload or navigate away and back — the REST API is the source of truth. |
| `Tokens` page shows valid JWT as "rejected" | The Inspector uses your live JWKS; a kid mismatch hints at a stale or out-of-rotation key | Compare the JWT's `kid` to `/admin/keys`; force a JWKS refresh on the verifier. |

For mutation-level 4xx / 5xx, see the [response-code table in admin-cli.md](admin-cli.md#what-can-go-wrong).

## See also

- [Admin CLI](admin-cli.md) — every operation in scripted form.
- [Key rotation](key-rotation.md) — the one operation the UI cannot do.
- [Audit & forensics](audit-and-forensics.md) — what to look for after a click.
- [`docs/reference/configuration.md`](../../reference/configuration.md) — `admin.*` and `server.*`.
- [`docs/reference/env-vars.md`](../../reference/env-vars.md) — `AUTHPLANE_ADMIN_*`.
