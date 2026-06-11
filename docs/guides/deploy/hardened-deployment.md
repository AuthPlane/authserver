# Hardened Deployment — Production Posture Settings

## What this is about

authserver ships with defaults that prioritize integrator ergonomics and availability — sensible for development, small teams, and the MCP-client integration paths the project is built around. For production deployments where you want stricter behavior at the cost of some convenience, there are a few knobs to flip. This guide lists them, explains the trade-off, and gives the env var to set.

These are not bugs in the defaults. The defaults exist because:
- a stricter setting would break out-of-the-box MCP integrations
- a stricter setting trades availability for security in a way only the operator can decide

But for a hardened production posture, you almost certainly want to flip them.

---

## OAuth: require explicit scope (`oauth.require_scope`)

**Default:** `true` (strict, RFC 6749 §3.3-compliant — reject `/authorize` requests that omit `scope`).

**Loose mode (`false`):** an authorize request without `scope` defaults to the resource's full registered scope set. This exists for MCP clients that omit `scope` from their authorize requests; rather than issuing a zero-scope token that opaquely fails on every tool call, the AS substitutes the catalog. A warning is logged on each substitution.

**Recommendation:** keep the default. If you have to set `false` for a specific MCP integration, set it explicitly in config so the choice is visible and audit it periodically.

```yaml
oauth:
  require_scope: true
```

```bash
AUTHPLANE_OAUTH_REQUIRE_SCOPE=true
```

When `require_scope=false` is observed at startup, the server logs:

```
WARN oauth.require_scope=false: authorize requests without scope default to the resource's full registered scope set; production deployments should set AUTHPLANE_OAUTH_REQUIRE_SCOPE=true
```

---

## Session: fail closed on transient store errors (`session.fail_closed`)

**Default:** `true` (fail-closed) since the 2026-05-18 follow-up audit. Any non-`ErrUserNotFound` error from the user store during the session middleware's user-existence check clears the cookie and the request continues anonymously (downstream handlers redirect to `/login`). A disabled or deleted user cannot ride out a DB outage with a still-valid cookie.

**Override to `false`:** keep the cookie on transient store errors so brief DB outages don't log every user out. Choose this only when uninterrupted browser sessions during outages matter more than immediate revocation of disabled accounts.

```yaml
session:
  fail_closed: true   # default
```

```bash
AUTHPLANE_SESSION_FAIL_CLOSED=false   # opt OUT of secure default
```

Both modes log loudly on the transient error so operators can see the rate:

```
ERROR session: user existence check failed  fail_mode=open  user_id=...
ERROR session: user existence check failed  fail_mode=closed  user_id=...
```

Operators that explicitly set `false` get a startup WARN:

```
WARN session.fail_closed=false explicitly overrides the secure default (true); transient user-store errors will keep sessions valid
```

---

## Admin port: network isolation

The admin port (`/admin/*`, default `:9090`) wraps every JSON API route in API-key middleware with constant-time comparison. The following surfaces on the same port are intentionally NOT API-key-protected:

- `/metrics` — Prometheus scrape; standard convention is unauthenticated
- `/admin/ui/*` — static SPA bundle; auth happens in-app via `/admin/auth/verify`

The model assumes the admin port is on a private network or otherwise network-isolated from untrusted callers. If you expose the admin port directly to the internet, `/metrics` becomes an information-disclosure surface (token-issuance rates, denial reasons, internal SLO data) and the static SPA assets become a fingerprinting surface.

**Recommendation:**
- Bind the admin port to `127.0.0.1` or a private interface (`admin.address: "127.0.0.1:9090"`)
- Reach it over SSH tunnel, VPN, or behind an authenticating reverse proxy
- If you must expose it publicly, put it behind a reverse proxy that requires authentication on `/metrics` and `/admin/ui/*`, and audit the API-key value lifecycle (rotation, storage)

The API-protected routes (`/admin/clients`, `/admin/users`, `/admin/keys`, etc.) are safe to expose because the API key is constant-time-checked, but the unauthenticated surfaces still need network isolation.

---

## Quick checklist

```yaml
oauth:
  require_scope: true       # default — keep it

session:
  fail_closed: true         # default — keep it

admin:
  address: "127.0.0.1:9090" # not 0.0.0.0 in production
```

Set via environment for 12-factor deployments:

```bash
AUTHPLANE_OAUTH_REQUIRE_SCOPE=true
AUTHPLANE_SESSION_FAIL_CLOSED=true
AUTHPLANE_ADMIN_ADDRESS=127.0.0.1:9090
```
