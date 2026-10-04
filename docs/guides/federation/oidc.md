# OIDC Federation — Delegate Login to Okta, Entra ID, Google Workspace, or Auth0

*Context: this is part of [Guides — Federation](README.md). Start with the primer if you haven't.*

**Audience:** Operator running Authplane for a team that already has a corporate IdP. After this recipe, users click "Sign in with &lt;your IdP&gt;" on the Authplane login page and Authplane auto-provisions a local account from the ID-token claims on first login and finds it again by the IdP's `sub` on every later one.

## What you'll achieve in 15 minutes

- One upstream OIDC provider wired into Authplane via a single config block (`oidc:`).
- Users authenticated at the IdP land on Authplane with their email and name auto-populated.
- Optionally, local password login disabled — every user must come in via the IdP.

## Prereqs

- Authplane authserver running on an HTTPS issuer URL. See [Deploy guides](../deploy/).
- An OAuth/OIDC application registered with your IdP, with **`https://<your-authserver-domain>/oidc/callback`** in its redirect URIs allowlist.
- The IdP's issuer URL, client ID, and client secret in hand.
- Concept context: [Identity and federation](../../concepts/identity-and-federation.md), [glossary — JWT](../../concepts/glossary.md#glossary-jwt).

## How it works (one paragraph)

User clicks the federation button on Authplane's login page; Authplane redirects to the IdP; the IdP authenticates the user; the IdP redirects back to `/oidc/callback` with an authorization code; Authplane exchanges the code for an ID token, looks the user up by the IdP's subject (`sub`), and creates a new local account on first login, filling `email` and `name` when the IdP sends them. An existing local account is never linked by email. The rest of the OAuth flow (consent, scope grant, token issuance) is unchanged. Full sequence in [Reference → Flow 14](../../reference/flows.md).

## Steps

### 1. Pick your IdP and grab the issuer URL

| IdP | Issuer URL | Notes |
|-----|-----------|-------|
| Google Workspace | `https://accounts.google.com` | Restrict by `hd` claim if you need a single domain. |
| Okta | `https://<your-org>.okta.com` | Use the org URL, not the auth-server URL. |
| Microsoft Entra ID | `https://login.microsoftonline.com/<tenant-id>/v2.0` | Use `common` for multi-tenant apps. |
| Auth0 | `https://<your-tenant>.auth0.com/` | Trailing slash required. |
| Dex (broker for multi-IdP) | `https://dex.example.com` | Use `connector_id` to pre-select a Dex connector. |

### 2. Register the redirect URI at the IdP

Add **exactly** `https://<your-authserver-domain>/oidc/callback` to the IdP's authorized redirect URIs. Trailing slashes, protocol, and port must match exactly. The path `/oidc/callback` is verified against [`docs/reference/http-api.md#http-public-oidc-callback`](../../reference/http-api.md#http-public-oidc-callback).

### 3. Configure Authplane

Add to `config.yaml` (all keys verified against [`docs/reference/configuration.md#config-oidc`](../../reference/configuration.md#config-oidc)):

```yaml
# Verified against docs/reference/configuration.md#config-oidc
oidc:
  enabled: true
  issuer: https://<your-org>.okta.com
  client_id: "0oab1c2d3eFgHiJkL4x7"
  client_secret: "<from IdP — prefer client_secret_ref>"
  display_name: Okta            # button text on the login page
  redirect_uri: https://auth.example.com/oidc/callback
  scopes: [openid, email, profile]
  show_local_login: true        # false disables password login: no form, POST /login answers 404
```

`show_local_login: false` turns local password login off, not just the form:
`POST /login` answers 404 for every account, including any local admin. Only the
browser password flow is affected — the admin API still authenticates with its
API key, and the `authserver admin` CLI works directly against the datastore, so
neither depends on local login. If the IdP becomes unavailable and you need
password sign-in back, set `AUTHPLANE_OIDC_SHOW_LOCAL_LOGIN=true` (or the YAML
key) and restart authserver.

Or via environment variables (verified against [`docs/reference/env-vars.md`](../../reference/env-vars.md)):

<!-- gate1-skip: OIDC client credentials must be obtained from the IdP per-deployment; this block is illustrative -->
```bash
# Verified against docs/reference/env-vars.md (AUTHPLANE_OIDC_*)
export AUTHPLANE_OIDC_ENABLED=true
export AUTHPLANE_OIDC_ISSUER=https://<your-org>.okta.com
export AUTHPLANE_OIDC_CLIENT_ID=0oab1c2d3eFgHiJkL4x7
export AUTHPLANE_OIDC_CLIENT_SECRET=...
export AUTHPLANE_OIDC_REDIRECT_URI=https://auth.example.com/oidc/callback
```

### 4. Per-provider quirks

- **Google Workspace** — to restrict logins to a single Workspace domain, configure the IdP-side hosted-domain restriction (Google's `hd` parameter) on the OAuth app; Authplane does not filter the `hd` claim itself.
- **Microsoft Entra ID** — multi-tenant apps must use `common` in the issuer; Authplane accepts any tenant that the app trusts. To restrict to one tenant, replace `common` with the tenant GUID.
- **Auth0** — issuer URL requires the trailing slash. Without it, JWKS discovery fails.
- **Okta** — confirm you're using the org URL (`https://acme.okta.com`) and not the auth-server URL (`https://acme.okta.com/oauth2/default`). The org URL hosts `/.well-known/openid-configuration` at the root.
- **Dex** — set `oidc.connector_id` to pre-select a connector (`github`, `ldap`, …) so users skip Dex's chooser page.

### 5. Restart and verify the login page

```bash
# Verified against docs/reference/http-api.md#http-public-oidc-start
curl -sI https://auth.example.com/oidc/start
# Expect: 302 redirect to your IdP's /authorize with client_id, scope=openid email profile, state=<csrf-nonce>
```

## Verify end-to-end

1. Open `https://auth.example.com/` in a fresh browser.
2. The login page should now show a button labeled with your `display_name` (e.g. "Sign in with Okta").
3. Click it. You should land at the IdP's login page. Authenticate.
4. The IdP redirects you back to `/oidc/callback`, then to wherever the original `/oauth/authorize` request was headed (or the Authplane home page if you started cold).
5. Confirm a local user was provisioned:

```bash
# Verified against docs/reference/cli.md#cli-admin-user-list
authserver admin user list | grep your-email@example.com
# Expect: one row, federated identity present in the user record
```

## What can go wrong

| Symptom | Likely cause | Fix |
|---------|--------------|-----|
| OIDC button doesn't appear on the login page | `oidc.enabled` is not `true`, or the server didn't reload config | Verify `AUTHPLANE_OIDC_ENABLED=true` (or YAML); restart authserver. |
| "OIDC authentication failed. Please try again." after IdP login | JWKS unreachable, signature failure, or `client_secret` wrong | Tail authserver logs — `WARN OIDC authentication failed error=<reason>` (`handleOIDCCallback` in `api/public/oauth/oidc.go`). Verify the IdP's `/.well-known/openid-configuration` is reachable from authserver's network. |
| IdP returns `redirect_uri mismatch` | The URL registered at the IdP does not exactly match `oidc.redirect_uri` | Compare character-for-character — protocol, host, port, path, and trailing slash all matter. |
| Federated user's account has no email | The IdP did not return an `email` claim in the ID token | Sign-in still works — users are keyed on the IdP's `sub`. To populate the email, add `email` to `oidc.scopes` and expose the claim in the IdP-side app config; it is filled in on the next login. |
| "The email address your identity provider shared is already used by another account" (HTTP 409) on first IdP login | The IdP asserted an email that a local (or another federated) account already holds. Authplane does not link accounts by email, so the login is refused and audited as `user.oidc_login_failed` with `reason=email_in_use` | Decide which account is the user's: give the other account a different email (`authserver admin user update`) or delete it, then retry the IdP login. |
| Redirect loop between Authplane and IdP | `oidc.redirect_uri` points to the IdP, not to Authplane | The redirect URI must be **Authplane's** callback (`/oidc/callback`), not the IdP's. |
| "Invalid or expired state. Please try again." on the callback | Browser cookies blocked, multi-tab login race, or replayed / stale state | One tab per login attempt; ensure the session cookie domain matches the issuer; check `session.secure: true` if issuer is HTTPS. The log line says which check failed — `WARN OIDC state decode failed`, `WARN OIDC state expired`, or `WARN OIDC state cookie mismatch` (`handleOIDCCallback` in `api/public/oauth/oidc.go`). |
| Login works but the user can't reach `/authorize` afterward | `show_local_login: false` and the user has no consent grants yet | Normal first-time path — the consent screen renders next. If it doesn't, check that the OAuth client redirect URI matches. |
| `POST /login` returns 404 | `show_local_login: false` — local password login is disabled | Expected. Sign in through the IdP button, or set `AUTHPLANE_OIDC_SHOW_LOCAL_LOGIN=true` and restart to restore password login. |

## Limitations

- **One upstream OIDC provider per Authplane instance.** For multiple IdPs, front them with [Dex](https://dexidp.io/) and configure Authplane to use Dex as the single upstream.
- **No account linking by email.** Federated users are identified by the IdP's `sub`, not by email. The `email` claim is optional; an email already held by another account blocks that user's first IdP login (see above).
- **No SCIM provisioning yet.** Users are JIT-provisioned on first login. Bulk pre-provisioning is roadmap.

## See also

- [JWT Bearer grant](jwt-bearer-grant.md) — non-interactive sibling for backend assertion exchange.
- [Enterprise-Managed Authorization (XAA)](enterprise-managed-auth-xaa.md) — when you also need per-IdP policy and audit chains.
- [Reference → OIDC callback endpoint](../../reference/http-api.md#http-public-oidc-callback)
- [Topology → OIDC federated login](../../topologies/oidc-federated-login.md) — production deployment diagram.
- [Concepts → Identity and federation](../../concepts/identity-and-federation.md)
