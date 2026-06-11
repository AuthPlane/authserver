# Identity and federation

*Context: this is part of [Concepts](README.md). Start with the primer if you haven't.*

Authplane needs a user identity attached to every user-facing token. There
are three supported sources of that identity, and you pick by configuration
— not by deployment.

## The three modes

| Stack | Authplane mode | What "login" means for the user |
|-------|----------------|---------------------------------|
| You're the only IdP | direct user auth | Email/password handled by authserver. |
| Existing OIDC IdP (Okta/Entra/Google Workspace) | federation | authserver redirects to your IdP for login, consumes the OIDC ID token, then issues authserver tokens. |
| Trusted upstream AS that issues identity assertions | [XAA](glossary.md#glossary-xaa) (RFC 7523) | Upstream AS signs a JWT asserting the user's identity; your client exchanges that assertion at `/oauth/token` via [JWT Bearer](glossary.md#glossary-jwt-bearer). |

You can mix the first two — a deployment can have local users *and* a
federated OIDC IdP active simultaneously. XAA is its own thing: it has no
login UI because the upstream AS already authenticated the user.

## Direct user auth

The simplest mode. authserver owns the user table, passwords are bcrypt'd,
the login page is served at `/login`. Sufficient for self-hosted single-team
deployments and for getting started locally.

Concerns to know about:

- Session cookies are HMAC-signed with `session.secret` (HttpOnly, Secure
  in production, SameSite=Lax).
- Brute force is throttled by per-IP rate limits and account lockout (see
  [Threat model](threat-model.md#t5-credential-brute-force)).
- Password reset is not built in — operators manage user accounts via the
  admin API.

## OIDC federation

When you already have an IdP, point authserver at it. authserver becomes
the OAuth AS your MCP clients talk to, but logins are delegated to the
upstream OIDC provider.

```
MCP client → authserver /authorize
              → 302 to IdP /authorize (Okta/Entra/...)
              → user logs in at IdP
              → IdP redirects back to authserver /oidc/callback
              → authserver verifies ID token, mints local user (if new)
              → continues OAuth flow, redirects to client with code
```

The user's [`sub`](glossary.md#glossary-jwt) in authserver-issued tokens is
authserver's local user ID, **not** the upstream IdP's `sub`. authserver
records the upstream `sub` separately so subsequent logins find the same
user.

This is sometimes called "AS-of-ASes" — authserver is the AS that MCP
servers trust; the upstream IdP is the AS that authserver trusts.

## XAA — eXternal Authorization Assertion

When an upstream system already issues short-lived signed identity tokens
(your enterprise SSO, a partner organization's AS, or another Authplane
instance), the client can present that JWT directly to authserver via the
JWT Bearer grant ([RFC 7523](https://datatracker.ietf.org/doc/html/rfc7523),
§2.1):

```
POST /oauth/token
grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer
assertion=<upstream-AS-signed JWT asserting the user's identity>
client_id=...
client_secret=...
```

authserver verifies the assertion's signature against the upstream's JWKS
(configured per upstream issuer), checks `iss`/`aud`/`exp`, looks up or
provisions the local user, and mints an authserver access token tied to
that user.

XAA is the right tool when:

- The user has no interactive browser session with authserver.
- A trusted upstream component (a vault, another AS, a service mesh) needs
  to mint tokens *on behalf of* users it has independently authenticated.
- You're chaining Authplane deployments — a regional AS asserting to a
  hub AS.

XAA is **not** the right tool for a generic backend service that wants its
own token — that's the [client credentials grant](glossary.md#glossary-client-credentials-grant).
It's also not the right tool for unattended bots that need upstream
provider access; for that, see the service-account-user pattern in the
token exchange guide.

## How identity propagates into tokens

Whatever the source, once authserver has a local user the token shape is
the same:

```json
{
  "iss": "https://as.example.com",
  "sub": "<local user_id>",
  "aud": "<resource-uri>",
  "scope": "...",
  "client_id": "<acting client>"
}
```

The `sub` is always authserver's local user ID. Downstream resource
servers don't see (or care about) which upstream IdP authenticated the
user — they only see the AS-signed token. This is what lets you change
identity backends without breaking any MCP server.

## Where to go next

- [Delegation and agent chains](delegation-and-agent-chains.md) — how an
  agent acts on behalf of an authenticated user.
- [Tokens and claims](tokens-and-claims.md) — the full claim shape.
- [Configuration reference](../reference/configuration.md) — the
  `oidc:` and `xaa:` config sections.
