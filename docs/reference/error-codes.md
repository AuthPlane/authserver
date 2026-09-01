# Error Codes — What Went Wrong and How to Fix It

## How authserver reports errors

Every error response from authserver combines OAuth 2.0 error codes (RFC 6749) with RFC 9457 Problem Details:

```json
{
  "error": "invalid_grant",
  "error_description": "the authorization grant is invalid, expired, or revoked",
  "type": "https://docs.authplane.ai/errors/invalid_grant",
  "title": "Bad Request",
  "detail": "the authorization grant is invalid, expired, or revoked",
  "status": 400
}
```

Content-Type: `application/problem+json`

The `error` field is the machine-readable code your client should switch on. The `error_description` is human-readable and explains what happened.

---

## Quick diagnosis — "I got an error, now what?"

### I'm trying to get a token and it failed

```
Is error = "invalid_client"?
  → Your client_id is wrong, your secret is wrong, or the client is suspended.
  → Check: did you copy the client_id and secret correctly? Is the client active?

Is error = "unauthorized_client"?
  → The client exists, but it's not allowed to use this grant type.
  → Check: does the client's grant_types list include the grant you're requesting?
  → Example: you're requesting client_credentials but the client was registered
    with only authorization_code.

Is error = "invalid_grant"?
  → The auth code or refresh token is expired, already used, or invalid.
  → Auth codes expire in 10 minutes and are single-use.
  → If you're refreshing: was the refresh token already used? (Reuse = family revoked.)

Is error = "invalid_scope"?
  → You requested scopes the client isn't allowed to have.
  → Check: what scopes was the client registered with?
  → Check: are the scopes declared on the target resource?
    (PATCH /admin/resources/{id} with the updated scopes array)

Is error = "invalid_dpop_proof"?
  → Your DPoP proof JWT is wrong. See the DPoP troubleshooting section.

Is error = "use_dpop_nonce"?
  → The server wants a nonce in your DPoP proof.
  → Read the DPoP-Nonce response header, include it in your proof, retry.

Is error = "access_denied"?
  → Token exchange: you're not authorized to exchange this token.
  → Check: is your client in the target resource's policy.exchange.allowed_client_ids?

Is error = "consent_required"?
  → Token exchange against a Broker resource: the user has not consented
    or the existing consent does not cover the requested scopes.
  → Read the response body's `consent_url` and `cause` fields.
  → cause = "consent_missing" → bound B (no consent_grants row) or D (no broker_grants).
  → cause = "scope_insufficient" → bound C or E. Send the user to consent_url.

Is error = "unsupported_grant_type"?
  → The grant type isn't enabled in config.
  → Example: client_credentials.enabled is false.
```

### I'm calling the admin API and it failed

```
401 → Missing or invalid API key. Use: Authorization: Bearer <api_key>
400 → Bad request body. Check required fields.
404 → Resource not found (client, user, or resource doesn't exist).
409 → Conflict — you're creating something that already exists (e.g., duplicate resource slug).
429 → Rate limited. Wait and retry.
500 → Server error. Check the server logs.
```

---

## Complete error reference

### `invalid_request` — HTTP 400

The request is malformed or missing required parameters.

| When you see it | What happened | How to fix |
|---|---|---|
| During authorization | `redirect_uri` doesn't match any URI the client registered | Use the exact redirect URI from client registration. No wildcards, no prefix matching. |
| During authorization | Required parameters missing (client_id, response_type, etc.) | Check the OAuth authorize request format in the [HTTP API reference](./http-api.md). |
| During token exchange | Vault vend with an actor_token | Vault vending doesn't support delegation. Remove the `actor_token` parameter. |
| During any request | Malformed JSON body or form parameters | Check Content-Type header and request body format. |

### `invalid_client` — HTTP 401

The client can't be authenticated.

| When you see it | What happened | How to fix |
|---|---|---|
| Unknown client_id | The client_id doesn't exist in authserver | Verify the client_id. Register the client if needed. |
| Wrong client_secret | The secret doesn't match | Secrets are case-sensitive. If lost, register a new client. |
| Client suspended | The client was suspended by an admin | Reactivate: `PATCH /admin/clients/{id}/reactivate` |
| CIMD fetch failed | URL-based client ID's metadata document couldn't be fetched | Verify the CIMD URL is reachable and returns valid JSON. |
| CIMD invalid | Client metadata document failed validation | Ensure valid `client_id`, `redirect_uris`, and `client_name` fields. |

**Note:** The response always includes `WWW-Authenticate: Basic realm="authserver"` for 401s.

### `invalid_grant` — HTTP 400

The authorization grant (code, token, or credentials) is invalid, expired, or revoked.

| When you see it | What happened | How to fix |
|---|---|---|
| Auth code expired | The code is older than 10 minutes | Start a new authorization flow. Codes are intentionally short-lived. |
| Auth code already used | Someone (maybe you, maybe an attacker) already exchanged this code | Each code can only be exchanged once. Request a new authorization. |
| Wrong code_verifier | The PKCE verifier doesn't match the challenge | Ensure `code_verifier` is the original random string, and `code_challenge` was `base64url(SHA-256(code_verifier))`. Only S256 is supported. |
| Wrong redirect_uri | The redirect_uri in the token request doesn't match the authorize request | Use the exact same redirect_uri in both requests. |
| Refresh token reuse | You presented a refresh token that an earlier rotation had already consumed. The server treats that as a replay: it rejects the request and revokes the whole token family. If the revocation itself fails server-side, operators are alerted ([details](../guides/operate/token-design-internals.md#refresh-token-rotation-and-reuse-detection)); the reply to you is still the reuse rejection, because the token you sent is spent either way. | **This means potential token theft.** Start a new authorization flow; do not retry the refresh token. The description is *token family revoked due to reuse detection* in both cases — whether the server-side revocation completed is reported to operators, never to the client. |
| Session expired | The user took too long to complete login/consent | Start a new authorization request. |
| Bad password | Login credentials are wrong | Check the password. After repeated failures, the IP may be locked out. |
| Token exchange: bad subject_token | The subject token is expired, has a bad signature, or wrong issuer | Verify the subject token is valid, not expired, and issued by this authserver instance. |

### `invalid_scope` — HTTP 400

The requested scope isn't available.

| When you see it | What happened | How to fix |
|---|---|---|
| Scope not registered | The scope name isn't declared on the target resource | Add it via `PATCH /admin/resources/{id}` — include the scope in the `scopes` array as `{"name": "...", "description": "..."}`. |
| Scope not in client's set | The client has registered scopes, but you asked for one outside that set | Narrow the request, or widen the client's scope via the admin API. |
| `client_credentials`: "created through dynamic registration" | The client came from `POST /oauth/register` or CIMD, which create user-delegated clients. Machine clients are pre-registered through the admin API | Create the machine client with `POST /admin/clients` instead. Granting scopes to the dynamically registered one is not the fix. |
| `client_credentials`: "the client has no registered scopes" | An admin-provisioned client was created without any scope | Grant scopes: `PATCH /admin/clients/{client_id}` with `{"scope": "..."}`. |
| jwt-bearer: "the requested scope is invalid or not allowed" | Same empty client scope, but this grant fails even when the request omits `scope`: the assertion's scopes intersect the empty ceiling to nothing. Unlike `client_credentials` it does not *yet* name the cause — the description is still the generic one, and closing that gap is tracked separately | Grant the client's scopes as above; if the token is meant to carry none, the assertion has to omit `scope` too. |
| Token exchange: scope escalation | You requested broader scopes than the subject token has | You can only narrow scopes during exchange, never broaden them. |

### `unauthorized_client` — HTTP 400

The client is registered but not authorized for the requested operation.

| When you see it | What happened | How to fix |
|---|---|---|
| Wrong grant_type | Client's `grant_types` doesn't include the requested grant | Re-register the client with the needed grant type. Example: add `"client_credentials"` or `"urn:ietf:params:oauth:grant-type:token-exchange"`. |

### `unsupported_grant_type` — HTTP 400

The grant type isn't supported or isn't enabled.

| When you see it | What happened | How to fix |
|---|---|---|
| Grant not enabled | The feature is disabled in config | Enable it: `client_credentials.enabled: true` or `token_exchange.enabled: true` |
| Unknown grant_type | Typo or unsupported value | Supported: `authorization_code`, `refresh_token`, `client_credentials`, `urn:ietf:params:oauth:grant-type:token-exchange`, `urn:ietf:params:oauth:grant-type:jwt-bearer` |

### `invalid_dpop_proof` — HTTP 400

The DPoP proof JWT is invalid.

| When you see it | What happened | How to fix |
|---|---|---|
| Wrong `typ` | Proof doesn't have `typ: dpop+jwt` | Set the JWT header `typ` to exactly `dpop+jwt` |
| Wrong `alg` | Algorithm not in {ES256, RS256, PS256} | Use one of the allowed algorithms. HS256 and `none` are always rejected. |
| Private key in `jwk` | The `jwk` header contains a private key | Only include the **public** key in the `jwk` header |
| `htm` mismatch | The `htm` claim doesn't match the HTTP method | Set `htm` to your actual request method (e.g., `POST`) |
| `htu` mismatch | The `htu` claim doesn't match the URL | Set `htu` to scheme + host + path (no query string) |
| `iat` too old | The proof is older than `proof_lifetime` | Generate a fresh proof for each request. Don't cache proofs. |
| JTI reused | You sent the same `jti` twice | Generate a new UUID for every proof |

### `use_dpop_nonce` — HTTP 400

The server requires a nonce in your DPoP proof. The response includes a `DPoP-Nonce` header with the value to use.

| When you see it | What happened | How to fix |
|---|---|---|
| Nonce missing | `require_nonce` is enabled and your proof doesn't include a nonce | Read the `DPoP-Nonce` response header. Include it as the `nonce` claim in your proof. Retry. |
| Nonce expired | The nonce you used has expired | Use the fresh nonce from the new `DPoP-Nonce` response header. |

### `invalid_grant` (XAA / JWT Bearer) — HTTP 400

Errors specific to the JWT Bearer grant type (`urn:ietf:params:oauth:grant-type:jwt-bearer`) and ID-JAG assertion validation.

| When you see it | What happened | How to fix |
|---|---|---|
| Identity assertion is invalid | The ID-JAG JWT couldn't be parsed or signature verification failed | Check that the assertion is signed with the IdP's private key and uses ES256, RS256, or PS256. |
| Identity assertion has expired | The assertion's `exp` is in the past | Issue a fresh assertion. Assertions must be used within `xaa.max_assertion_age` (default: 5m). |
| Identity assertion audience does not match | The `aud` claim doesn't match the AS issuer URL | Set `aud` to the authserver server's issuer URL. |
| Identity assertion issuer is not trusted | The `iss` claim doesn't match any registered trusted IdP | Register the IdP via `POST /admin/idps`. |
| Identity assertion type header is invalid | The JWT `typ` header is not `oauth-id-jag+jwt` | Set the JWT header `typ` to exactly `oauth-id-jag+jwt`. |
| Identity assertion client_id does not match | The `client_id` claim in the assertion doesn't match the authenticated client | The `client_id` in the ID-JAG must match the `client_id` used for client authentication on the token request. |
| Identity assertion has already been used | The `jti` was already consumed (replay) | Generate a unique `jti` for every assertion. |
| Trusted identity provider is disabled | The IdP is registered but disabled | Re-enable the IdP via `PUT /admin/idps/{id}` with `enabled: true`. |

### `access_denied` — HTTP 403

The request is authenticated but not authorized.

| When you see it | What happened | How to fix |
|---|---|---|
| Identity assertion denied by policy | No XAA policy allows this IdP/client/scope/resource combination | Create or update a policy via `POST /admin/xaa/policies` that permits the combination. |
| No subject mapping found for identity | Subject mode is `strict` and no mapping exists for the IdP subject | Create a subject mapping via `POST /admin/xaa/subject-mappings`. |
| Token exchange: not authorized | Your client isn't in the target resource's `policy.exchange.allowed_client_ids` and the subject token doesn't have a `may_act` claim for you | Add your client to `policy.exchange.allowed_client_ids` on the target resource via `PATCH /admin/resources/{id}`, or empty the list to allow any client. |
| Token exchange: chain too deep | Delegation chain exceeds `max_chain_depth` | Increase the limit or reduce delegation levels. |
| OIDC auth failed | Upstream identity provider rejected the authentication | Check IdP config: client_id, client_secret, redirect_uri. |

### `consent_required` (token exchange) — HTTP 400

Returned by `POST /oauth/token` with `grant_type=urn:ietf:params:oauth:grant-type:token-exchange` when the requested `resource` maps to a Mint or Broker resource and the three-bound consent check fails. The response carries two structured fields beyond the standard OAuth shape:

- **`consent_url`** — where to send the user to collect missing consent. Two flavors selected by the AS based on which bound failed:
  - `/connect/{provider}` — upstream OAuth re-auth (bound D: no `broker_grants`, or bound E: upstream did not grant a scope).
  - `/authorize?resource=<slug>&scope=<missing>` — AS-side re-consent (bound B: no `consent_grants` row, or bound C: consent grant doesn't cover the requested scopes).
- **`cause`** — sub-discriminator: `consent_missing` or `scope_insufficient`. Empty defaults to `consent_missing` server-side.

**Example response:**

```json
{
  "error": "consent_required",
  "error_description": "Authorize access to google-calendar",
  "consent_url": "https://as.example.com/connect/google-calendar",
  "cause": "consent_missing",
  "type": "https://docs.authplane.ai/errors/consent_required",
  "title": "Bad Request",
  "detail": "Authorize access to google-calendar",
  "status": 400
}
```

The `consent_url` is the canonical bare URL. Clients are free to append their own `return_url` query parameter before opening the URL in the user's browser. Both fields are only populated for `consent_required` errors; they are absent from every other error response.

Previously, servers omit the `cause` field entirely; SDKs that decode-with-extra-fields (Go, TypeScript, Python, Rust) tolerate this gracefully.

| When you see it | `cause` | Recovery |
|---|---|---|
| `consent_required` from `/authorize` | (n/a — not used on `/authorize`) | Render the consent screen for the user. |
| `consent_required` from `/oauth/token` | `consent_missing` | Open `consent_url` — either upstream OAuth re-auth or AS-side `/authorize` re-consent depending on which bound failed. |
| `consent_required` from `/oauth/token` | `scope_insufficient` | Same as above; the AS picks the URL flavor. |
| `consent_required` from `/oauth/token` | (empty) | Treat as `consent_missing`. |

### `consent_required` — HTTP 302

The user hasn't consented to the requested scopes yet. This is a redirect to the consent page — it's part of the normal authorization flow, not an error condition.

### `slow_down` — HTTP 429

Too many requests. Check the `Retry-After` header for how long to wait.

### `server_error` — HTTP 500

Something unexpected happened on the server side (database failure, signing error, etc.). Check the server logs for details.

---

## Authorization redirect errors

When an error occurs during `GET /oauth/authorize`, authserver handles it differently based on whether it can safely redirect:

| Condition | Behavior | Why |
|---|---|---|
| client_id valid AND redirect_uri matches registration | Redirects to `redirect_uri?error=CODE&error_description=...&state=STATE` | Safe to redirect — the URI belongs to the registered client |
| client_id unknown OR redirect_uri doesn't match | Renders an HTML error page directly | **Cannot redirect** — the URI might be an attacker's site (open redirect prevention) |

---

## Retry guide

Not all errors are retryable. Save yourself debugging time:

| Error | Retry? | What to do |
|---|---|---|
| `use_dpop_nonce` | **Yes** — immediately | Read `DPoP-Nonce` header, update proof, retry |
| `slow_down` (429) | **Yes** — after delay | Wait for `Retry-After` duration, then retry |
| `server_error` (500) | **Yes** — with backoff | Exponential backoff (1s, 2s, 4s...). If persistent, check server logs. |
| `invalid_dpop_proof` | **Maybe** | Fix the proof and retry if the cause is fixable (stale `iat`, wrong `htm`/`htu`). Don't retry if the proof is structurally broken. |
| `invalid_grant` | **No** | The grant is consumed or expired. Start a fresh flow. |
| `invalid_client` | **No** | Credentials are wrong. Fix them. |
| `invalid_scope` | **No** | Scopes are wrong. Fix the request. |
| `unauthorized_client` | **No** | Client config is wrong. Update registration. |
| `access_denied` | **No** | Policy prevents this exchange. Update the allowlist. |
