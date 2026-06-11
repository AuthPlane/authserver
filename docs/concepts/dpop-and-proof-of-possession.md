# DPoP and proof of possession

*Context: this is part of [Concepts](README.md). Start with the primer if you haven't.*

## Why bind tokens to a key?

A regular Bearer token is like a house key: anyone who has it can use it.
If an attacker steals the token (from a log, a network tap, or a
compromised service), they can use it freely until it expires.

[DPoP](glossary.md#glossary-dpop) (Demonstrating Proof of Possession,
[RFC 9449](https://datatracker.ietf.org/doc/html/rfc9449)) changes this.
It binds a token to a specific key pair that only your client has. Now the
token is like a house key that only works with your fingerprint — stealing
the key alone isn't enough. The attacker would also need your private key,
which never leaves your service.

## When you need this

**Enable DPoP when:**
- Tokens transit multiple services (e.g., MCP client → authorization server → MCP server) and you want protection if any hop is compromised
- You're in a high-security environment where token theft is a realistic concern
- Your MCP servers are deployed in environments where network traffic might be observable
- Compliance requires proof-of-possession tokens

**Skip DPoP when:**
- You're running everything locally (development/testing)
- All communication is over TLS on a trusted internal network
- You don't want the added complexity (DPoP requires key management on the client side)
- Your tokens have very short expiry (< 5 minutes) and the risk window is acceptable

**Performance impact:** DPoP adds ~1ms of cryptographic overhead per request (proof creation + verification). The proof is a small JWT (~500 bytes). For most deployments this is negligible.

## How it works — the simple version

```
1. Your service generates a key pair (once, at startup)
2. For every token request, your service creates a signed "proof"
   saying "I'm making this specific request right now"
3. authserver checks the proof and stamps the token with your public key's thumbprint
4. When your service uses the token, it creates another proof
5. The MCP server checks: does the proof's key match the stamp in the token?
```

If someone steals just the token, they can't create valid proofs (they don't have the private key). If someone steals just a proof, they can't reuse it (proofs are single-use and time-bound).

## Quick start

### 1. Enable in config

```yaml
dpop:
  enabled: true
  proof_lifetime: 2m       # how fresh proofs must be (default: 60s)
  nonce_ttl: 5m            # how long server nonces are valid (default: 60s)
  require_nonce: false      # require server nonce in every proof (default: false)
```

### 2. Generate a key pair

Your service needs an asymmetric key pair. EC P-256 is recommended (compact and fast):

```bash
openssl ecparam -name prime256v1 -genkey -noout -out dpop_key.pem
openssl ec -in dpop_key.pem -pubout -out dpop_pub.pem
```

**Keep the private key secure.** It never leaves your service. Never include it in a DPoP proof.

### 3. Create a proof and request a token

Include a DPoP proof in the `DPoP` header when requesting a token:

```bash
curl -X POST http://localhost:9000/oauth/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -H "DPoP: eyJhbGciOiJFUzI1NiIs..." \
  -d "grant_type=client_credentials" \
  -d "client_id=CLIENT_ID" \
  -d "client_secret=CLIENT_SECRET"
```

The response will have `token_type: DPoP` instead of `Bearer`:

```json
{
  "access_token": "eyJhbGciOi...",
  "token_type": "DPoP",
  "expires_in": 3600
}
```

The access token now contains a `cnf.jkt` claim — your public key's thumbprint:

```json
{
  "cnf": { "jkt": "0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I" }
}
```

### 4. Use the token with a proof

When calling an MCP server, include both the token and a new proof:

```bash
curl -X POST http://mcp-server:3000/mcp \
  -H "Authorization: DPoP eyJhbGciOi..." \
  -H "DPoP: eyJhbGciOiJFUzI1NiIs..." \
  -d '{"method": "tools/call", ...}'
```

Note: `Authorization: DPoP ...` (not `Bearer`).

## Configuration reference

### `dpop.enabled`

**What:** Turns on DPoP support. When enabled, clients *may* include DPoP proofs. It's opt-in per client — clients that don't send proofs still get regular Bearer tokens.
**Default:** `false`
**Risk if enabled without clients ready:** None. DPoP is additive. Existing clients without DPoP continue working.

### `dpop.proof_lifetime`

**What:** Maximum age of a DPoP proof. The server checks `|now - iat| <= proof_lifetime`. Proofs older than this are rejected.
**Default:** `60s`
**Must be:** Between 10 seconds and 300 seconds.
**Trade-off:** Shorter = more secure (tighter replay window), but requires tighter clock sync between client and server. `60s–120s` works for most deployments.
**Clock skew:** The server accepts proofs where `iat` is up to `proof_lifetime` in the past OR future. So a 60s lifetime tolerates ±60s of clock difference.

### `dpop.nonce_ttl`

**What:** How long a server-issued nonce is valid.
**Default:** `60s`
**Must be:** Greater than 0 when DPoP is enabled.
**What nonces do:** When `require_nonce` is true, the server issues a random nonce that the client must include in its proof. This binds the proof to a narrow server-controlled time window, providing replay protection even if an attacker captures proofs.

### `dpop.require_nonce`

**What:** When true, every DPoP proof must include a `nonce` claim matching a server-issued nonce. Proofs without a nonce are rejected with `use_dpop_nonce` and a `DPoP-Nonce` response header.
**Default:** `false`
**Trade-off:** More secure (proofs are bound to server time), but adds an extra round trip when the client doesn't have a valid nonce. The first request fails with `use_dpop_nonce`, the client retries with the nonce.
**Recommendation:** Enable for high-security deployments. Skip for development or when the overhead of the extra round trip matters.

## Constructing a DPoP proof

A DPoP proof is a JWT with specific headers and claims. Here's what goes in it:

### Headers

| Header | Value | Notes |
|--------|-------|-------|
| `typ` | `dpop+jwt` | Must be exactly this |
| `alg` | `ES256`, `RS256`, or `PS256` | See "Allowed algorithms" below |
| `jwk` | Your **public** key as a JWK | Never include the private key — authserver rejects it |

### Claims

| Claim | Required | What it is |
|-------|----------|-----------|
| `jti` | Always | A unique ID (UUID). Used once — replay detected and rejected |
| `htm` | Always | The HTTP method of YOUR request (e.g., `POST`) |
| `htu` | Always | The HTTP URL of YOUR request (scheme + host + path, no query string) |
| `iat` | Always | Current Unix timestamp. Must be within `proof_lifetime` of server time |
| `nonce` | When server requires it | The value from the `DPoP-Nonce` response header |
| `ath` | At resource server | `base64url(SHA-256(access_token))` — binds the proof to a specific token |

### When `ath` is needed

- **At the token endpoint:** Don't include `ath` (you don't have the token yet)
- **At the resource server (MCP server):** Include `ath` = `base64url(SHA-256(access_token))`

### Pseudocode

```python
def create_dpop_proof(private_key, method, url, nonce=None, access_token=None):
    header = {
        "typ": "dpop+jwt",
        "alg": "ES256",
        "jwk": extract_public_key(private_key)  # PUBLIC key only!
    }
    payload = {
        "jti": generate_uuid(),
        "htm": method,                           # "POST", "GET", etc.
        "htu": strip_query_and_fragment(url),    # "https://auth.example.com/oauth/token"
        "iat": current_unix_timestamp()
    }
    if nonce:
        payload["nonce"] = nonce
    if access_token:
        payload["ath"] = base64url(sha256(access_token))
    return jwt_sign(header, payload, private_key)
```

## Allowed algorithms

| Algorithm | Key type | Recommendation |
|-----------|----------|----------------|
| ES256 | ECDSA P-256 | **Recommended** — compact proofs (~200 bytes), fast signing |
| RS256 | RSA 2048+ | Widely supported, larger proofs (~350 bytes) |
| PS256 | RSA-PSS 2048+ | PSS padding variant of RSA |

**Always rejected (security invariant):**
- `alg: none` — allows unsigned proofs (trivially forgeable)
- `HS256`, `HS384`, `HS512` — symmetric algorithms; the verifier would need the signing key, defeating proof-of-possession
- Private key in `jwk` header — would leak your private key to the server

## Nonce flow

When `require_nonce` is enabled (or when the server decides a nonce is needed), the flow has an extra step:

```
Client → POST /oauth/token (with DPoP proof, no nonce)
Server → 400 Bad Request
         DPoP-Nonce: abc123
         {"error": "use_dpop_nonce"}

Client → POST /oauth/token (with DPoP proof, nonce=abc123)
Server → 200 OK
         {"access_token": "...", "token_type": "DPoP"}
```

**Tip:** Cache the nonce from the response and include it in subsequent proofs. Nonces expire after `nonce_ttl`, so you'll occasionally get a `use_dpop_nonce` error — just retry with the new nonce.

## Resource server validation

When an MCP server receives a request with `Authorization: DPoP <token>`, it should:

1. **Decode the access token** and check for a `cnf.jkt` claim. If present, the token is DPoP-bound.
2. **Require a `DPoP` header** on the request. Missing → reject with 401.
3. **Validate the proof:**
   - Verify the JWT signature using the public key in the proof's `jwk` header
   - Check `htm` matches the request's HTTP method
   - Check `htu` matches the request's URL
   - Check `iat` is recent (within acceptable window)
4. **Compute the thumbprint** of the public key in the proof's `jwk` header (SHA-256, per RFC 7638)
5. **Compare** the computed thumbprint to the `cnf.jkt` in the access token. Mismatch → reject.
6. **Verify `ath`** = `base64url(SHA-256(access_token))`. Mismatch → reject.

If any check fails, respond with HTTP 401.

## Which grants support DPoP?

DPoP works with all token-issuing grants:

| Grant | DPoP supported | Notes |
|-------|---------------|-------|
| Authorization code | Yes | Proof at token endpoint; `cnf.jkt` in access token |
| Client credentials | Yes | Same flow |
| Token exchange | Yes | DPoP proof at exchange; can override or propagate `cnf.jkt` |
| Refresh token | Yes | DPoP proof required on refresh; binding maintained |

## Security properties

| Threat | Without DPoP | With DPoP |
|--------|-------------|-----------|
| Token stolen from logs | Attacker can use it freely until expiry | Token is useless without the private key |
| Token intercepted in transit | Attacker can use it | Token is useless without the private key |
| Proof captured in transit | N/A | Proof is single-use (JTI) and time-bound (iat) — can't be replayed |
| Both token AND proof stolen | N/A | Proof is single-use — attacker gets one request at most |
| Private key stolen | N/A | Game over — rotate the key and re-register |

**Bottom line:** DPoP makes token theft much harder to exploit. The attacker needs the private key (which never leaves the client) plus the ability to create proofs in real time. It doesn't protect against a fully compromised client (where the attacker has the private key), but it does protect against network-level and log-level token theft.

## Troubleshooting

| Error | Meaning | Fix |
|---|---|---|
| `invalid_dpop_proof` | The proof JWT is malformed or invalid | Check: `typ` must be `dpop+jwt`, `alg` must be ES256/RS256/PS256, `jwk` must be a public key (not private), `htm`/`htu` must match your request, `iat` must be recent |
| `use_dpop_nonce` | Server requires a nonce you didn't include | Read the `DPoP-Nonce` response header, include it in your proof's `nonce` claim, and retry |
| `invalid_dpop_proof` (replay) | You reused a `jti` | Generate a fresh UUID for every proof. Each proof must have a unique `jti`. Replay tracking is backed by the [Replay Store](glossary.md#glossary-replay-store). |
| Token type is `Bearer` not `DPoP` | DPoP is not enabled or proof wasn't included | Check `dpop.enabled: true` in config. Ensure the `DPoP` header is present on the token request. |

## Where to go next

- [Tokens and claims](tokens-and-claims.md) — how the `cnf.jkt` claim
  appears in the access token.
- [Threat model](threat-model.md#t14-dpop-proof-replay) — what DPoP
  defends against and what it doesn't.
- [HTTP API reference](../reference/http-api.md) — the wire format of the
  `DPoP` header and the `use_dpop_nonce` retry contract.
- [Environment variables reference](../reference/env-vars.md) — every
  `dpop.*` setting and its env-var override.
