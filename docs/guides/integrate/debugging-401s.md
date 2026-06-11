# Debugging 401s from an Authplane-protected MCP server

*Context: part of [Guides — Integrate](README.md). Triage an authenticated MCP request that's coming back 401.*

**Audience:** Builders and operators triaging an authenticated MCP request that's being rejected with 401. A 401 from an Authplane-protected MCP server almost always reduces to one of three causes: (1) `aud` mismatch, (2) signature/`kid` verification failure, or (3) insufficient scope. The `WWW-Authenticate` header on the 401 response and the SDK's structured log are your first stops.

## The minimum diagnostic

```bash
# 1. Inspect the 401 — the SDK populates WWW-Authenticate per RFC 6750
curl -sS -i -H "Authorization: Bearer $TOKEN" http://localhost:8080/mcp -d '{...}' | head -20
# Expect:
#   WWW-Authenticate: Bearer error="invalid_token", error_description="...",
#     resource_metadata="http://localhost:8080/.well-known/oauth-protected-resource"

# 2. Decode the JWT payload — confirm iss, aud, scope, exp, kid
echo "$TOKEN" | cut -d. -f2 | base64 -d 2>/dev/null | jq '{iss,sub,aud,scope,exp}'
echo "$TOKEN" | cut -d. -f1 | base64 -d 2>/dev/null | jq '{alg,kid}'

# 3. Introspect — does the AS still consider it active?
curl -sS -X POST http://localhost:9000/oauth/introspect \
  -d "token=$TOKEN" -d "client_id=$CID" -d "client_secret=$CS" | jq .
# → "active": true means the AS is happy; the problem is on the RS side.

# 4. Confirm RS resource URI matches token aud byte-for-byte
authserver admin resource list | grep -A1 <slug>
# → uri must equal the JWT's aud claim exactly
```

## Decision tree

| `error_description` includes... | Cause | Fix |
| --- | --- | --- |
| `aud` / `audience` | JWT `aud` ≠ RS's configured `Resource` | Re-mint with `resource=<exact RS uri>`. Both sides must agree byte-for-byte (trailing slash matters). |
| `signature` / `kid` / `key` | RS can't verify against AS JWKS | (a) Issuer URL mismatch — RS `Issuer` ≠ JWT `iss`. (b) JWKS unreachable — `curl $AUTHPLANE_ISSUER/.well-known/jwks.json` from the RS host. (c) After key rotation, force RS to refresh JWKS (SDKs auto-refresh on unknown `kid`). |
| `expired` / `exp` | Token TTL elapsed | Mint a new one; check clock skew between AS and RS. |
| `insufficient_scope` | RS requires scopes not in JWT `scope` | Either request the wider scope at the AS (and grant via `authserver admin client update --scope ...`), or relax the RS scope check. |
| `dpop` mismatch | DPoP enabled, but proof header missing/invalid | See [DPoP and proof-of-possession](../../concepts/dpop-and-proof-of-possession.md). |
| `revoked` | Token was revoked via `/oauth/revoke` | Mint a new one; the old one is dead for the rest of its TTL. |

## Why this works

The Authplane SDKs log the exact verification failure as structured JSON: `level=warn msg="bearer auth rejected" reason=<...> token_kid=<...> aud_expected=<...> aud_actual=<...>`. Pair that with `WWW-Authenticate: error_description` on the 401 response (per [RFC 6750](https://datatracker.ietf.org/doc/html/rfc6750)) and you'll identify the cause in one round-trip. JWKS misses, signature failures, and aud mismatches are all distinguishable.

## What can go wrong

| Symptom | Fix |
| --- | --- |
| MCP client never sends a token (loops on 401) | The client requires PRM discovery. Confirm `/.well-known/oauth-protected-resource` is reachable and `WWW-Authenticate` carries `resource_metadata=`. |
| Token verifies in `jwt.io` but fails on the server | Clock skew, or RS is on an old issuer URL. Compare `iss` to RS's `Issuer` env var verbatim. |
| Logs show `failed to fetch JWKS` | RS host can't reach the AS. NetworkPolicy, DNS, or the AS pod is down. |

## See also

- Reference: [`error-codes.md`](../../reference/error-codes.md), [`http-api.md` — `/oauth/introspect`](../../reference/http-api.md)
- Concept: [Tokens and claims](../../concepts/tokens-and-claims.md)
- Operate: [Audit and forensics](../operate/audit-and-forensics.md)
- DPoP: [DPoP and proof-of-possession](../../concepts/dpop-and-proof-of-possession.md)
