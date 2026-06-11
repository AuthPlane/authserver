#!/usr/bin/env bash
# verify.sh — end-to-end smoke for the retrofit example.
#
# The point of this example is to show what happens BEFORE and AFTER adding
# Authplane to the same MCP server. The smoke-test does both:
#
#   Phase A — the `before` server (unauthed) accepts a tools/call with no
#             token, returns the tool result. Proves it's a real, working
#             MCP server.
#   Phase B — the `after` server (authed) rejects the same unauthenticated
#             tools/call with 401, then accepts it once you mint a bearer
#             token. Proves the 5-line auth block is real, not theatre.
#
# A successful run prints both result lines and exits 0.

set -euo pipefail

ADMIN_URL="${ADMIN_URL:-http://localhost:9001}"
ISSUER_URL="${ISSUER_URL:-http://localhost:9000}"
BEFORE_URL="${BEFORE_URL:-http://localhost:8080/mcp}"
AFTER_URL="${AFTER_URL:-http://localhost:8090/mcp}"
RESOURCE_URI="${RESOURCE_URI:-http://localhost:8090/mcp}"
RESOURCE_SLUG="retrofit-after"
SCOPE="mcp:tools"

if [[ -f .env ]]; then
  # shellcheck disable=SC1091
  set -a; source .env; set +a
fi
: "${AUTHPLANE_ADMIN_API_KEY:?missing AUTHPLANE_ADMIN_API_KEY (is .env present?)}"

red()   { printf '\033[31m%s\033[0m\n' "$*" >&2; }
green() { printf '\033[32m%s\033[0m\n' "$*"; }
log()   { printf '[verify] %s\n' "$*"; }

# --- wait for everyone to be ready ------------------------------------------
log "waiting for authserver discovery at ${ISSUER_URL}/.well-known/oauth-authorization-server"
deadline=$(( $(date +%s) + 60 ))
until curl -fsS -o /dev/null --max-time 2 "${ISSUER_URL}/.well-known/oauth-authorization-server"; do
  if [[ $(date +%s) -ge $deadline ]]; then
    red "authserver discovery did not return 200 within 60s"
    docker logs authplane-retrofit-as 2>&1 | tail -40 >&2 || true
    exit 1
  fi
  sleep 1
done
green "authserver ready"

for url in "${BEFORE_URL}" "${AFTER_URL}"; do
  log "waiting for ${url}"
  deadline=$(( $(date +%s) + 90 ))
  while true; do
    code=$(curl -s -o /dev/null -w '%{http_code}' --max-time 2 "${url}" || true)
    # Any 4xx/2xx means "process is alive and responding"; we don't care
    # which exactly — Phase A and B will exercise the real protocol.
    # `before` returns 406 (FastMCP plain); `after` returns 501 (Authplane
    # middleware on top of FastMCP). Both mean "alive, just doesn't like GET".
    if [[ "$code" =~ ^(200|202|400|401|405|406|501)$ ]]; then break; fi
    if [[ $(date +%s) -ge $deadline ]]; then
      red "${url} not ready (last code=${code:-none})"
      exit 1
    fi
    sleep 2
  done
done
green "both MCP servers ready"

# --- hardening: prove the readiness probe reached THIS run's after-server ----
# A 4xx from the loop above only proves *something* is bound to :8090. A
# leftover server/AS from a prior attempt can answer with a valid-looking 401
# and masquerade as "ready". Confirm the process is ours by checking its
# Protected Resource Metadata advertises the exact Resource URI we're about to
# register — a stray process would advertise a different URI, or none.
prm_url="${AFTER_URL%/mcp}/.well-known/oauth-protected-resource/mcp"
prm_resource=$(curl -fsS --max-time 5 "${prm_url}" 2>/dev/null | jq -r '.resource // empty' || true)
if [[ "${prm_resource}" != "${RESOURCE_URI}" ]]; then
  red "  after: a process on :8090 advertises resource='${prm_resource:-<none>}', not '${RESOURCE_URI}'."
  red "  A stale server/AS from a prior run is probably still bound to the port. Reset and retry:"
  red "    make clean && docker ps -aq --filter name=authplane | xargs -r docker rm -f"
  exit 1
fi
green "  after: PRM advertises ${RESOURCE_URI} — confirmed this run's process"

# --- helper: full MCP handshake + tools/call ---------------------------------
# Args: $1=mcp_url, $2=optional bearer (empty for unauth).
mcp_call() {
  local url="$1"; local bearer="${2:-}"
  local auth_h=()
  [[ -n "$bearer" ]] && auth_h=(-H "Authorization: Bearer ${bearer}")

  local hdrs; hdrs=$(mktemp)
  local init; init=$(curl -fsS -D "$hdrs" -X POST "$url" ${auth_h[@]+"${auth_h[@]}"} \
    -H 'Content-Type: application/json' \
    -H 'Accept: application/json, text/event-stream' \
    -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"verify","version":"1.0"}}}') || {
      rm -f "$hdrs"
      echo ""
      return 1
    }
  local sid; sid=$(awk 'tolower($1)=="mcp-session-id:"{print $2}' "$hdrs" | tr -d '\r')
  rm -f "$hdrs"
  [[ -z "$sid" ]] && { echo "$init" | head -5 >&2; return 2; }

  curl -fsS -o /dev/null -X POST "$url" ${auth_h[@]+"${auth_h[@]}"} \
    -H "Mcp-Session-Id: ${sid}" \
    -H 'Content-Type: application/json' \
    -H 'Accept: application/json, text/event-stream' \
    -d '{"jsonrpc":"2.0","method":"notifications/initialized"}'

  local body; body=$(curl -fsS -X POST "$url" ${auth_h[@]+"${auth_h[@]}"} \
    -H "Mcp-Session-Id: ${sid}" \
    -H 'Content-Type: application/json' \
    -H 'Accept: application/json, text/event-stream' \
    -d '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"add","arguments":{"a":17,"b":25}}}')
  # FastMCP frames as either raw JSON or `data: {…}` SSE; pluck either way.
  local payload; payload=$(echo "$body" | sed -n 's/^data: //p')
  [[ -z "$payload" ]] && payload="$body"
  echo "$payload"
}

# --- Phase A: before (unauthed) ----------------------------------------------
log "Phase A — calling 'before' server with NO bearer (should succeed)"
if a_body=$(mcp_call "${BEFORE_URL}" ""); then
  if echo "$a_body" | grep -q '"42'; then
    green "  before: tools/call add(17,25) = 42 (no auth required, as expected)"
  else
    red "  before: unexpected response"
    echo "$a_body" | head -5 >&2
    exit 1
  fi
else
  red "  before: tools/call failed unexpectedly"
  exit 1
fi

# --- Phase B.1: after (unauthed)  → must reject ------------------------------
log "Phase B.1 — calling 'after' server with NO bearer (should be REJECTED)"
unauth_code=$(curl -s -o /dev/null -w '%{http_code}' -X POST "${AFTER_URL}" \
  -H 'Content-Type: application/json' \
  -H 'Accept: application/json, text/event-stream' \
  -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}')
if [[ "$unauth_code" == "401" ]]; then
  green "  after: unauthenticated probe rejected with HTTP 401 (auth enforced)"
else
  red "  after: expected 401, got ${unauth_code} — auth is NOT enforced"
  exit 1
fi

# --- Phase B.2: register Resource + client at the AS -------------------------
log "Phase B.2 — registering the 'after' server as a Mint Resource"
curl -fsS -o /dev/null -X POST "${ADMIN_URL}/admin/resources" \
  -H "Authorization: Bearer ${AUTHPLANE_ADMIN_API_KEY}" \
  -H "Content-Type: application/json" \
  -d @- <<EOF || true
{
  "slug": "${RESOURCE_SLUG}",
  "uri": "${RESOURCE_URI}",
  "backend_kind": "mint",
  "display_name": "Retrofit demo (after)",
  "scopes": [{"name": "${SCOPE}", "description": "demo tools"}]
}
EOF

log "Phase B.2 — registering a client_credentials OAuth client"
client_resp=$(curl -fsS -X POST "${ADMIN_URL}/admin/clients" \
  -H "Authorization: Bearer ${AUTHPLANE_ADMIN_API_KEY}" \
  -H "Content-Type: application/json" \
  -d @- <<EOF
{
  "client_name": "retrofit-demo-client",
  "grant_types": ["client_credentials"],
  "token_endpoint_auth_method": "client_secret_basic",
  "scope": "${SCOPE}"
}
EOF
)
CLIENT_ID=$(echo "$client_resp" | jq -er '.client_id')
CLIENT_SECRET=$(echo "$client_resp" | jq -er '.client_secret')
green "  registered: client_id=${CLIENT_ID}"

# --- Phase B.3: mint a bearer ------------------------------------------------
log "Phase B.3 — minting an access token"
token_resp=$(curl -fsS -X POST "${ISSUER_URL}/oauth/token" \
  -u "${CLIENT_ID}:${CLIENT_SECRET}" \
  -d "grant_type=client_credentials" \
  -d "scope=${SCOPE}" \
  --data-urlencode "resource=${RESOURCE_URI}")
ACCESS_TOKEN=$(echo "$token_resp" | jq -er '.access_token')
green "  token minted (len=${#ACCESS_TOKEN})"

# --- Phase B.4: after (authed) — must succeed --------------------------------
log "Phase B.4 — calling 'after' server WITH the bearer (should succeed)"
if b_body=$(mcp_call "${AFTER_URL}" "${ACCESS_TOKEN}"); then
  if echo "$b_body" | grep -q '"42'; then
    green "  after: tools/call add(17,25) = 42 (auth bearer accepted)"
  else
    red "  after: unexpected response under valid bearer"
    echo "$b_body" | head -5 >&2
    exit 1
  fi
else
  red "  after: tools/call failed under valid bearer — this should not happen"
  exit 1
fi

echo
green "ALL CHECKS PASSED — retrofit verified end-to-end."
green "  before  (no auth) → 200, tool result"
green "  after  no bearer  → 401"
green "  after  + bearer   → 200, tool result"
