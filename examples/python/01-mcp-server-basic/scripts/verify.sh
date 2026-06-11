#!/usr/bin/env bash
# verify.sh — end-to-end smoke for Tier 01 (Python).
#
# Pipeline:
#   1. wait for authserver discovery (:9000)
#   2. register a Mint resource matching the MCP audience
#   3. register an OAuth client with the client_credentials grant
#   4. wait for mcp-server (:8080) — confirm it returns 401 unauthenticated
#   5. mint a client_credentials access token (resource=, scope=mcp:echo)
#   6. JSON-RPC `initialize` → capture `mcp-session-id` response header
#   7. `notifications/initialized` (required by the MCP streamable-http
#      transport before tools become callable)
#   8. `tools/call` echo with the bearer + session and assert the echoed
#      string round-trips — proves the auth chain reaches a real tool, not
#      just the initialize handler
#
# Exits 0 on full success. Any failure prints the offending response and
# exits 1.
#
# Note: tier-01 uses client_credentials only. The authserver enforces
# policy.runtime.client_ids only for the token-exchange grant (actor
# attestation chain), not for client_credentials — see
# internal/services/client_credentials.go vs internal/services/token_exchange.go:1946.
# Tier-04 (broker upstream) does include the step (it uses token-exchange).

set -euo pipefail

# Endpoint URLs. Override via env if the example is brought up on non-default
# ports (e.g. during local development with a docker-compose.override.yml).
ADMIN_URL="${ADMIN_URL:-http://localhost:9001}"
ISSUER_URL="${ISSUER_URL:-http://localhost:9000}"
MCP_URL="${MCP_URL:-http://localhost:8080/mcp}"
# Resource URI must match the JWT audience the MCP server's verifier expects
# (= base_url + /mcp). The authplane-fastmcp adapter derives this from
# `base_url` + `mcp_path` (default "/mcp"); see
# python-sdk/authplane-fastmcp/authplane_fastmcp/auth.py:188-191.
RESOURCE_URI="${RESOURCE_URI:-http://localhost:8080/mcp}"
RESOURCE_SLUG="demo-mcp"
SCOPE="mcp:echo"

# Pull the admin API key from .env so we don't rely on the operator exporting it.
if [[ -f .env ]]; then
  # shellcheck disable=SC1091
  set -a; source .env; set +a
fi
: "${AUTHPLANE_ADMIN_API_KEY:?missing AUTHPLANE_ADMIN_API_KEY (is .env present?)}"

red()   { printf '\033[31m%s\033[0m\n' "$*" >&2; }
green() { printf '\033[32m%s\033[0m\n' "$*"; }
log()   { printf '[verify] %s\n' "$*"; }

# --- step 1: discovery ready -------------------------------------------------
log "waiting for authserver discovery at ${ISSUER_URL}/.well-known/oauth-authorization-server"
deadline=$(( $(date +%s) + 60 ))
until curl -fsS -o /dev/null --max-time 2 "${ISSUER_URL}/.well-known/oauth-authorization-server"; do
  if [[ $(date +%s) -ge $deadline ]]; then
    red "authserver discovery did not return 200 within 60s"
    docker compose logs authserver | tail -40 >&2 || true
    exit 1
  fi
  sleep 1
done
green "authserver discovery OK"

# --- step 2: register the Mint resource -------------------------------------
# DTO: api/admin/dto.go:349 (createResourceRequest); scopes use
# internal/admin/dto/dto.go:32 (ScopeView).
log "creating Mint resource slug=${RESOURCE_SLUG} uri=${RESOURCE_URI}"
resource_resp=$(curl -fsS -X POST "${ADMIN_URL}/admin/resources" \
  -H "Authorization: Bearer ${AUTHPLANE_ADMIN_API_KEY}" \
  -H "Content-Type: application/json" \
  -d @- <<EOF || true
{
  "slug": "${RESOURCE_SLUG}",
  "uri": "${RESOURCE_URI}",
  "backend_kind": "mint",
  "display_name": "Demo MCP",
  "scopes": [{"name": "${SCOPE}", "description": "echo tool"}]
}
EOF
)

# If the resource already exists from a prior run, accept the 409 and continue.
if [[ -z "$resource_resp" ]]; then
  log "resource create returned empty body — assuming it already exists, continuing"
else
  echo "$resource_resp" | jq -e '.id' >/dev/null || { red "resource create failed: $resource_resp"; exit 1; }
  green "resource registered"
fi

# --- step 3: register the client --------------------------------------------
# DTO: api/admin/dto.go:15 (createClientRequest). grant_types is an array; the
# admin REST handler wraps the CLI input.CreateClientRequest with the same
# field names.
log "creating OAuth client with grant_types=[client_credentials]"
client_resp=$(curl -fsS -X POST "${ADMIN_URL}/admin/clients" \
  -H "Authorization: Bearer ${AUTHPLANE_ADMIN_API_KEY}" \
  -H "Content-Type: application/json" \
  -d @- <<EOF
{
  "client_name": "demo-mcp-client",
  "grant_types": ["client_credentials"],
  "token_endpoint_auth_method": "client_secret_basic",
  "scope": "${SCOPE}"
}
EOF
)
CLIENT_ID=$(echo "$client_resp" | jq -er '.client_id')
CLIENT_SECRET=$(echo "$client_resp" | jq -er '.client_secret')
green "client created: ${CLIENT_ID}"

# --- step 4: wait for mcp-server ---------------------------------------------
log "waiting for mcp-server at ${MCP_URL} (expect 401)"
deadline=$(( $(date +%s) + 90 ))
while true; do
  code=$(curl -s -o /dev/null -w '%{http_code}' --max-time 2 "${MCP_URL}" || true)
  if [[ "$code" == "401" || "$code" == "405" ]]; then
    break
  fi
  if [[ $(date +%s) -ge $deadline ]]; then
    red "mcp-server did not become ready (last status=${code:-none})"
    docker compose logs mcp-server | tail -40 >&2 || true
    exit 1
  fi
  sleep 2
done
green "mcp-server is up (unauthenticated probe returned HTTP ${code})"

# --- step 5: mint a token via client_credentials -----------------------------
# Handler: api/public/oauth/handlers.go:207-246. Form parameters:
#   grant_type, scope, resource — see input.ClientCredentialsRequest at
#   internal/ports/input. Client auth via Basic (RFC 6749 §2.3.1).
log "requesting client_credentials token"
token_resp=$(curl -fsS -X POST "${ISSUER_URL}/oauth/token" \
  -u "${CLIENT_ID}:${CLIENT_SECRET}" \
  -d "grant_type=client_credentials" \
  -d "scope=${SCOPE}" \
  --data-urlencode "resource=${RESOURCE_URI}")
ACCESS_TOKEN=$(echo "$token_resp" | jq -er '.access_token')
green "token minted (length=${#ACCESS_TOKEN})"

# --- step 6: JSON-RPC `initialize` ------------------------------------------
# Streamable-http transport requires a 3-step handshake:
#   (a) POST initialize        → server returns its capability doc and a
#                                 `mcp-session-id` response header
#   (b) POST notifications/initialized (with the session id)
#   (c) POST tools/call         (with the session id)
# We do all three to prove the auth chain reaches a real tool, not just
# the initialize handler.
log "MCP: initialize (capturing mcp-session-id)"
HEADERS_FILE=$(mktemp -t mcp_init_headers.XXXXXX)
init_body=$(curl -fsS -D "${HEADERS_FILE}" -X POST "${MCP_URL}" \
  -H "Authorization: Bearer ${ACCESS_TOKEN}" \
  -H "Content-Type: application/json" \
  -H "Accept: application/json, text/event-stream" \
  -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"verify.sh","version":"1.0"}}}')
# `awk` (not `sed`) because: (a) HTTP headers are case-insensitive and
# `tolower(...)` handles `Mcp-Session-Id` vs `mcp-session-id` cleanly,
# (b) BSD sed (macOS default) lacks the GNU label syntax that the same
# match would otherwise need.
SESSION_ID=$(awk 'tolower($1)=="mcp-session-id:"{print $2}' "${HEADERS_FILE}" | tr -d '\r')
rm -f "${HEADERS_FILE}"
if [[ -z "${SESSION_ID}" ]]; then
  red "initialize response did not carry mcp-session-id header"
  echo "${init_body}" | head -40 >&2
  exit 1
fi
if ! echo "${init_body}" | grep -q 'demo-server'; then
  red "initialize response did not name 'demo-server'"
  echo "${init_body}" | head -40 >&2
  exit 1
fi
green "initialize OK (session ${SESSION_ID:0:8}…)"

# --- step 7: send the `notifications/initialized` notification --------------
log "MCP: notifications/initialized"
curl -fsS -o /dev/null -X POST "${MCP_URL}" \
  -H "Authorization: Bearer ${ACCESS_TOKEN}" \
  -H "Mcp-Session-Id: ${SESSION_ID}" \
  -H "Content-Type: application/json" \
  -H "Accept: application/json, text/event-stream" \
  -d '{"jsonrpc":"2.0","method":"notifications/initialized"}'
green "notifications/initialized OK"

# --- step 8: tools/call the echo tool ---------------------------------------
log "MCP: tools/call echo"
tool_body=$(curl -fsS -X POST "${MCP_URL}" \
  -H "Authorization: Bearer ${ACCESS_TOKEN}" \
  -H "Mcp-Session-Id: ${SESSION_ID}" \
  -H "Content-Type: application/json" \
  -H "Accept: application/json, text/event-stream" \
  -d '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"echo","arguments":{"text":"round-trip"}}}')
# Strip any SSE framing: the body may be either raw JSON or an
# `event: message\ndata: {…}` wrapper depending on the transport response
# negotiation. Pluck the JSON payload either way.
tool_payload=$(echo "${tool_body}" | sed -n 's/^data: //p')
[[ -z "${tool_payload}" ]] && tool_payload="${tool_body}"
if ! echo "${tool_payload}" | grep -q 'round-trip'; then
  red "tools/call echo did not round-trip the argument"
  echo "${tool_body}" | head -20 >&2
  exit 1
fi
green "tools/call echo OK (round-tripped \"round-trip\")"

echo
green "ALL CHECKS PASSED"
