#!/usr/bin/env bash
# verify.sh — end-to-end smoke for Tier 03 (TypeScript FastMCP + DPoP).
#
# Pipeline:
#   1. wait for authserver discovery (:9000)
#   2. register a Mint resource exposing both scopes (mcp:echo, mcp:add)
#   3. register an OAuth client with the client_credentials grant
#   4. wait for mcp-server (:8080) — confirm it returns 401 unauthenticated
#   5. build the agent image, run it, and assert:
#        - DPoP-bound token acquisition succeeds
#        - echo tool call returns 200
#        - add_numbers tool call returns 200 with the expected sum
#
# Note: client_credentials does not require policy.runtime.client_ids on
# the Resource (only token-exchange does). Tier-04 includes the step because that flow uses token-exchange.
#
# Exits 0 on full success. Any failure prints the offending response and
# exits 1.

set -euo pipefail

# Endpoint URLs. Override via env if the example is brought up on non-default
# ports (e.g. during local development with a docker-compose.override.yml).
ADMIN_URL="${ADMIN_URL:-http://localhost:9001}"
ISSUER_URL="${ISSUER_URL:-http://localhost:9000}"
MCP_URL="${MCP_URL:-http://localhost:8080/mcp}"
# Resource URI must match the JWT audience the FastMCP server's verifier
# expects (= the `resource` arg passed to authplaneFastMcpAuth()).
RESOURCE_URI="${RESOURCE_URI:-http://localhost:8080/mcp}"
RESOURCE_SLUG="${RESOURCE_SLUG:-demo-mcp-tier03}"
ECHO_SCOPE="mcp:echo"
ADD_SCOPE="mcp:add"
SCOPES="${ECHO_SCOPE} ${ADD_SCOPE}"

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

# --- step 2: register the Mint resource with BOTH scopes --------------------
# DTO: api/admin/dto.go createResourceRequest; scopes use ScopeView.
# Anchor: docs/reference/http-api.md#http-admin-resources-create
log "creating Mint resource slug=${RESOURCE_SLUG} uri=${RESOURCE_URI} scopes=[${ECHO_SCOPE}, ${ADD_SCOPE}]"
resource_status=$(curl -s -o /tmp/resource.$$ -w '%{http_code}' -X POST "${ADMIN_URL}/admin/resources" \
  -H "Authorization: Bearer ${AUTHPLANE_ADMIN_API_KEY}" \
  -H "Content-Type: application/json" \
  -d @- <<EOF
{
  "slug": "${RESOURCE_SLUG}",
  "uri": "${RESOURCE_URI}",
  "backend_kind": "mint",
  "display_name": "Demo FastMCP DPoP",
  "scopes": [
    {"name": "${ECHO_SCOPE}", "description": "echo tool"},
    {"name": "${ADD_SCOPE}",  "description": "add_numbers tool"}
  ]
}
EOF
)
if [[ "$resource_status" == "200" || "$resource_status" == "201" ]]; then
  green "resource registered"
elif [[ "$resource_status" == "409" ]]; then
  log "resource ${RESOURCE_SLUG} already exists, continuing"
else
  red "resource create failed: HTTP ${resource_status}"
  cat /tmp/resource.$$ >&2 || true
  rm -f /tmp/resource.$$
  exit 1
fi
rm -f /tmp/resource.$$

# --- step 3: register the OAuth client --------------------------------------
# DTO: api/admin/dto.go createClientRequest. Anchor:
#   docs/reference/http-api.md#http-admin-clients-create
log "creating OAuth client with grant_types=[client_credentials] scope='${SCOPES}'"
client_resp=$(curl -fsS -X POST "${ADMIN_URL}/admin/clients" \
  -H "Authorization: Bearer ${AUTHPLANE_ADMIN_API_KEY}" \
  -H "Content-Type: application/json" \
  -d @- <<EOF
{
  "client_name": "demo-fastmcp-dpop-client",
  "grant_types": ["client_credentials"],
  "token_endpoint_auth_method": "client_secret_basic",
  "scope": "${SCOPES}"
}
EOF
)
CLIENT_ID=$(echo "$client_resp" | jq -er '.client_id')
CLIENT_SECRET=$(echo "$client_resp" | jq -er '.client_secret')
green "client created: ${CLIENT_ID}"

# --- step 4: wait for mcp-server ---------------------------------------------
# Readiness probe: any HTTP response means the server is listening. FastMCP's
# httpStream transport answers a bare GET (no MCP session / Accept header) with
# 400 before auth runs; an authenticated-but-tokenless request would get 401,
# and some transports use 405. Accept all three — the real auth assertions come
# from the agent flow below.
log "waiting for mcp-server at ${MCP_URL} (expect 400/401/405)"
deadline=$(( $(date +%s) + 90 ))
while true; do
  code=$(curl -s -o /dev/null -w '%{http_code}' --max-time 2 "${MCP_URL}" || true)
  if [[ "$code" == "400" || "$code" == "401" || "$code" == "405" ]]; then
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

# --- step 5: build + run the agent ------------------------------------------
# The agent uses @authplane/sdk's AuthplaneClient with a DPoPProvider to
# request a DPoP-bound client_credentials token at POST /oauth/token (anchor:
# docs/reference/http-api.md#http-public-oauth-token), then attaches a fresh
# DPoP proof per outbound MCP call. The FastMCP server's verifier rejects
# any request whose DPoP proof key thumbprint differs from the token's
# `cnf.jkt`, exercising RFC 9449 sender-constrained tokens.
log "building agent image"
docker compose build agent >/dev/null
green "agent image built"

agent_issuer="${AGENT_ISSUER:-http://authserver:9000}"
agent_mcp="${AGENT_MCP_URL:-http://mcp-server:8080/mcp}"
agent_resource="${RESOURCE_URI}"  # audience binding; must match the registered resource URI

log "running agent (acquires DPoP-bound token + calls echo and add_numbers)"
agent_log=$(mktemp)
trap 'rm -f "$agent_log"' EXIT

if ! docker compose run --rm \
  -e AUTHPLANE_ISSUER="${agent_issuer}" \
  -e AUTHPLANE_RESOURCE="${agent_resource}" \
  -e AUTHPLANE_CLIENT_ID="${CLIENT_ID}" \
  -e AUTHPLANE_CLIENT_SECRET="${CLIENT_SECRET}" \
  -e MCP_URL="${agent_mcp}" \
  -e ECHO_TEXT="hello from tier 03" \
  agent | tee "$agent_log"; then
  red "agent exited non-zero"
  exit 1
fi

if ! grep -q '\[agent\] echo OK' "$agent_log"; then
  red "agent did not report a successful echo call"
  exit 1
fi
if ! grep -q 'hello from tier 03' "$agent_log"; then
  red "agent echo response did not include the expected text"
  exit 1
fi
if ! grep -q '\[agent\] add_numbers OK' "$agent_log"; then
  red "agent did not report a successful add_numbers call"
  exit 1
fi
# 2 + 3 = 5; the FastMCP add_numbers tool stringifies the sum.
if ! grep -q '"5"' "$agent_log"; then
  red "agent add_numbers response did not include the expected sum '5'"
  exit 1
fi

green "agent completed DPoP-bound calls to both tools"
echo
green "ALL CHECKS PASSED"
