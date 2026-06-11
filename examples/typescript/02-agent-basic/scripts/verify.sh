#!/usr/bin/env bash
# verify.sh — end-to-end smoke for Tier 02 (TypeScript agent).
#
# Tier 02 is the client side of tier 01 (`../01-mcp-server-basic`). This
# script assumes tier 01's `make run` has already brought up the authserver
# (:9000/:9001) and the MCP server (:8080).
#
# Pipeline:
#   1. wait for authserver discovery (:9000) and the MCP server (:8080)
#   2. register a Mint resource that matches the MCP audience (idempotent)
#   3. register an OAuth client with the client_credentials grant
#   4. build the agent container (or reuse the cached image)
#   5. run the agent — it acquires a token via @authplane/sdk and calls the
#      tier-01 echo tool with the bearer token
#
# Note: client_credentials does not require policy.runtime.client_ids on
# the Resource (only token-exchange does). Tier-04 includes the step because that flow uses token-exchange.
#
# Exits 0 on full success. Any failure prints the offending response and
# exits 1.

set -euo pipefail

# Endpoint URLs. Override via env if the example pair is brought up on
# non-default ports.
ADMIN_URL="${ADMIN_URL:-http://localhost:9001}"
ISSUER_URL="${ISSUER_URL:-http://localhost:9000}"
MCP_URL="${MCP_URL:-http://localhost:8080/mcp}"
# Resource URI must match the JWT audience the tier-01 MCP server expects.
RESOURCE_URI="${RESOURCE_URI:-http://localhost:8080/mcp}"
RESOURCE_SLUG="${RESOURCE_SLUG:-demo-mcp}"
SCOPE="${SCOPE:-mcp:echo}"

# Pull the admin API key from .env so we don't rely on the operator exporting it.
if [[ -f .env ]]; then
  # shellcheck disable=SC1091
  set -a; source .env; set +a
fi
: "${AUTHPLANE_ADMIN_API_KEY:?missing AUTHPLANE_ADMIN_API_KEY (is .env present?)}"

red()   { printf '\033[31m%s\033[0m\n' "$*" >&2; }
green() { printf '\033[32m%s\033[0m\n' "$*"; }
log()   { printf '[verify] %s\n' "$*"; }

# --- step 1a: discovery ready -----------------------------------------------
log "waiting for authserver discovery at ${ISSUER_URL}/.well-known/oauth-authorization-server"
deadline=$(( $(date +%s) + 60 ))
until curl -fsS -o /dev/null --max-time 2 "${ISSUER_URL}/.well-known/oauth-authorization-server"; do
  if [[ $(date +%s) -ge $deadline ]]; then
    red "authserver discovery did not return 200 within 60s — is tier 01 running?"
    red "  cd ../01-mcp-server-basic && make run"
    exit 1
  fi
  sleep 1
done
green "authserver discovery OK"

# --- step 1b: tier-01 mcp server ready --------------------------------------
log "waiting for tier-01 mcp-server at ${MCP_URL} (expect 401 unauthenticated)"
deadline=$(( $(date +%s) + 60 ))
while true; do
  code=$(curl -s -o /dev/null -w '%{http_code}' --max-time 2 "${MCP_URL}" || true)
  if [[ "$code" == "401" || "$code" == "405" ]]; then
    break
  fi
  if [[ $(date +%s) -ge $deadline ]]; then
    red "tier-01 mcp-server did not become ready (last status=${code:-none}) — is tier 01 running?"
    exit 1
  fi
  sleep 2
done
green "tier-01 mcp-server is up (unauthenticated probe returned HTTP ${code})"

# --- step 2: register the Mint resource (idempotent) ------------------------
# DTO: api/admin/dto.go createResourceRequest. Anchor:
#   docs/reference/http-api.md#http-admin-resources-create
log "creating Mint resource slug=${RESOURCE_SLUG} uri=${RESOURCE_URI} (ignoring 409)"
resource_status=$(curl -s -o /tmp/resource.$$ -w '%{http_code}' -X POST "${ADMIN_URL}/admin/resources" \
  -H "Authorization: Bearer ${AUTHPLANE_ADMIN_API_KEY}" \
  -H "Content-Type: application/json" \
  -d @- <<EOF
{
  "slug": "${RESOURCE_SLUG}",
  "uri": "${RESOURCE_URI}",
  "backend_kind": "mint",
  "display_name": "Demo MCP",
  "scopes": [{"name": "${SCOPE}", "description": "echo tool"}]
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
log "creating OAuth client with grant_types=[client_credentials]"
client_resp=$(curl -fsS -X POST "${ADMIN_URL}/admin/clients" \
  -H "Authorization: Bearer ${AUTHPLANE_ADMIN_API_KEY}" \
  -H "Content-Type: application/json" \
  -d @- <<EOF
{
  "client_name": "demo-agent-ts",
  "grant_types": ["client_credentials"],
  "token_endpoint_auth_method": "client_secret_basic",
  "scope": "${SCOPE}"
}
EOF
)
CLIENT_ID=$(echo "$client_resp" | jq -er '.client_id')
CLIENT_SECRET=$(echo "$client_resp" | jq -er '.client_secret')
green "client created: ${CLIENT_ID}"

# --- step 4: build the agent image ------------------------------------------
log "building agent image"
docker compose build agent >/dev/null
green "agent image built"

# --- step 5: run the agent --------------------------------------------------
# The agent uses @authplane/sdk's AuthplaneClient to request a
# client_credentials token at POST /oauth/token (anchor:
# docs/reference/http-api.md#http-public-oauth-token), then calls the
# tier-01 MCP server with the bearer token.
#
# The agent container joins tier-01's compose network, so it can resolve
# the service hostnames directly. The SDK validates that the discovered
# `metadata.issuer` matches the configured `issuer` — that means the
# agent's issuer URL must be the same one tier-01's AS was configured
# with (`http://authserver:9000` per tier-01 `.env.example`).
agent_issuer="${AGENT_ISSUER:-http://authserver:9000}"
agent_mcp="${AGENT_MCP_URL:-http://mcp-server:8080/mcp}"
agent_resource="${RESOURCE_URI}"  # the audience binding; must match the registered resource URI

log "running agent (acquires token + calls echo tool)"
agent_log=$(mktemp)
trap 'rm -f "$agent_log"' EXIT

if ! docker compose run --rm \
  -e AUTHPLANE_ISSUER="${agent_issuer}" \
  -e AUTHPLANE_RESOURCE="${agent_resource}" \
  -e AUTHPLANE_CLIENT_ID="${CLIENT_ID}" \
  -e AUTHPLANE_CLIENT_SECRET="${CLIENT_SECRET}" \
  -e MCP_URL="${agent_mcp}" \
  -e ECHO_TEXT="hello from tier 02" \
  agent | tee "$agent_log"; then
  red "agent exited non-zero"
  exit 1
fi

if ! grep -q '\[agent\] echo OK' "$agent_log"; then
  red "agent did not report a successful echo call"
  exit 1
fi
if ! grep -q 'hello from tier 02' "$agent_log"; then
  red "agent echo response did not include the expected text"
  exit 1
fi

green "agent echoed via authenticated MCP call"
echo
green "ALL CHECKS PASSED"
