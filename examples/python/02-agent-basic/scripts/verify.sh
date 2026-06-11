#!/usr/bin/env bash
# verify.sh — end-to-end smoke for Tier 02 (Python).
#
# Pipeline:
#   1. wait for authserver discovery (:9000)   — brought up by tier 01
#   2. wait for the tier-01 MCP server (:8080) — confirm it returns 401
#   3. register a Mint resource matching the MCP audience (idempotent)
#   4. register an OAuth client with the client_credentials grant
#   5. run agent.py — it acquires a token via the SDK and calls the MCP
#      JSON-RPC `initialize` against the protected MCP server, then prints
#      "authenticated MCP initialize OK" on success. Exit 0 + that
#      substring counts as a pass.
#
# Note: client_credentials does not require policy.runtime.client_ids on
# the Resource (only token-exchange does). Tier-04 includes the step because that flow uses token-exchange.
#
# Tier 02 depends on tier 01 (`examples/python/01-mcp-server-basic`) being
# up first; this script does not start authserver itself.
#
# Exits 0 on full success. Any failure prints the offending response and
# exits 1.

set -euo pipefail

# Endpoint URLs. Override via env if tier 01 was brought up on non-default
# ports (e.g. with a docker-compose.override.yml).
ADMIN_URL="${ADMIN_URL:-http://localhost:9001}"
ISSUER_URL="${ISSUER_URL:-http://localhost:9000}"
MCP_URL="${MCP_URL:-http://localhost:8080/mcp}"
# Resource URI must match the JWT audience the tier-01 MCP server's verifier
# expects (= base_url + /mcp). See tier 01's verify.sh for the same value.
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

# --- step 1: discovery ready (tier 01's authserver) -------------------------
log "waiting for authserver discovery at ${ISSUER_URL}/.well-known/oauth-authorization-server"
deadline=$(( $(date +%s) + 60 ))
until curl -fsS -o /dev/null --max-time 2 "${ISSUER_URL}/.well-known/oauth-authorization-server"; do
  if [[ $(date +%s) -ge $deadline ]]; then
    red "authserver discovery did not return 200 within 60s"
    red "is tier 01 (examples/python/01-mcp-server-basic) running? run \`make run\` there first."
    exit 1
  fi
  sleep 1
done
green "authserver discovery OK"

# --- step 2: wait for tier-01 mcp-server ------------------------------------
log "waiting for tier-01 mcp-server at ${MCP_URL} (expect 401)"
deadline=$(( $(date +%s) + 90 ))
while true; do
  code=$(curl -s -o /dev/null -w '%{http_code}' --max-time 2 "${MCP_URL}" || true)
  if [[ "$code" == "401" || "$code" == "405" ]]; then
    break
  fi
  if [[ $(date +%s) -ge $deadline ]]; then
    red "tier-01 mcp-server did not become ready (last status=${code:-none})"
    red "is tier 01 (examples/python/01-mcp-server-basic) running? run \`make run\` there first."
    exit 1
  fi
  sleep 2
done
green "tier-01 mcp-server is up (unauthenticated probe returned HTTP ${code})"

# --- step 3: register the Mint resource -------------------------------------
# DTO: api/admin/dto.go:349 (createResourceRequest); scopes use
# internal/admin/dto/dto.go:32 (ScopeView). Idempotent: an existing resource
# returns 409, which we accept and continue past.
log "creating Mint resource slug=${RESOURCE_SLUG} uri=${RESOURCE_URI} (idempotent)"
resource_resp=$(curl -sS -X POST "${ADMIN_URL}/admin/resources" \
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

if [[ -z "$resource_resp" ]] || echo "$resource_resp" | grep -q '"error"'; then
  log "resource create returned error or empty body — assuming it already exists from tier 01, continuing"
else
  echo "$resource_resp" | jq -e '.id' >/dev/null || { red "resource create failed: $resource_resp"; exit 1; }
  green "resource registered"
fi

# --- step 4: register the client --------------------------------------------
# DTO: api/admin/dto.go:15 (createClientRequest).
log "creating OAuth client with grant_types=[client_credentials]"
client_resp=$(curl -fsS -X POST "${ADMIN_URL}/admin/clients" \
  -H "Authorization: Bearer ${AUTHPLANE_ADMIN_API_KEY}" \
  -H "Content-Type: application/json" \
  -d @- <<EOF
{
  "client_name": "demo-agent-client",
  "grant_types": ["client_credentials"],
  "token_endpoint_auth_method": "client_secret_basic",
  "scope": "${SCOPE}"
}
EOF
)
CLIENT_ID=$(echo "$client_resp" | jq -er '.client_id')
CLIENT_SECRET=$(echo "$client_resp" | jq -er '.client_secret')
green "client created: ${CLIENT_ID}"

# --- step 5: run agent.py ---------------------------------------------------
# agent.py reads CLIENT_ID / CLIENT_SECRET / AUTHPLANE_ISSUER / RESOURCE_URI
# / MCP_URL from the environment. The .env we loaded above provides the
# AS-side values; the credentials minted in this run are injected
# transiently via `docker compose run -e`. Inside the tier-01 compose
# network the agent reaches the AS at `authserver:9000` and the MCP server
# at `mcp-server:8080`.
log "running agent.py inside the tier-01 compose network"
agent_out=$(docker compose run --rm --no-TTY \
  -e CLIENT_ID="${CLIENT_ID}" \
  -e CLIENT_SECRET="${CLIENT_SECRET}" \
  -e AUTHPLANE_ISSUER="http://authserver:9000" \
  -e RESOURCE_URI="${RESOURCE_URI}" \
  -e MCP_URL="http://mcp-server:8080/mcp" \
  agent 2>&1) || agent_rc=$?
agent_rc="${agent_rc:-0}"

if [[ "$agent_rc" -ne 0 ]]; then
  red "agent exited with code ${agent_rc}"
  echo "$agent_out" | head -60 >&2
  exit 1
fi

if ! echo "$agent_out" | grep -q 'authenticated MCP initialize OK'; then
  red "agent did not print the expected success marker; got:"
  echo "$agent_out" | head -60 >&2
  exit 1
fi
green "agent completed; authenticated MCP initialize OK"

echo
green "ALL CHECKS PASSED"
