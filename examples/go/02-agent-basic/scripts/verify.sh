#!/usr/bin/env bash
# verify.sh — end-to-end smoke for Tier 02 (Go agent).
#
# Pipeline (mirrors the tier-02 Python script; the agent itself is the SUT):
#   1. wait for authserver discovery (:9000)
#   2. register a Mint resource matching the MCP audience (idempotent — 409 OK)
#   3. register an OAuth client with the client_credentials grant
#   4. wait for mcp-server (:8080) — confirm it returns 401 unauthenticated
#   5. seed .env with the freshly-minted CLIENT_ID / CLIENT_SECRET
#   6. `go run ./` the agent and assert it prints the echoed text
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
# Resource URI must match the JWT audience the tier-01 MCP server's verifier
# expects. The Go SDK adapter reads it verbatim from AUTHPLANE_RESOURCE and
# uses it as the JWT `aud` claim the verifier requires.
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
    exit 1
  fi
  sleep 1
done
green "authserver discovery OK"

# --- step 2: register the Mint resource -------------------------------------
# DTO: api/admin/dto.go createResourceRequest; scopes use internal/admin/dto/dto.go
# ScopeView. Anchor: docs/reference/http-api.md#http-admin-resources-create
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
if [[ -z "$resource_resp" ]] || echo "$resource_resp" | grep -q '"code":"conflict"'; then
  log "resource already exists — continuing"
else
  echo "$resource_resp" | jq -e '.id' >/dev/null || { red "resource create failed: $resource_resp"; exit 1; }
  green "resource registered"
fi

# --- step 3: register the client --------------------------------------------
# DTO: api/admin/dto.go createClientRequest. grant_types is an array; the admin
# REST handler wraps the CLI input.CreateClientRequest with the same field
# names. Anchor: docs/reference/http-api.md#http-admin-clients-create
log "creating OAuth client with grant_types=[client_credentials]"
client_resp=$(curl -fsS -X POST "${ADMIN_URL}/admin/clients" \
  -H "Authorization: Bearer ${AUTHPLANE_ADMIN_API_KEY}" \
  -H "Content-Type: application/json" \
  -d @- <<EOF
{
  "client_name": "demo-mcp-agent",
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
log "waiting for tier-01 mcp-server at ${MCP_URL} (expect 401 unauthenticated)"
deadline=$(( $(date +%s) + 90 ))
while true; do
  code=$(curl -s -o /dev/null -w '%{http_code}' --max-time 2 "${MCP_URL}" || true)
  if [[ "$code" == "401" || "$code" == "405" ]]; then
    break
  fi
  if [[ $(date +%s) -ge $deadline ]]; then
    red "tier-01 mcp-server did not become ready (last status=${code:-none})"
    red "did you run 'cd ../01-mcp-server-basic && make run' first?"
    exit 1
  fi
  sleep 2
done
green "tier-01 mcp-server is up (unauthenticated probe returned HTTP ${code})"

# --- step 5: seed .env so the agent can read its credentials ----------------
log "writing CLIENT_ID/CLIENT_SECRET into .env for the agent to read"
# Strip any previous AUTHPLANE_CLIENT_ID/AUTHPLANE_CLIENT_SECRET lines, then
# append the fresh values. Keeps the file deterministic across reruns.
tmp_env=$(mktemp)
grep -v '^AUTHPLANE_CLIENT_ID=' .env | grep -v '^AUTHPLANE_CLIENT_SECRET=' > "$tmp_env"
{
  echo "AUTHPLANE_CLIENT_ID=${CLIENT_ID}"
  echo "AUTHPLANE_CLIENT_SECRET=${CLIENT_SECRET}"
} >> "$tmp_env"
mv "$tmp_env" .env

# --- step 6: run the agent and check its output ------------------------------
# The agent acquires a token via authplane.Client.ClientCredentials and POSTs
# a tools/call JSON-RPC request to the tier-01 MCP server. On success it
# prints the echoed text on stdout.
log "running the agent (\`go run ./\`)"
set -a; source .env; set +a
agent_out=$(go run ./ 2>&1) || {
  red "agent exited non-zero:"
  echo "$agent_out" >&2
  exit 1
}

if ! echo "$agent_out" | grep -q 'hello from tier-02 agent'; then
  red "agent did not echo the expected payload — got:"
  echo "$agent_out" | head -40 >&2
  exit 1
fi
green "agent call OK"

echo
green "ALL CHECKS PASSED"
