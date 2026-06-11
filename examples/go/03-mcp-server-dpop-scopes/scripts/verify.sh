#!/usr/bin/env bash
# verify.sh — end-to-end smoke for Tier 03 (Go DPoP + scoped tools).
#
# Pipeline (mirrors the tier-02 Go script + a DPoP-bound run of the agent):
#   1. wait for authserver discovery (:9000)
#   2. register a Mint resource with two scopes (mcp:echo, mcp:add) — idempotent
#   3. register an OAuth client with grant_types=[client_credentials] and the
#      two scopes
#   4. wait for mcp-server (:8080) — confirm it returns 401 unauthenticated
#   5. seed .env with the freshly-minted CLIENT_ID / CLIENT_SECRET
#   6. `go run ./agent` and assert it printed both:
#        - the echoed text from the echo tool
#        - the sum '5' from the add_numbers tool
#
# Note: client_credentials does not require policy.runtime.client_ids on
# the Resource (only token-exchange does). Tier-04 includes the step because that flow uses token-exchange.
#
# Exits 0 on full success. Any failure prints the offending response and exits 1.

set -euo pipefail

# Endpoint URLs. Override via env if the example is brought up on non-default
# ports (e.g. during local development with a docker-compose.override.yml).
ADMIN_URL="${ADMIN_URL:-http://localhost:9001}"
ISSUER_URL="${ISSUER_URL:-http://localhost:9000}"
MCP_URL="${MCP_URL:-http://localhost:8080/mcp}"
# Resource URI must match the JWT audience the tier-03 MCP server's verifier
# expects. The Go SDK adapter reads it verbatim from AUTHPLANE_RESOURCE and
# uses it as the JWT `aud` claim the verifier requires; see
# go-sdk/mcp/pkg/authplanemcp/adapter.go (Options.Resource field).
RESOURCE_URI="${RESOURCE_URI:-http://localhost:8080/mcp}"
RESOURCE_SLUG="demo-mcp-tier03"

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

# --- step 2: register the Mint resource with both scopes --------------------
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
  "display_name": "Demo MCP Tier 03",
  "scopes": [
    {"name": "mcp:echo", "description": "echo tool"},
    {"name": "mcp:add",  "description": "add_numbers tool"}
  ]
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
  "client_name": "demo-mcp-tier03-agent",
  "grant_types": ["client_credentials"],
  "token_endpoint_auth_method": "client_secret_basic",
  "scope": "mcp:echo mcp:add"
}
EOF
)
CLIENT_ID=$(echo "$client_resp" | jq -er '.client_id')
CLIENT_SECRET=$(echo "$client_resp" | jq -er '.client_secret')
green "client created: ${CLIENT_ID}"

# --- step 4: wait for mcp-server ---------------------------------------------
log "waiting for tier-03 mcp-server at ${MCP_URL} (expect 401 unauthenticated)"
deadline=$(( $(date +%s) + 90 ))
while true; do
  code=$(curl -s -o /dev/null -w '%{http_code}' --max-time 2 "${MCP_URL}" || true)
  if [[ "$code" == "401" || "$code" == "405" ]]; then
    break
  fi
  if [[ $(date +%s) -ge $deadline ]]; then
    red "tier-03 mcp-server did not become ready (last status=${code:-none})"
    docker compose logs mcp-server | tail -40 >&2 || true
    exit 1
  fi
  sleep 2
done
green "tier-03 mcp-server is up (unauthenticated probe returned HTTP ${code})"

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

# --- step 6: run the DPoP-bound agent and check both tool outputs -----------
# The agent generates a fresh ephemeral ES256 DPoP key, asks the AS to mint a
# client_credentials token DPoP-bound to that key (the AS sets cnf.jkt), and
# then calls both MCP tools with a fresh `DPoP:` proof header per request.
log "running the agent (\`go run ./agent\`)"
# In the native flow the AS, the MCP server and this agent all run against the
# host-visible localhost issuer set in .env, so no AUTHPLANE_ISSUER override is
# needed — sourcing .env is enough.
set -a; source .env; set +a
agent_out=$(go run ./agent 2>&1) || {
  red "agent exited non-zero:"
  echo "$agent_out" >&2
  exit 1
}

if ! echo "$agent_out" | grep -q 'echo:.*hello from tier-03 agent'; then
  red "agent did not echo the expected payload — got:"
  echo "$agent_out" | head -40 >&2
  exit 1
fi

# add_numbers(2,3) -> 5. Match the literal "5" in the add_numbers output line.
if ! echo "$agent_out" | grep -E 'add_numbers:.*"text":"5"' >/dev/null; then
  red "agent did not return the expected sum from add_numbers — got:"
  echo "$agent_out" | head -40 >&2
  exit 1
fi

green "agent calls OK (echo + add_numbers both passed)"

echo
green "ALL CHECKS PASSED"
