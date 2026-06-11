#!/usr/bin/env bash
# verify.sh — end-to-end smoke for Tier 03 (Python).
#
# Pipeline (extends the tier-02 pipeline):
#   1. wait for authserver discovery (:9000)
#   2. register a Mint resource with BOTH scopes (mcp:echo, mcp:add)
#   3. register an OAuth client with the client_credentials grant
#   4. wait for mcp-server (:8080) — confirm it returns 401 unauthenticated
#   5. run agent.py — generates a DPoP key, mints a DPoP-bound token
#      for both scopes, calls `initialize`, `tools/call echo`, and
#      `tools/call add_numbers`; exits 0 on success with a success marker.
#   6. (optional) re-run agent.py with AGENT_DROP_DPOP_PROOF=1 — the
#      MCP server must respond 401 because the DPoP-bound token is being
#      presented without its proof. This is the criterion-#11 check from
#      the brief; it proves DPoP enforcement is real, not just configured.
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
# Resource URI must match the JWT audience the MCP server's verifier expects
# (= base_url + /mcp). The authplane-fastmcp adapter derives this from
# `base_url` + `mcp_path` (default "/mcp"); see
# python-sdk/authplane-fastmcp/authplane_fastmcp/auth.py:188-190.
RESOURCE_URI="${RESOURCE_URI:-http://localhost:8080/mcp}"
RESOURCE_SLUG="demo-mcp-dpop"
SCOPES="mcp:echo mcp:add"

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

# --- step 2: register the Mint resource with both scopes ---------------------
# DTO: api/admin/dto.go (createResourceRequest); scopes use the same
# `name|upstream|description` tuple as tier 01.
log "creating Mint resource slug=${RESOURCE_SLUG} uri=${RESOURCE_URI} scopes=[mcp:echo,mcp:add]"
resource_resp=$(curl -fsS -X POST "${ADMIN_URL}/admin/resources" \
  -H "Authorization: Bearer ${AUTHPLANE_ADMIN_API_KEY}" \
  -H "Content-Type: application/json" \
  -d @- <<EOF || true
{
  "slug": "${RESOURCE_SLUG}",
  "uri": "${RESOURCE_URI}",
  "backend_kind": "mint",
  "display_name": "Demo MCP (DPoP + per-tool scopes)",
  "scopes": [
    {"name": "mcp:echo", "description": "echo tool"},
    {"name": "mcp:add",  "description": "add_numbers tool"}
  ]
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

# --- step 3: register the OAuth client --------------------------------------
log "creating OAuth client with grant_types=[client_credentials] scope='${SCOPES}'"
client_resp=$(curl -fsS -X POST "${ADMIN_URL}/admin/clients" \
  -H "Authorization: Bearer ${AUTHPLANE_ADMIN_API_KEY}" \
  -H "Content-Type: application/json" \
  -d @- <<EOF
{
  "client_name": "demo-dpop-client",
  "grant_types": ["client_credentials"],
  "token_endpoint_auth_method": "client_secret_basic",
  "scope": "${SCOPES}"
}
EOF
)
CLIENT_ID=$(echo "$client_resp" | jq -er '.client_id')
CLIENT_SECRET=$(echo "$client_resp" | jq -er '.client_secret')
green "client created: ${CLIENT_ID}"

# --- step 4: wait for mcp-server --------------------------------------------
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

# --- step 5: run agent.py — happy path --------------------------------------
# Inside the compose network the agent reaches the AS at `authserver:9000`
# and the MCP server at `mcp-server:8080`. We inject CLIENT_ID/SECRET
# transiently via `docker compose run -e`.
log "running agent.py (DPoP-bound token, both scopes)"
agent_out=$(docker compose run --rm --no-TTY \
  -e CLIENT_ID="${CLIENT_ID}" \
  -e CLIENT_SECRET="${CLIENT_SECRET}" \
  -e AUTHPLANE_ISSUER="http://authserver" \
  -e RESOURCE_URI="${RESOURCE_URI}" \
  -e MCP_URL="http://mcp-server:8080/mcp" \
  agent 2>&1) || agent_rc=$?
agent_rc="${agent_rc:-0}"

if [[ "$agent_rc" -ne 0 ]]; then
  red "agent exited with code ${agent_rc}"
  echo "$agent_out" | head -80 >&2
  exit 1
fi

if ! echo "$agent_out" | grep -q 'authenticated MCP DPoP + per-tool scope calls OK'; then
  red "agent did not print the expected success marker; got:"
  echo "$agent_out" | head -80 >&2
  exit 1
fi
green "agent completed; happy-path DPoP + scope calls OK"

# --- step 6: criterion-#11 negative probe (optional but valuable) -----------
# Re-run the agent with the DPoP header stripped from the MCP call. The
# server's verifier must respond 401 because the token is DPoP-bound but
# the proof header is missing. Skip this probe by setting SKIP_DPOP_NEG=1.
if [[ "${SKIP_DPOP_NEG:-0}" != "1" ]]; then
  log "running agent.py with DPoP proof stripped — expect 401 from MCP server"
  set +e
  neg_out=$(docker compose run --rm --no-TTY \
    -e CLIENT_ID="${CLIENT_ID}" \
    -e CLIENT_SECRET="${CLIENT_SECRET}" \
    -e AUTHPLANE_ISSUER="http://authserver" \
    -e RESOURCE_URI="${RESOURCE_URI}" \
    -e MCP_URL="http://mcp-server:8080/mcp" \
    -e AGENT_DROP_DPOP_PROOF="1" \
    agent 2>&1)
  neg_rc=$?
  set -e
  if [[ "$neg_rc" -eq 0 ]]; then
    red "negative probe unexpectedly succeeded — server did NOT enforce DPoP binding"
    echo "$neg_out" | head -40 >&2
    exit 1
  fi
  if ! echo "$neg_out" | grep -q 'HTTP 401'; then
    red "negative probe failed but did not return 401; got:"
    echo "$neg_out" | head -40 >&2
    exit 1
  fi
  green "negative probe rejected with HTTP 401 — DPoP enforcement confirmed"
fi

echo
green "ALL CHECKS PASSED"
