#!/usr/bin/env bash
# mcp-demo-server-start.sh — Start the authserver Authorization Server for SDK demos.
#
# Single-phase startup. After the server is up the script provisions everything
# the calculator demo needs through the Admin API — the same surface operators
# use in production:
#   1. POST /admin/resources                                          (calculator MCP resource)
#   2. POST /admin/clients                                            (calculator OAuth client)
#   3. POST /admin/resources/{slug}/policy/exchange/allowed-clients   (allowlist the client for token-exchange)
#   4. POST /admin/users                                              (demo end-user)
#
# The server-generated client credentials are written to:
#   /tmp/authserver-demo.key        (client secret)
#   /tmp/authserver-demo.client-id  (client ID)
#
# SDK demo run.sh scripts read these files to pick up credentials automatically.
#
# Usage:
#   ./demo/mcp-demo-server-start.sh
#
# The server runs in the background. To stop it:
#   kill $(cat /tmp/authserver-demo.pid)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
AUTHSERVER_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
BINARY="${AUTHSERVER_ROOT}/bin/authserver"
CONFIG="${SCRIPT_DIR}/authserver-demo.yaml"
PID_FILE="/tmp/authserver-demo.pid"
LOG_FILE="/tmp/authserver-demo.log"
SECRET_FILE="/tmp/authserver-demo.key"
CLIENT_ID_FILE="/tmp/authserver-demo.client-id"

ADMIN_URL="http://localhost:9001"
ADMIN_KEY="b480b9760e730abe43b98d0ba01418961df392de0fc6358c36a9a62a8764a7c1"
AUTH_HEADER="Authorization: Bearer ${ADMIN_KEY}"

CALC_RESOURCE_SLUG="calculator-mcp-demo"
CALC_RESOURCE_URI="http://localhost:8080/mcp"

# google-calendar Broker resource — exists solely to demonstrate the URL
# elicitation flow. The broker provider is configured in authserver-demo.yaml
# with fake Google OAuth credentials; clicking the consent_url the AS hands
# back will fail at Google's screen, which is fine: SDK demos only need to
# observe `consent_required` come back from token exchange.
GCAL_RESOURCE_SLUG="google-calendar"
GCAL_RESOURCE_URI="https://www.googleapis.com/calendar/v3"
GCAL_BROKER_PROVIDER_SLUG="google-calendar"
GCAL_UPSTREAM_SCOPE="https://www.googleapis.com/auth/calendar"

# Hardcoded demo secrets.
# Note: AUTHPLANE_SESSION_SECRET is intentionally not set so the server generates
# a random ephemeral secret each run. This ensures browser sessions from previous
# runs are invalidated when the DB is wiped on restart.
export AUTHPLANE_ADMIN_API_KEY="${ADMIN_KEY}"
export AUTHPLANE_ENCRYPTION_KEY="bed8eb204ebfe0bc38750d871e048051129f69c3ea85389c423a54e5b01b0e7f"
# AUTHPLANE_CONNECT_STATE_SECRET overrides connect.state_secret in the YAML.
# Demo-fake value (32+ chars). Generate a real one with: openssl rand -hex 32
export AUTHPLANE_CONNECT_STATE_SECRET="demo-connect-state-secret-not-for-production-use"
# CONNECTOR_GOOGLE_SECRET is the env var the broker_providers[google-calendar]
# config_data.client_secret_ref points at. The value is never exercised — the
# AS only reads it when actually performing the upstream OAuth exchange, which
# requires real Google credentials. The demo only triggers consent_required.
export CONNECTOR_GOOGLE_SECRET="demo-fake-google-client-secret"

if [[ ! -x "${BINARY}" ]]; then
  echo "--> authserver binary not found at ${BINARY} — building..."
  (cd "${AUTHSERVER_ROOT}" && make build)
  if [[ ! -x "${BINARY}" ]]; then
    echo "ERROR: build finished but ${BINARY} is still missing" >&2
    exit 1
  fi
  echo "    Build complete."
  echo ""
fi

stop_server() {
  if [[ -f "${PID_FILE}" ]]; then
    local pid
    pid=$(cat "${PID_FILE}")
    if kill -0 "${pid}" 2>/dev/null; then
      echo "--> Stopping authserver (pid ${pid})..."
      kill "${pid}"
      for _ in $(seq 1 10); do
        kill -0 "${pid}" 2>/dev/null || break
        sleep 0.5
      done
    fi
    rm -f "${PID_FILE}"
  fi
}

wait_for_admin() {
  echo "--> Waiting for admin API at ${ADMIN_URL}..."
  for i in $(seq 1 30); do
    if curl -sf -o /dev/null -H "${AUTH_HEADER}" "${ADMIN_URL}/admin/stats"; then
      echo "    Admin API ready."
      echo ""
      return
    fi
    if [[ $i -eq 30 ]]; then
      echo "ERROR: Admin API not ready after 30 attempts. Check ${LOG_FILE}" >&2
      exit 1
    fi
    sleep 1
  done
}

# ── Start server ──────────────────────────────────────────────────────────────

stop_server

# Always start fresh — wipe the data dir so registrations are clean on every run.
rm -rf "${SCRIPT_DIR}/data"
mkdir -p "${SCRIPT_DIR}/data/keys"

echo "==> Starting authserver"
echo "    Config: ${CONFIG}"
echo "    Log:    ${LOG_FILE}"
echo ""

cd "${SCRIPT_DIR}"
"${BINARY}" serve --config "${CONFIG}" \
  > "${LOG_FILE}" 2>&1 &
echo $! > "${PID_FILE}"
echo "--> authserver started (pid $(cat "${PID_FILE}"))"
echo ""

wait_for_admin

# ── Provision calculator demo via Admin API ──────────────────────────────────

echo "--> Registering calculator MCP resource (POST /admin/resources)..."
RESOURCE_HTTP=$(curl -s -o /tmp/authserver-demo.resource.json -w "%{http_code}" \
  -X POST "${ADMIN_URL}/admin/resources" \
  -H "${AUTH_HEADER}" \
  -H "Content-Type: application/json" \
  -d "{
    \"slug\": \"${CALC_RESOURCE_SLUG}\",
    \"uri\": \"${CALC_RESOURCE_URI}\",
    \"backend_kind\": \"mint\",
    \"display_name\": \"Calculator MCP Demo\",
    \"scopes\": [
      {\"name\": \"tools/add\", \"description\": \"Permission to call the add tool\"},
      {\"name\": \"tools/multiply\", \"description\": \"Permission to call the multiply tool\"},
      {\"name\": \"tools/consent_demo\", \"description\": \"Permission to call the consent_demo tool (URL elicitation flow)\"}
    ]
  }")
if [[ "${RESOURCE_HTTP}" != "201" ]]; then
  echo "ERROR: create resource returned HTTP ${RESOURCE_HTTP}" >&2
  cat /tmp/authserver-demo.resource.json >&2
  exit 1
fi
echo "    created resource: ${CALC_RESOURCE_SLUG} (${CALC_RESOURCE_URI})"
echo ""

echo "--> Registering google-calendar Broker resource (POST /admin/resources)..."
GCAL_HTTP=$(curl -s -o /tmp/authserver-demo.gcal-resource.json -w "%{http_code}" \
  -X POST "${ADMIN_URL}/admin/resources" \
  -H "${AUTH_HEADER}" \
  -H "Content-Type: application/json" \
  -d "{
    \"slug\": \"${GCAL_RESOURCE_SLUG}\",
    \"uri\": \"${GCAL_RESOURCE_URI}\",
    \"backend_kind\": \"broker\",
    \"display_name\": \"Google Calendar (demo, fake credentials)\",
    \"broker_provider_slug\": \"${GCAL_BROKER_PROVIDER_SLUG}\",
    \"scopes\": [
      {
        \"name\": \"${GCAL_UPSTREAM_SCOPE}\",
        \"upstream\": \"${GCAL_UPSTREAM_SCOPE}\",
        \"description\": \"Read/write access to the user's Google calendars\"
      }
    ]
  }")
if [[ "${GCAL_HTTP}" != "201" ]]; then
  echo "ERROR: create google-calendar resource returned HTTP ${GCAL_HTTP}" >&2
  cat /tmp/authserver-demo.gcal-resource.json >&2
  exit 1
fi
echo "    created resource: ${GCAL_RESOURCE_SLUG} (${GCAL_RESOURCE_URI})"
echo ""

# Fronting link calculator-mcp-demo -> google-calendar. Token exchange from the
# Mint source to the Broker target requires this row in `fronting_links`; without
# it the AS rejects with "fronting_link_missing". The scope_map maps the
# inbound calculator scope (tools/consent_demo) to the broker scope the
# upstream provider expects. See docs/how-to/topologies/mcp-gateway-broker.md.
echo "--> Declaring fronting link ${CALC_RESOURCE_SLUG} -> ${GCAL_RESOURCE_SLUG} (POST /admin/fronting)..."
FRONTING_HTTP=$(curl -s -o /tmp/authserver-demo.fronting.json -w "%{http_code}" \
  -X POST "${ADMIN_URL}/admin/fronting" \
  -H "${AUTH_HEADER}" \
  -H "Content-Type: application/json" \
  -d "{
    \"source\": \"${CALC_RESOURCE_SLUG}\",
    \"target\": \"${GCAL_RESOURCE_SLUG}\",
    \"scope_map\": {
      \"tools/consent_demo\": [\"${GCAL_UPSTREAM_SCOPE}\"]
    }
  }")
if [[ "${FRONTING_HTTP}" != "201" ]]; then
  echo "ERROR: create fronting link returned HTTP ${FRONTING_HTTP}" >&2
  cat /tmp/authserver-demo.fronting.json >&2
  exit 1
fi
echo "    linked ${CALC_RESOURCE_SLUG} -> ${GCAL_RESOURCE_SLUG}"
echo ""

echo "--> Registering calculator demo client (POST /admin/clients)..."
CLIENT_RESP=$(curl -s \
  -X POST "${ADMIN_URL}/admin/clients" \
  -H "${AUTH_HEADER}" \
  -H "Content-Type: application/json" \
  -d '{
    "client_name": "Calculator MCP Demo",
    "redirect_uris": ["http://localhost:8080/callback"],
    "grant_types": ["client_credentials", "urn:ietf:params:oauth:grant-type:token-exchange"],
    "token_endpoint_auth_method": "client_secret_basic"
  }')

CALC_CLIENT_ID=$(echo "${CLIENT_RESP}" | grep -o '"client_id":"[^"]*"' | cut -d'"' -f4)
CALC_CLIENT_SECRET=$(echo "${CLIENT_RESP}" | grep -o '"client_secret":"[^"]*"' | cut -d'"' -f4)
if [[ -z "${CALC_CLIENT_ID}" || -z "${CALC_CLIENT_SECRET}" ]]; then
  echo "ERROR: could not extract client_id/client_secret from response:" >&2
  echo "${CLIENT_RESP}" >&2
  exit 1
fi
echo "    obtained client_id: ${CALC_CLIENT_ID}"
echo ""

echo "${CALC_CLIENT_ID}" > "${CLIENT_ID_FILE}"
echo "${CALC_CLIENT_SECRET}" > "${SECRET_FILE}"

add_to_exchange_allowlist() {
  local resource_slug="$1"
  local out_file="/tmp/authserver-demo.allow-${resource_slug}.json"
  local http
  http=$(curl -s -o "${out_file}" -w "%{http_code}" \
    -X POST "${ADMIN_URL}/admin/resources/${resource_slug}/policy/exchange/allowed-clients" \
    -H "${AUTH_HEADER}" \
    -H "Content-Type: application/json" \
    -d "{\"client_id\":\"${CALC_CLIENT_ID}\"}")
  if [[ "${http}" != "200" ]]; then
    echo "ERROR: add allowed client to ${resource_slug} returned HTTP ${http}" >&2
    cat "${out_file}" >&2
    exit 1
  fi
  echo "    allowlisted ${CALC_CLIENT_ID} for token-exchange against ${resource_slug}"
}

echo "--> Adding client to resource exchange allowlists..."
add_to_exchange_allowlist "${CALC_RESOURCE_SLUG}"
add_to_exchange_allowlist "${GCAL_RESOURCE_SLUG}"
echo ""

# Broker dispatch (token exchange targeting a Broker resource) requires the
# requesting client to be runtime-linked to a Mint resource — the AS uses that
# linkage to identify which Mint MCP is acting as the agent for this exchange.
# Without this, the broker-dispatch path fails with access_denied
# ("agent_attestation_unknown_actor") before reaching the consent_required
# check we want the demo to surface.
echo "--> Linking calculator client to calculator-mcp-demo as runtime actor..."
RUNTIME_HTTP=$(curl -s -o /tmp/authserver-demo.runtime.json -w "%{http_code}" \
  -X POST "${ADMIN_URL}/admin/resources/${CALC_RESOURCE_SLUG}/policy/runtime/client-ids" \
  -H "${AUTH_HEADER}" \
  -H "Content-Type: application/json" \
  -d "{\"client_id\":\"${CALC_CLIENT_ID}\"}")
if [[ "${RUNTIME_HTTP}" != "200" ]] && [[ "${RUNTIME_HTTP}" != "201" ]]; then
  echo "ERROR: link runtime client_id to ${CALC_RESOURCE_SLUG} returned HTTP ${RUNTIME_HTTP}" >&2
  cat /tmp/authserver-demo.runtime.json >&2
  exit 1
fi
echo "    runtime-linked ${CALC_CLIENT_ID} -> ${CALC_RESOURCE_SLUG}"
echo ""

echo "--> Registering demo user (POST /admin/users)..."
HTTP_STATUS=$(curl -s -o /dev/null -w "%{http_code}" \
  -X POST "${ADMIN_URL}/admin/users" \
  -H "${AUTH_HEADER}" \
  -H "Content-Type: application/json" \
  -d '{"email":"demo@example.com","name":"Demo User","password":"demo-password","role":"user"}')
if [[ "$HTTP_STATUS" == "201" ]]; then
  echo "    created user: demo@example.com"
elif [[ "$HTTP_STATUS" == "409" ]]; then
  echo "    user exists:  demo@example.com (skipped)"
else
  echo "ERROR: create user returned HTTP ${HTTP_STATUS}" >&2
  exit 1
fi
echo ""

echo "==> Authorization Server ready."
echo ""
echo "    Issuer:               http://localhost:9000"
echo "    Admin API:            http://localhost:9001"
echo "    Calculator (Mint):    ${CALC_RESOURCE_SLUG}  ->  ${CALC_RESOURCE_URI}"
echo "    Google Cal (Broker):  ${GCAL_RESOURCE_SLUG}  ->  ${GCAL_RESOURCE_URI}"
echo "    Client ID:            ${CALC_CLIENT_ID}"
echo "    Client Secret:        ${CALC_CLIENT_SECRET}"
echo "    Client ID file:       ${CLIENT_ID_FILE}"
echo "    Secret file:          ${SECRET_FILE}"
echo ""
echo "    Token exchanges targeting the Broker resource will return"
echo "    error=consent_required with a connect_url — the SDK adapters'"
echo "    URL elicitation flow exists to surface this to MCP clients."
echo ""
echo "    To stop the server:"
echo "      kill \$(cat ${PID_FILE})"
echo ""
