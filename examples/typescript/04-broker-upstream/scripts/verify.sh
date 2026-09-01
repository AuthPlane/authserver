#!/usr/bin/env bash
# verify.sh — end-to-end smoke for Tier 04 (TypeScript Broker upstream).
#
# Pipeline:
#   1. wait for authserver discovery (:9000)
#   2. register a Broker provider (fake authorize/token URLs — the agent
#      never reaches the upstream, the flow stops at consent_required)
#   3. register a Broker-kind Resource backed by the provider above
#   4. register the actor-MCP Resource (Mint) the agent represents
#   5. register an OAuth client with the client_credentials grant
#   6. authorize the client to act AS the actor-MCP resource
#      (policy.runtime.client_ids) and as exchange-acting against the
#      Broker resource (policy.exchange.allowed-clients)
#   7. build + run the agent and assert ConsentRequiredError handling:
#        - agent acquires a subject_token via client_credentials
#        - agent calls AuthplaneClient.exchange(...)
#        - AS returns consent_required + consent_url
#        - SDK maps that to a ConsentRequiredError; agent prints the URL
#
# Exits 0 on full success. Any failure prints the offending response and
# exits 1.

set -euo pipefail

ADMIN_URL="${ADMIN_URL:-http://localhost:9001}"
ISSUER_URL="${ISSUER_URL:-http://localhost:9000}"

UPSTREAM_RESOURCE_SLUG="${UPSTREAM_RESOURCE:-github}"
ACTOR_MCP_SLUG="${ACTOR_MCP_SLUG:-demo-mcp-tier04}"
ACTOR_MCP_URI="${ACTOR_MCP_URI:-http://localhost:8080/mcp}"
PROVIDER_SLUG="${PROVIDER_SLUG:-github}"
# Stable URI of the Broker resource (RFC 8707 resource indicator). The agent
# mints its subject_token against this URI so the exchange is a direct-broker
# exchange — matching the Go and Python tier-04 examples. Minting against the
# actor-MCP Mint instead would make the AS require a fronting_links row.
BROKER_RESOURCE_URI="${BROKER_RESOURCE_URI:-https://github.example.invalid}"

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

# --- step 2: register the Broker provider -----------------------------------
# DTO: createBrokerProviderRequest. Anchor:
#   docs/reference/http-api.md#http-admin-broker-providers-create
# The authorize/token URLs are placeholders. The agent never reaches the
# upstream — the example stops at consent_required.
log "registering broker provider slug=${PROVIDER_SLUG} (placeholder URLs)"
provider_status=$(curl -s -o /tmp/provider.$$ -w '%{http_code}' -X POST "${ADMIN_URL}/admin/broker-providers" \
  -H "Authorization: Bearer ${AUTHPLANE_ADMIN_API_KEY}" \
  -H "Content-Type: application/json" \
  -d @- <<EOF
{
  "slug": "${PROVIDER_SLUG}",
  "display_name": "GitHub OAuth",
  "protocol": "oauth",
  "config_data": {
    "client_id": "Iv1.fakeoauthapp_abc123",
    "client_secret_ref": "AUTHPLANE_ADMIN_API_KEY",
    "authorize_url": "https://github.example.invalid/login/oauth/authorize",
    "token_url": "https://github.example.invalid/login/oauth/access_token"
  }
}
EOF
)
if [[ "$provider_status" == "200" || "$provider_status" == "201" ]]; then
  green "broker provider registered"
elif [[ "$provider_status" == "409" ]]; then
  log "broker provider ${PROVIDER_SLUG} already exists, continuing"
else
  red "broker provider create failed: HTTP ${provider_status}"
  cat /tmp/provider.$$ >&2 || true
  rm -f /tmp/provider.$$
  exit 1
fi
rm -f /tmp/provider.$$

# --- step 3: register the Broker-kind Resource ------------------------------
# DTO: createResourceRequest with backend_kind=broker + broker_provider_slug.
# Anchor: docs/reference/http-api.md#http-admin-resources-create
log "registering broker-kind resource slug=${UPSTREAM_RESOURCE_SLUG} backend=broker"
broker_resource_status=$(curl -s -o /tmp/broker-resource.$$ -w '%{http_code}' -X POST "${ADMIN_URL}/admin/resources" \
  -H "Authorization: Bearer ${AUTHPLANE_ADMIN_API_KEY}" \
  -H "Content-Type: application/json" \
  -d @- <<EOF
{
  "slug": "${UPSTREAM_RESOURCE_SLUG}",
  "uri": "${BROKER_RESOURCE_URI}",
  "backend_kind": "broker",
  "broker_provider_slug": "${PROVIDER_SLUG}",
  "display_name": "Demo upstream broker",
  "scopes": [
    {"name": "repo", "description": "repo access", "upstream": "repo"}
  ]
}
EOF
)
if [[ "$broker_resource_status" == "200" || "$broker_resource_status" == "201" ]]; then
  green "broker resource registered"
elif [[ "$broker_resource_status" == "409" ]]; then
  log "broker resource ${UPSTREAM_RESOURCE_SLUG} already exists, continuing"
else
  red "broker resource create failed: HTTP ${broker_resource_status}"
  cat /tmp/broker-resource.$$ >&2 || true
  rm -f /tmp/broker-resource.$$
  exit 1
fi
rm -f /tmp/broker-resource.$$

# --- step 4: register the actor-MCP Mint resource ---------------------------
# The Broker dispatch's agent-attestation gate (token_exchange.go:1255) maps
# the acting req.client_id back to this Mint resource via
# policy.runtime.client_ids (bound in step 6a). The subject_token itself is
# minted against the Broker resource (direct-broker model), not this Mint.
log "registering actor-mcp resource slug=${ACTOR_MCP_SLUG} backend=mint"
actor_resource_status=$(curl -s -o /tmp/actor-resource.$$ -w '%{http_code}' -X POST "${ADMIN_URL}/admin/resources" \
  -H "Authorization: Bearer ${AUTHPLANE_ADMIN_API_KEY}" \
  -H "Content-Type: application/json" \
  -d @- <<EOF
{
  "slug": "${ACTOR_MCP_SLUG}",
  "uri": "${ACTOR_MCP_URI}",
  "backend_kind": "mint",
  "display_name": "Demo actor MCP",
  "scopes": [
    {"name": "repo", "description": "actor-side repo scope"}
  ]
}
EOF
)
if [[ "$actor_resource_status" == "200" || "$actor_resource_status" == "201" ]]; then
  green "actor-mcp resource registered"
elif [[ "$actor_resource_status" == "409" ]]; then
  log "actor-mcp resource ${ACTOR_MCP_SLUG} already exists, continuing"
else
  red "actor-mcp resource create failed: HTTP ${actor_resource_status}"
  cat /tmp/actor-resource.$$ >&2 || true
  rm -f /tmp/actor-resource.$$
  exit 1
fi
rm -f /tmp/actor-resource.$$

# --- step 5: register the OAuth client --------------------------------------
# DTO: createClientRequest. Anchor:
#   docs/reference/http-api.md#http-admin-clients-create
# Client gets both client_credentials (to acquire the subject_token) and
# the RFC 8693 grant (to call /oauth/token with grant_type=token-exchange).
log "creating OAuth client (client_credentials + token-exchange grants)"
client_resp=$(curl -fsS -X POST "${ADMIN_URL}/admin/clients" \
  -H "Authorization: Bearer ${AUTHPLANE_ADMIN_API_KEY}" \
  -H "Content-Type: application/json" \
  -d @- <<EOF
{
  "client_name": "demo-broker-upstream-client",
  "grant_types": ["client_credentials", "urn:ietf:params:oauth:grant-type:token-exchange"],
  "token_endpoint_auth_method": "client_secret_basic",
  "scope": "repo"
}
EOF
)
CLIENT_ID=$(echo "$client_resp" | jq -er '.client_id')
CLIENT_SECRET=$(echo "$client_resp" | jq -er '.client_secret')
green "client created: ${CLIENT_ID}"

# --- step 6a: authorize client AS the actor-MCP (runtime.client_ids) -------
# Endpoint: POST /admin/resources/{slug}/policy/runtime/client-ids. Anchor:
#   docs/reference/http-api.md#http-admin-resources-slug-policy-runtime-client-ids-create
log "authorizing client ${CLIENT_ID} as runtime actor for ${ACTOR_MCP_SLUG}"
curl -fsS -X POST "${ADMIN_URL}/admin/resources/${ACTOR_MCP_SLUG}/policy/runtime/client-ids" \
  -H "Authorization: Bearer ${AUTHPLANE_ADMIN_API_KEY}" \
  -H "Content-Type: application/json" \
  -d "{\"client_id\": \"${CLIENT_ID}\"}" >/dev/null
green "runtime actor linkage created"

# --- step 6b: authorize client to exchange AGAINST the broker resource ------
# Endpoint: POST /admin/resources/{slug}/policy/exchange/allowed-clients.
# Anchor: docs/reference/http-api.md#http-admin-resources-slug-policy-exchange-allowed-clients-create
log "authorizing client ${CLIENT_ID} for exchange against ${UPSTREAM_RESOURCE_SLUG}"
curl -fsS -X POST "${ADMIN_URL}/admin/resources/${UPSTREAM_RESOURCE_SLUG}/policy/exchange/allowed-clients" \
  -H "Authorization: Bearer ${AUTHPLANE_ADMIN_API_KEY}" \
  -H "Content-Type: application/json" \
  -d "{\"client_id\": \"${CLIENT_ID}\"}" >/dev/null
green "exchange policy ACL updated"

# --- step 7: build + run the agent ------------------------------------------
# The agent calls /oauth/token twice:
#   (a) grant_type=client_credentials → subject_token bound to the actor MCP
#   (b) grant_type=urn:ietf:params:oauth:grant-type:token-exchange against
#       the Broker resource — AS returns consent_required + consent_url
#       because no broker_grants row exists for (user, provider).
# Anchor: docs/reference/http-api.md#http-public-oauth-token
log "building agent image"
docker compose build agent >/dev/null
green "agent image built"

agent_log=$(mktemp)
trap 'rm -f "$agent_log"' EXIT

# The agent exits 2 on the consent_required branch — that's the expected
# path here, not a failure. `|| true` keeps `set -e` from tripping; we
# assert on the log content below.
log "running agent (expect ConsentRequiredError + consent_url)"
docker compose run --rm \
  -e AUTHPLANE_ISSUER="http://authserver:9000" \
  -e AUTHPLANE_CLIENT_ID="${CLIENT_ID}" \
  -e AUTHPLANE_CLIENT_SECRET="${CLIENT_SECRET}" \
  -e UPSTREAM_RESOURCE="${UPSTREAM_RESOURCE_SLUG}" \
  -e BROKER_RESOURCE_URI="${BROKER_RESOURCE_URI}" \
  agent 2>&1 | tee "$agent_log" || true

if ! grep -q '\[agent\] consent_required: visit' "$agent_log"; then
  red "agent did not surface ConsentRequiredError (expected '[agent] consent_required: visit ...')"
  exit 1
fi
# Sanity: the consent_url should point at the AS, not be empty/null. The AS
# emits either /connect/{provider} or /authorize?resource=... — both contain
# the issuer host.
if ! grep -qE '\[agent\] consent_required: visit https?://[^[:space:]]+' "$agent_log"; then
  red "consent_url is missing or empty in agent output"
  exit 1
fi

green "agent caught ConsentRequiredError and printed consent_url"
echo
green "ALL CHECKS PASSED"
