#!/usr/bin/env bash
# verify.sh — end-to-end smoke for Tier 04 (Python).
#
# Pipeline:
#   1. wait for authserver discovery (:9000) and confirm
#      grant_types_supported advertises RFC 8693.
#   2. register a Broker provider `github-stub` (POST /admin/broker-providers).
#      Endpoints point at example.invalid URLs — the example never actually
#      hits them; the consent step would in a real deployment.
#   3. register a Mint resource `mcp-agent` (POST /admin/resources) — this
#      is the actor MCP the agent's client_id is bound to. The Broker
#      dispatch path needs this to look up consent_grants for the
#      agent-attestation gate (see internal/services/token_exchange.go
#      :1244-1314).
#   4. register a Broker resource `github` backed by `github-stub`
#      (POST /admin/resources with backend_kind=broker).
#   5. register an OAuth client with both `client_credentials` and the
#      token-exchange grant types (POST /admin/clients).
#   6. authorize the client AS the `mcp-agent` Mint resource
#      (POST /admin/resources/mcp-agent/policy/runtime/client-ids) so that
#      `resolveActorMCP(req.ClientID)` succeeds at exchange time.
#   7. authorize the client to act AS the `github` Broker resource
#      (POST /admin/resources/github/policy/exchange/allowed-clients).
#   8. run the agent. It mints a base `client_credentials` token, then
#      attempts a Token Exchange against the Broker resource. The AS
#      returns `consent_required` with a `consent_url` (no consent_grants
#      row on file → bound-B fails first). The agent catches
#      `ConsentRequiredError` and prints the `consent_url` — that IS the
#      tier-04 demonstration. In a real deployment the user would visit
#      that URL and the retry would succeed.
#
# Exits 0 on full success. Any failure prints the offending response and
# exits 1.

set -euo pipefail

# Endpoint URLs. Override via env if the example is brought up on non-default
# ports (e.g. during local development with a docker-compose.override.yml).
ADMIN_URL="${ADMIN_URL:-http://localhost:9001}"
ISSUER_URL="${ISSUER_URL:-http://localhost:9000}"

PROVIDER_SLUG="github-stub"
BROKER_RESOURCE_SLUG="github"
ACTOR_RESOURCE_SLUG="mcp-agent"
ACTOR_RESOURCE_URI="http://localhost:8080/mcp"
BROKER_RESOURCE_URI="https://github-stub.example.invalid/api"

# Pull the admin API key from .env so we don't rely on the operator exporting it.
if [[ -f .env ]]; then
  # shellcheck disable=SC1091
  set -a; source .env; set +a
fi
: "${AUTHPLANE_ADMIN_API_KEY:?missing AUTHPLANE_ADMIN_API_KEY (is .env present?)}"

red()   { printf '\033[31m%s\033[0m\n' "$*" >&2; }
green() { printf '\033[32m%s\033[0m\n' "$*"; }
log()   { printf '[verify] %s\n' "$*"; }

# --- step 1: discovery ready + advertises token-exchange ---------------------
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
discovery=$(curl -fsS "${ISSUER_URL}/.well-known/oauth-authorization-server")
if ! echo "$discovery" | jq -e '.grant_types_supported | index("urn:ietf:params:oauth:grant-type:token-exchange")' >/dev/null; then
  red "AS discovery does not advertise token-exchange — is AUTHPLANE_TOKEN_EXCHANGE_ENABLED=true?"
  echo "$discovery" | jq '.grant_types_supported' >&2 || true
  exit 1
fi
green "authserver discovery OK (advertises token-exchange)"

# --- step 2: register the Broker provider ------------------------------------
# DTO: api/admin/dto.go:374 (createBrokerProviderRequest). The authorize_url /
# token_url point at example.invalid because this example never drives the
# user-facing /connect/<provider> flow — we stop at the ConsentRequiredError
# the agent sees on the very first exchange attempt.
log "creating Broker provider slug=${PROVIDER_SLUG}"
prov_resp=$(curl -fsS -X POST "${ADMIN_URL}/admin/broker-providers" \
  -H "Authorization: Bearer ${AUTHPLANE_ADMIN_API_KEY}" \
  -H "Content-Type: application/json" \
  -d @- <<EOF || true
{
  "slug": "${PROVIDER_SLUG}",
  "display_name": "GitHub (stub)",
  "protocol": "oauth",
  "config_data": {
    "client_id": "stub-client-id",
    "client_secret_env": "AUTHPLANE_ADMIN_API_KEY",
    "authorize_url": "https://github-stub.example.invalid/login/oauth/authorize",
    "token_url": "https://github-stub.example.invalid/login/oauth/access_token"
  }
}
EOF
)
if [[ -z "$prov_resp" ]]; then
  log "broker provider create returned empty body — assuming it already exists, continuing"
else
  echo "$prov_resp" | jq -e '.id' >/dev/null || { red "broker provider create failed: $prov_resp"; exit 1; }
  green "broker provider registered"
fi

# --- step 3: register the actor MCP (Mint resource) --------------------------
# The Broker dispatch path identifies the actor MCP by looking up a Mint
# resource whose `policy.runtime.client_ids` contains the acting client_id
# (see token_exchange.go:1244-1255). Without this, the exchange fails with
# `unauthorized_client` instead of `consent_required`.
log "creating Mint resource slug=${ACTOR_RESOURCE_SLUG} (actor MCP)"
actor_resp=$(curl -fsS -X POST "${ADMIN_URL}/admin/resources" \
  -H "Authorization: Bearer ${AUTHPLANE_ADMIN_API_KEY}" \
  -H "Content-Type: application/json" \
  -d @- <<EOF || true
{
  "slug": "${ACTOR_RESOURCE_SLUG}",
  "uri": "${ACTOR_RESOURCE_URI}",
  "backend_kind": "mint",
  "display_name": "Tier-04 demo agent (actor MCP)",
  "scopes": [
    {"name": "mcp:tools", "description": "agent base scope"}
  ]
}
EOF
)
if [[ -z "$actor_resp" ]]; then
  log "actor resource create returned empty body — assuming it already exists, continuing"
else
  echo "$actor_resp" | jq -e '.id' >/dev/null || { red "actor resource create failed: $actor_resp"; exit 1; }
  green "actor Mint resource registered"
fi

# --- step 4: register the Broker resource ------------------------------------
# DTO: api/admin/dto.go:349 (createResourceRequest). `broker_provider_slug`
# is the slug-friendly alternative to `broker_provider_id` — the handler
# resolves it before persistence (dto.go:344-348).
log "creating Broker resource slug=${BROKER_RESOURCE_SLUG} provider=${PROVIDER_SLUG}"
broker_resp=$(curl -fsS -X POST "${ADMIN_URL}/admin/resources" \
  -H "Authorization: Bearer ${AUTHPLANE_ADMIN_API_KEY}" \
  -H "Content-Type: application/json" \
  -d @- <<EOF || true
{
  "slug": "${BROKER_RESOURCE_SLUG}",
  "uri": "https://github-stub.example.invalid/api",
  "backend_kind": "broker",
  "broker_provider_slug": "${PROVIDER_SLUG}",
  "display_name": "GitHub (brokered)",
  "scopes": [
    {"name": "repo",      "upstream": "repo",      "description": "repo access"},
    {"name": "read:user", "upstream": "read:user", "description": "user profile"}
  ]
}
EOF
)
if [[ -z "$broker_resp" ]]; then
  log "broker resource create returned empty body — assuming it already exists, continuing"
else
  echo "$broker_resp" | jq -e '.id' >/dev/null || { red "broker resource create failed: $broker_resp"; exit 1; }
  green "Broker resource registered"
fi

# --- step 5: register the OAuth client ---------------------------------------
# Confidential client with BOTH grant types: client_credentials (to mint the
# base machine token) and token-exchange (to exchange it for an
# upstream-narrowed broker token). Per docs/guides/upstream-providers/
# token-exchange-grant.md step 2, public clients cannot do token exchange.
log "creating OAuth client (client_credentials + token-exchange)"
client_resp=$(curl -fsS -X POST "${ADMIN_URL}/admin/clients" \
  -H "Authorization: Bearer ${AUTHPLANE_ADMIN_API_KEY}" \
  -H "Content-Type: application/json" \
  -d @- <<EOF
{
  "client_name": "tier04-broker-agent",
  "grant_types": [
    "client_credentials",
    "urn:ietf:params:oauth:grant-type:token-exchange"
  ],
  "token_endpoint_auth_method": "client_secret_basic",
  "scope": "mcp:tools repo read:user"
}
EOF
)
CLIENT_ID=$(echo "$client_resp" | jq -er '.client_id')
CLIENT_SECRET=$(echo "$client_resp" | jq -er '.client_secret')
green "client created: ${CLIENT_ID}"

# --- step 6: authorize the client AS the actor MCP ---------------------------
# Endpoint: POST /admin/resources/{slug}/policy/runtime/client-ids — see
# docs/reference/http-api.md anchor
# `http-admin-resources-slug-policy-runtime-client-ids-create`. Without this,
# the AS cannot resolve the acting client to its Mint actor resource and
# refuses the exchange with unauthorized_client (token_exchange.go:1257-1265).
log "authorizing client ${CLIENT_ID} as runtime actor for resource ${ACTOR_RESOURCE_SLUG}"
curl -fsS -X POST "${ADMIN_URL}/admin/resources/${ACTOR_RESOURCE_SLUG}/policy/runtime/client-ids" \
  -H "Authorization: Bearer ${AUTHPLANE_ADMIN_API_KEY}" \
  -H "Content-Type: application/json" \
  -d "{\"client_id\": \"${CLIENT_ID}\"}" >/dev/null
green "actor binding installed"

# --- step 7: authorize the client to exchange against the Broker resource ---
# Endpoint: POST /admin/resources/{slug}/policy/exchange/allowed-clients —
# anchor `http-admin-resources-slug-policy-exchange-allowed-clients-create`.
# DTO: api/admin/resources_policy.go:24 (allowedClientRequest). Without
# this, the operator gate rejects the exchange before any consent check
# even runs (token_exchange.go:1184-1195).
log "authorizing client ${CLIENT_ID} as token-exchange actor for resource ${BROKER_RESOURCE_SLUG}"
curl -fsS -X POST "${ADMIN_URL}/admin/resources/${BROKER_RESOURCE_SLUG}/policy/exchange/allowed-clients" \
  -H "Authorization: Bearer ${AUTHPLANE_ADMIN_API_KEY}" \
  -H "Content-Type: application/json" \
  -d "{\"client_id\": \"${CLIENT_ID}\"}" >/dev/null
green "exchange policy installed"

# --- step 8: run the agent — expect ConsentRequiredError --------------------
# Inside the compose network the agent reaches the AS at `authserver:9000`.
log "running agent.py — expect ConsentRequiredError with consent_url"
agent_out=$(docker compose run --rm --no-TTY \
  -e CLIENT_ID="${CLIENT_ID}" \
  -e CLIENT_SECRET="${CLIENT_SECRET}" \
  -e AUTHPLANE_ISSUER="http://authserver:9000" \
  -e BROKER_RESOURCE_URI="${BROKER_RESOURCE_URI}" \
  -e BROKER_RESOURCE_SLUG="${BROKER_RESOURCE_SLUG}" \
  -e BROKER_SCOPE="repo" \
  agent 2>&1) || agent_rc=$?
agent_rc="${agent_rc:-0}"

if [[ "$agent_rc" -ne 0 ]]; then
  red "agent exited with code ${agent_rc}"
  echo "$agent_out" | head -80 >&2
  exit 1
fi

if ! echo "$agent_out" | grep -q 'consent_required'; then
  red "agent did not surface consent_required; got:"
  echo "$agent_out" | head -80 >&2
  exit 1
fi
if ! echo "$agent_out" | grep -q 'consent_url='; then
  red "agent did not print a consent_url; got:"
  echo "$agent_out" | head -80 >&2
  exit 1
fi
green "agent received ConsentRequiredError with consent_url — broker flow OK"

echo
green "ALL CHECKS PASSED"
