#!/usr/bin/env bash
# verify.sh — end-to-end smoke for Tier 04 (Go broker + RFC 8693 + consent).
#
# Pipeline (mirrors the Python and TypeScript tier-04 scripts):
#   1. wait for authserver discovery (:9000) and confirm token-exchange is
#      advertised in `grant_types_supported`
#   2. register the upstream broker provider (POST /admin/broker-providers)
#   3. register an actor MCP (Mint resource). The broker dispatch path
#      identifies the actor MCP via policy.runtime.client_ids list-membership
#      (token_exchange.go:1244-1314); without this row the exchange would be
#      rejected with `unauthorized_client` before any consent check runs.
#   4. register the Broker resource bound to the provider, with a scope
#      catalog (POST /admin/resources, backend_kind=broker)
#   5. register the acting confidential client with BOTH
#      `client_credentials` (so the verify pipeline can mint the
#      subject_token below) AND
#      `urn:ietf:params:oauth:grant-type:token-exchange` (the grant the
#      agent itself uses). Public clients cannot perform token exchange —
#      see docs/guides/upstream-providers/token-exchange-grant.md step 2.
#   6. bind the client to the actor MCP (POST
#      /admin/resources/{actor}/policy/runtime/client-ids) so
#      resolveActorMCP succeeds at exchange time.
#   7. add the client to policy.exchange.allowed_client_ids on the broker
#      resource (POST /admin/resources/{slug}/policy/exchange/allowed-clients)
#   8. mint a `client_credentials` token via POST /oauth/token. This is the
#      service-account access token the agent presents as `subject_token`;
#      it stands in for the user-issued access token an MCP server would
#      forward verbatim in a real deployment. Persisted to .env so main.go
#      can read it via AUTHPLANE_USER_ACCESS_TOKEN.
#   9. `go run ./` the agent. The agent attempts the token exchange, gets
#      back `consent_required` from the AS (no consent_grants row exists
#      for this user/agent/resource, and there's no admin endpoint to seed
#      one — consent_grants and broker_grants are written only by the real
#      interactive `/connect/<provider>` flow), catches
#      `*authplane.ConsentRequiredError`, prints the `consent_url` an
#      operator would surface to a real user, and exits 2.
#  10. assert the agent exited 2 and that its stdout contains the
#      consent_url banner. THAT is the tier-04 demonstration: every
#      production agent has to handle this branch, and this is what it
#      looks like.
#
# Exits 0 on full success. Any failure prints the offending response and exits 1.

set -euo pipefail

# Endpoint URLs. Override via env if the example is brought up on non-default
# ports (e.g. during local development with a docker-compose.override.yml).
ADMIN_URL="${ADMIN_URL:-http://localhost:9001}"
ISSUER_URL="${ISSUER_URL:-http://localhost:9000}"
PROVIDER_SLUG="${BROKER_PROVIDER_SLUG:-github}"
RESOURCE_SLUG="${BROKER_RESOURCE_SLUG:-github}"
# Slug of the Mint resource representing the acting MCP. Python tier-04 uses
# `mcp-agent`; we suffix `-go` so the two examples can share an authserver
# during cross-language smokes without clobbering each other.
ACTOR_RESOURCE_SLUG="${ACTOR_RESOURCE_SLUG:-mcp-agent-go}"
ACTOR_RESOURCE_URI="${ACTOR_RESOURCE_URI:-http://localhost:8080/mcp-go}"

# Pull config from .env so we don't rely on the operator exporting it.
if [[ -f .env ]]; then
  # shellcheck disable=SC1091
  set -a; source .env; set +a
fi
: "${AUTHPLANE_ADMIN_API_KEY:?missing AUTHPLANE_ADMIN_API_KEY (is .env present?)}"
: "${CONNECTOR_GITHUB_CLIENT_ID:?missing CONNECTOR_GITHUB_CLIENT_ID (replace placeholder in .env)}"
: "${CONNECTOR_GITHUB_SECRET:?missing CONNECTOR_GITHUB_SECRET (replace placeholder in .env)}"

red()   { printf '\033[31m%s\033[0m\n' "$*" >&2; }
green() { printf '\033[32m%s\033[0m\n' "$*"; }
log()   { printf '[verify] %s\n' "$*"; }

# --- step 1: discovery ready + token-exchange advertised --------------------
# Anchor: docs/reference/http-api.md#http-public-well-known-oauth-authorization-server
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
grants_supported=$(curl -fsS "${ISSUER_URL}/.well-known/oauth-authorization-server" | jq -r '.grant_types_supported | join(",")')
if ! echo "$grants_supported" | grep -q 'urn:ietf:params:oauth:grant-type:token-exchange'; then
  red "AS does not advertise token-exchange grant — is AUTHPLANE_TOKEN_EXCHANGE_ENABLED=true?"
  red "grant_types_supported=${grants_supported}"
  exit 1
fi
green "authserver discovery OK; token-exchange advertised"

# Stable URI for the Broker resource — RFC 8707 resource indicator. The
# value is opaque from the AS's perspective (this example never drives the
# user-facing /connect/<provider> flow) but must be a URI so client_credentials
# `resource=` parameters and policy lookups agree.
BROKER_RESOURCE_URI="${BROKER_RESOURCE_URI:-https://github-stub.example.invalid/api}"

# --- step 2: register the upstream broker provider --------------------------
# DTO + handler: api/admin (broker-providers). Anchor:
# docs/reference/http-api.md#http-admin-broker-providers-create
# CLI equivalent: docs/reference/cli.md#cli-admin-provider-create
log "registering broker provider slug=${PROVIDER_SLUG} (idempotent)"
provider_resp=$(curl -sS -X POST "${ADMIN_URL}/admin/broker-providers" \
  -H "Authorization: Bearer ${AUTHPLANE_ADMIN_API_KEY}" \
  -H "Content-Type: application/json" \
  -d @- <<EOF || true
{
  "slug": "${PROVIDER_SLUG}",
  "display_name": "GitHub",
  "protocol": "oauth",
  "config_data": {
    "client_id": "${CONNECTOR_GITHUB_CLIENT_ID}",
    "client_secret_env": "CONNECTOR_GITHUB_SECRET",
    "authorize_url": "https://github.com/login/oauth/authorize",
    "token_url": "https://github.com/login/oauth/access_token"
  }
}
EOF
)
if [[ -z "$provider_resp" ]] || echo "$provider_resp" | grep -q '"code":"conflict"'; then
  log "broker provider already exists — continuing"
else
  echo "$provider_resp" | jq -e '.id' >/dev/null || { red "provider create failed: $provider_resp"; exit 1; }
  green "broker provider registered"
fi

# --- step 3: register the actor MCP (Mint resource) -------------------------
# dispatchBroker identifies the actor MCP by looking up a Mint resource whose
# policy.runtime.client_ids contains the acting client_id
# (token_exchange.go:1244-1255). Without this row, the exchange fails with
# unauthorized_client instead of consent_required. Anchor:
# docs/reference/http-api.md#http-admin-resources-create
log "registering actor MCP Mint resource slug=${ACTOR_RESOURCE_SLUG} (idempotent)"
actor_resp=$(curl -sS -X POST "${ADMIN_URL}/admin/resources" \
  -H "Authorization: Bearer ${AUTHPLANE_ADMIN_API_KEY}" \
  -H "Content-Type: application/json" \
  -d @- <<EOF || true
{
  "slug": "${ACTOR_RESOURCE_SLUG}",
  "uri": "${ACTOR_RESOURCE_URI}",
  "backend_kind": "mint",
  "display_name": "Tier-04 Go demo agent (actor MCP)",
  "scopes": [
    {"name": "mcp:tools", "description": "agent base scope"}
  ]
}
EOF
)
if [[ -z "$actor_resp" ]] || echo "$actor_resp" | grep -q '"code":"conflict"'; then
  log "actor MCP resource already exists — continuing"
else
  echo "$actor_resp" | jq -e '.id' >/dev/null || { red "actor resource create failed: $actor_resp"; exit 1; }
  green "actor MCP resource registered"
fi

# --- step 4: register the Broker resource -----------------------------------
# DTO: createResourceRequest with backend_kind=broker + broker_provider_slug +
# scopes[].upstream. Anchor: docs/reference/http-api.md#http-admin-resources-create
# CLI equivalent: docs/reference/cli.md#cli-admin-resource-create
log "registering Broker resource slug=${RESOURCE_SLUG} (idempotent)"
resource_resp=$(curl -sS -X POST "${ADMIN_URL}/admin/resources" \
  -H "Authorization: Bearer ${AUTHPLANE_ADMIN_API_KEY}" \
  -H "Content-Type: application/json" \
  -d @- <<EOF || true
{
  "slug": "${RESOURCE_SLUG}",
  "uri": "${BROKER_RESOURCE_URI}",
  "backend_kind": "broker",
  "broker_provider_slug": "${PROVIDER_SLUG}",
  "display_name": "GitHub (broker)",
  "scopes": [
    { "name": "repo",      "upstream": "repo" },
    { "name": "read:user", "upstream": "read:user" }
  ]
}
EOF
)
if [[ -z "$resource_resp" ]] || echo "$resource_resp" | grep -q '"code":"conflict"'; then
  log "broker resource already exists — continuing"
else
  echo "$resource_resp" | jq -e '.id' >/dev/null || { red "resource create failed: $resource_resp"; exit 1; }
  green "broker resource registered"
fi

# --- step 5: register the acting confidential client -----------------------
# Confidential client with BOTH grant types: `client_credentials` so the
# verify pipeline can mint the subject_token (step 8 below) AND the
# token-exchange grant the agent itself uses. Public clients cannot perform
# token exchange (see docs/guides/upstream-providers/token-exchange-grant.md
# step 2). Anchor: docs/reference/http-api.md#http-admin-clients-create
log "registering acting client (grant_types=[client_credentials, token-exchange])"
client_resp=$(curl -fsS -X POST "${ADMIN_URL}/admin/clients" \
  -H "Authorization: Bearer ${AUTHPLANE_ADMIN_API_KEY}" \
  -H "Content-Type: application/json" \
  -d @- <<EOF
{
  "client_name": "demo-broker-tier04-agent",
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

# --- step 6: bind the client to the actor MCP -------------------------------
# resolveActorMCP looks up a Mint resource whose policy.runtime.client_ids
# list contains the acting client_id (token_exchange.go:1244-1255). Anchor:
# docs/reference/http-api.md#http-admin-resources-slug-policy-runtime-client-ids-create
log "binding ${CLIENT_ID} as runtime actor on ${ACTOR_RESOURCE_SLUG}"
curl -fsS -X POST \
  "${ADMIN_URL}/admin/resources/${ACTOR_RESOURCE_SLUG}/policy/runtime/client-ids" \
  -H "Authorization: Bearer ${AUTHPLANE_ADMIN_API_KEY}" \
  -H "Content-Type: application/json" \
  -d "{\"client_id\": \"${CLIENT_ID}\"}" >/dev/null
green "actor binding installed"

# --- step 7: authorize the client to exchange against the broker resource ---
# policy.exchange.allowed_client_ids is the third bound of the three-bound
# check (consent_grants + broker_grants + this). Anchor:
# docs/reference/http-api.md#http-admin-resources-slug-policy-exchange-allowed-clients-create
log "adding ${CLIENT_ID} to policy.exchange.allowed_client_ids on ${RESOURCE_SLUG}"
curl -fsS -X POST \
  "${ADMIN_URL}/admin/resources/${RESOURCE_SLUG}/policy/exchange/allowed-clients" \
  -H "Authorization: Bearer ${AUTHPLANE_ADMIN_API_KEY}" \
  -H "Content-Type: application/json" \
  -d "{\"client_id\": \"${CLIENT_ID}\"}" >/dev/null
green "client allowed for exchange"

# --- step 8: mint a base subject_token via client_credentials ---------------
# Stands in for the user-issued access token an MCP server forwards verbatim
# in a real deployment. We mint it here so the verify pipeline is fully
# self-contained — no interactive browser dance required. Anchor:
# docs/reference/http-api.md#http-public-oauth-token
log "minting base subject_token via client_credentials"
token_resp=$(curl -fsS -X POST "${ISSUER_URL}/oauth/token" \
  -u "${CLIENT_ID}:${CLIENT_SECRET}" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --data-urlencode "grant_type=client_credentials" \
  --data-urlencode "scope=mcp:tools" \
  --data-urlencode "resource=${BROKER_RESOURCE_URI}")
USER_ACCESS_TOKEN=$(echo "$token_resp" | jq -er '.access_token')
green "subject_token minted (length=${#USER_ACCESS_TOKEN})"

# --- step 9: write the dynamic creds into .env for the agent ----------------
# main.go reads AUTHPLANE_CLIENT_ID / _SECRET / _USER_ACCESS_TOKEN via
# os.Getenv after `source .env`; rewrite all three keys in one pass so a
# repeated run doesn't accumulate stale lines.
log "writing CLIENT_ID/CLIENT_SECRET/USER_ACCESS_TOKEN into .env for the agent"
tmp_env=$(mktemp)
grep -v -E '^(AUTHPLANE_CLIENT_ID|AUTHPLANE_CLIENT_SECRET|AUTHPLANE_USER_ACCESS_TOKEN)=' .env > "$tmp_env"
{
  echo "AUTHPLANE_CLIENT_ID=${CLIENT_ID}"
  echo "AUTHPLANE_CLIENT_SECRET=${CLIENT_SECRET}"
  echo "AUTHPLANE_USER_ACCESS_TOKEN=${USER_ACCESS_TOKEN}"
} >> "$tmp_env"
mv "$tmp_env" .env

# --- step 10: run the agent and assert the ConsentRequiredError branch ------
# The agent attempts an RFC 8693 token exchange against the Broker resource.
# There is no consent_grants row on file for (user, agent, resource) — and
# Authplane provides no admin endpoint to seed one; consent_grants and
# broker_grants are written only by the real interactive
# `/connect/${PROVIDER_SLUG}` flow (anchor:
# docs/reference/http-api.md#http-public-connect-provider). So the AS
# returns `consent_required` with a `consent_url`, the Go SDK surfaces it
# as `*authplane.ConsentRequiredError`, and the agent prints the URL +
# exits 2. THIS is the tier-04 demonstration — every production agent has
# to handle this branch; the example shows exactly what that looks like.
log "building and running the agent — expecting consent_required (exit 2)"
set -a; source .env; set +a
# Build to a temp binary and exec it directly: `go run` always exits 1
# when the inner program exits non-zero (it prints `exit status N` to
# stderr but doesn't propagate N), which makes the rc=2 assertion below
# impossible to satisfy under `go run`. Building + exec'ing the binary
# preserves the real exit code. See https://github.com/golang/go/issues/24284.
agent_bin=$(mktemp -t tier04-agent.XXXXXX)
trap 'rm -f "$agent_bin"' EXIT
go build -o "$agent_bin" ./
# Capture stdout+stderr AND the agent's real exit code. The earlier
# `$(... || true); $?` form always set $? to 0 because the `|| true`
# collapsed the subshell exit code.
agent_rc=0
agent_out=$("$agent_bin" 2>&1) || agent_rc=$?

if [[ $agent_rc -ne 2 ]]; then
  red "agent did NOT exit 2 (got ${agent_rc}); ConsentRequiredError branch did not fire."
  echo "$agent_out" | head -40 >&2
  exit 1
fi

if ! echo "$agent_out" | grep -qi 'consent'; then
  red "agent exited 2 but did not print a consent banner — got:"
  echo "$agent_out" | head -40 >&2
  exit 1
fi
green "consent_required branch fired as expected"
green "(in a real flow, the user would now visit the printed URL and the retry would succeed.)"

echo
green "ALL CHECKS PASSED"
