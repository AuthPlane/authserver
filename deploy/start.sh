#!/bin/sh
# start.sh — Start the Authplane infrastructure stack.
#
# Auto-generates session secret and admin API key if not already set.
# Passes all arguments to docker compose (e.g. --build, -d, down).
#
# Usage:
#   ./deploy/start.sh up --build        # Start with build
#   ./deploy/start.sh up --build -d     # Start detached
#   ./deploy/start.sh down -v           # Tear down with volumes
#   ./deploy/start.sh logs authserver      # View logs
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
COMPOSE_FILE="${COMPOSE_FILE:-$SCRIPT_DIR/docker-compose.yml}"

# Auto-generate secrets if not set.
if [ -z "$AUTHPLANE_SESSION_SECRET" ]; then
  export AUTHPLANE_SESSION_SECRET="$(openssl rand -hex 32)"
  echo "Generated AUTHPLANE_SESSION_SECRET (ephemeral)."
fi

if [ -z "$AUTHPLANE_ADMIN_API_KEY" ]; then
  export AUTHPLANE_ADMIN_API_KEY="$(openssl rand -hex 32)"
  echo "Generated AUTHPLANE_ADMIN_API_KEY: $AUTHPLANE_ADMIN_API_KEY"
  echo "  (save this if you need to call the admin API from the host)"
fi

echo ""
echo "Compose file: $COMPOSE_FILE"
echo ""

exec docker compose -f "$COMPOSE_FILE" "$@"
