#!/bin/sh
# setup.sh — One-shot init script that seeds a demo user into authserver.
# Runs inside a curlimages/curl container started by docker-compose.
set -e

AUTHSERVER_URL="${AUTHSERVER_URL:-http://authserver:9000}"
ADMIN_URL="${ADMIN_URL:-http://authserver:9001}"
ADMIN_KEY="${AUTHPLANE_ADMIN_API_KEY:?AUTHPLANE_ADMIN_API_KEY is required}"

echo "Waiting for authserver to be healthy..."
until curl -sf "$AUTHSERVER_URL/health" > /dev/null 2>&1; do
  sleep 1
done
echo "authserver is healthy."

echo "Creating demo user (demo@example.com)..."
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$ADMIN_URL/admin/users" \
  -H "Authorization: Bearer $ADMIN_KEY" \
  -H "Content-Type: application/json" \
  -d '{"email":"demo@example.com","password":"demo-password","name":"Demo User","role":"user"}')

case "$HTTP_CODE" in
  201) echo "  User created." ;;
  *)   echo "  User creation returned HTTP $HTTP_CODE (may already exist)." ;;
esac

echo ""
echo "Setup complete."
echo "  Login:    demo@example.com / demo-password"
echo "  Admin:    $ADMIN_URL (Bearer token = AUTHPLANE_ADMIN_API_KEY)"
echo "  Grafana:  http://localhost:3000 (admin / admin)"
