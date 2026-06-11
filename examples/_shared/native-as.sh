#!/usr/bin/env bash
# Starts / stops the Authplane authserver as a one-shot Docker container
# for the native-flow examples. The container runs the published image
# (`authplane/authserver:latest` by default) and mounts the
# shared minimal config.
#
# Usage:
#   examples/_shared/native-as.sh start   # boot the AS in the background
#   examples/_shared/native-as.sh stop    # remove the container
#   examples/_shared/native-as.sh logs    # tail recent AS logs
#
# Environment overrides (all optional):
#   AS_CONTAINER  container name           (default: authplane-example-as)
#   AS_IMAGE      image tag                (default: authplane/authserver:latest)
#   AS_PORT       public OAuth port        (default: 9000)
#   AS_ADMIN_PORT admin API port           (default: 9001)
#   AS_CONFIG     path to config.yaml      (default: this directory's config.example.yaml)
#
# Required env (read from caller's .env before invocation):
#   AUTHPLANE_SERVER_ISSUER, AUTHPLANE_ADMIN_API_KEY, AUTHPLANE_SESSION_SECRET,
#   AUTHPLANE_CLIENT_CREDENTIALS_ENABLED, AUTHPLANE_DPOP_ENABLED, AUTHPLANE_TOKEN_EXCHANGE_ENABLED

set -e

AS_CONTAINER="${AS_CONTAINER:-authplane-example-as}"
AS_IMAGE="${AS_IMAGE:-authplane/authserver:latest}"
AS_PORT="${AS_PORT:-9000}"
AS_ADMIN_PORT="${AS_ADMIN_PORT:-9001}"
script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
AS_CONFIG="${AS_CONFIG:-$script_dir/config.example.yaml}"

case "${1:-}" in
  start)
    docker rm -f "$AS_CONTAINER" >/dev/null 2>&1 || true
    docker run -d --rm --name "$AS_CONTAINER" \
      -p "$AS_PORT:9000" -p "$AS_ADMIN_PORT:9001" \
      -e AUTHPLANE_SERVER_ISSUER \
      -e AUTHPLANE_ADMIN_API_KEY \
      -e AUTHPLANE_SESSION_SECRET \
      -e AUTHPLANE_CLIENT_CREDENTIALS_ENABLED \
      -e AUTHPLANE_DPOP_ENABLED \
      -e AUTHPLANE_TOKEN_EXCHANGE_ENABLED \
      -v "$AS_CONFIG:/config.yaml:ro" \
      "$AS_IMAGE" serve --config /config.yaml >/dev/null
    echo "  authserver:   $AS_CONTAINER on :$AS_PORT / admin :$AS_ADMIN_PORT"
    ;;
  stop)
    docker rm -f "$AS_CONTAINER" >/dev/null 2>&1 || true
    ;;
  logs)
    docker logs "$AS_CONTAINER" 2>&1 | tail -40 || echo "(authserver container not running)"
    ;;
  *)
    echo "usage: $0 {start|stop|logs}" >&2
    exit 2
    ;;
esac
