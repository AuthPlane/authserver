#!/usr/bin/env bash
# Verifies that the universal prereqs for the native-flow examples are
# present and ready. Per-language prereqs (Go / Python / Node) are checked
# by each example's own Makefile before calling this script.
#
# Usage:
#   examples/_shared/check-prereqs.sh
#
# Exits non-zero with an actionable message on the first missing dep.

set -e

missing=()

need() {
  local cmd="$1" hint="$2"
  if ! command -v "$cmd" >/dev/null 2>&1; then
    missing+=("$cmd  ← $hint")
  fi
}

need docker "install Docker Desktop (https://docker.com/products/docker-desktop) or rancher-desktop"
need curl   "preinstalled on macOS/Linux; install via your package manager"
need jq     "macOS: brew install jq   |   Debian/Ubuntu: apt install jq   |   Alpine: apk add jq"

if [[ ${#missing[@]} -gt 0 ]]; then
  echo "ERROR: missing required commands:" >&2
  for line in "${missing[@]}"; do echo "  - $line" >&2; done
  exit 1
fi

if ! docker info >/dev/null 2>&1; then
  echo "ERROR: docker is installed but the daemon is not running." >&2
  echo "       Start Docker Desktop (or 'rancher-desktop start') and retry." >&2
  exit 1
fi
