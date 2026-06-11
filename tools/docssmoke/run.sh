#!/usr/bin/env bash
# docssmoke — run `make verify` against every example under examples/<lang>/<NN-name>/.
#
# For each matched example:
#   1. `make run`     — bring up the example's docker compose stack
#   2. wait for the authserver discovery endpoint to return 200 (max 60s)
#   3. `make verify`  — run the example's assertions
#   4. `make clean`   — ALWAYS, via a trap, even on failure / SIGINT
#
# An example is SKIPped (not failed) when it has no Makefile, no `verify`
# target, or ships a `.docssmoke-skip` file (used for examples that aren't
# independently runnable, e.g. tier-02 agents that drive the tier-01 stack).
#
# Exit non-zero if any example failed. `--bail` stops on the first failure.
#
# Env:
#   SMOKE_AUTHSERVER_IMAGE  docker image to export to child makes (default: authplane/authserver:latest)
#
# Deps: bash 4+, docker, curl.

set -euo pipefail

# -----------------------------------------------------------------------------
# Config
# -----------------------------------------------------------------------------

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &>/dev/null && pwd)"
REPO_ROOT="$(cd -- "${SCRIPT_DIR}/../.." &>/dev/null && pwd)"
EXAMPLES_ROOT="${REPO_ROOT}/examples"

DISCOVERY_URL="http://localhost:9000/.well-known/oauth-authorization-server"
HEALTH_TIMEOUT_SECS=60
# Global pre-check: ports the authserver itself binds in every example. The
# per-example pre-check (see check_example_ports) covers additional ports
# (e.g. an MCP server on 8080) by parsing the example's docker-compose.yml.
REQUIRED_PORTS=(9000 9001)

: "${SMOKE_AUTHSERVER_IMAGE:=authplane/authserver:latest}"
export SMOKE_AUTHSERVER_IMAGE

FILTER=""
BAIL=0

# -----------------------------------------------------------------------------
# Output helpers
# -----------------------------------------------------------------------------

if [[ -t 1 ]]; then
  C_RESET=$'\033[0m'
  C_BOLD=$'\033[1m'
  C_RED=$'\033[31m'
  C_GREEN=$'\033[32m'
  C_YELLOW=$'\033[33m'
  C_BLUE=$'\033[34m'
else
  C_RESET=""; C_BOLD=""; C_RED=""; C_GREEN=""; C_YELLOW=""; C_BLUE=""
fi

log()  { printf '%s[docssmoke]%s %s\n' "$C_BLUE"   "$C_RESET" "$*"; }
ok()   { printf '%s[docssmoke]%s %s%s%s\n' "$C_BLUE" "$C_RESET" "$C_GREEN" "$*" "$C_RESET"; }
warn() { printf '%s[docssmoke]%s %s%s%s\n' "$C_BLUE" "$C_RESET" "$C_YELLOW" "$*" "$C_RESET" >&2; }
err()  { printf '%s[docssmoke]%s %s%s%s\n' "$C_BLUE" "$C_RESET" "$C_RED"    "$*" "$C_RESET" >&2; }

# -----------------------------------------------------------------------------
# Usage
# -----------------------------------------------------------------------------

usage() {
  cat <<EOF
Usage: $(basename "$0") [options]

Walks examples/<lang>/<NN-name>/ and runs \`make run\` -> wait-for-health ->
\`make verify\` -> \`make clean\` in each. Cleanup is trap-guarded.

Options:
  --filter <glob>   Only run examples whose path under examples/ matches <glob>
                    (shell glob, e.g. 'python/01*' or 'go/*').
  --bail            Stop on first failure.
  --keep-going      Continue past failures (default).
  -h, --help        Show this help.

Environment:
  SMOKE_AUTHSERVER_IMAGE   authserver image (default: authplane/authserver:latest)

Exit codes:
  0   all examples passed (or none matched / none exist)
  1   one or more examples failed
  2   precondition failed (port conflict, missing deps, bad flags)
EOF
}

# -----------------------------------------------------------------------------
# Arg parsing
# -----------------------------------------------------------------------------

while [[ $# -gt 0 ]]; do
  case "$1" in
    --filter)
      [[ $# -ge 2 ]] || { err "--filter requires a value"; exit 2; }
      FILTER="$2"
      shift 2
      ;;
    --filter=*)
      FILTER="${1#--filter=}"
      shift
      ;;
    --bail)
      BAIL=1
      shift
      ;;
    --keep-going)
      BAIL=0
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      err "unknown argument: $1"
      usage >&2
      exit 2
      ;;
  esac
done

# -----------------------------------------------------------------------------
# Preconditions
# -----------------------------------------------------------------------------

require_cmd() {
  local cmd="$1"
  command -v "$cmd" >/dev/null 2>&1 || { err "required command not found: $cmd"; exit 2; }
}

require_cmd docker
require_cmd curl
require_cmd make

# Port-conflict detection — refuse to fight for the port.
port_in_use() {
  local port="$1"
  # lsof is the most portable check we can rely on across macOS + Linux dev boxes.
  if command -v lsof >/dev/null 2>&1; then
    lsof -nP -iTCP:"$port" -sTCP:LISTEN >/dev/null 2>&1
    return $?
  fi
  # Fallback: try to open the port with bash's /dev/tcp.
  if (echo >"/dev/tcp/127.0.0.1/$port") >/dev/null 2>&1; then
    return 0
  fi
  return 1
}

check_ports() {
  local conflicts=()
  local p
  for p in "${REQUIRED_PORTS[@]}"; do
    if port_in_use "$p"; then
      conflicts+=("$p")
    fi
  done
  if [[ ${#conflicts[@]} -gt 0 ]]; then
    err "port conflict: the following TCP port(s) are already in use: ${conflicts[*]}"
    err "docssmoke needs ports ${REQUIRED_PORTS[*]} free. Stop the conflicting process(es) and retry."
    exit 2
  fi
}

# Parse host-side ports from a docker-compose.yml `ports:` stanza. Handles
# the common forms "host:container" (quoted or bare) — what every example
# uses today. Output: one host port per line. Stderr-silent on missing file.
example_host_ports() {
  local compose="$1"
  [[ -f "$compose" ]] || return 0
  # Lines look like:    - "9000:9000"  OR    - 9000:9000   OR    - "9000:80"
  # The leading "-" makes this a YAML list element under a `ports:` key.
  grep -E '^[[:space:]]*-[[:space:]]*"?[0-9]+:[0-9]+"?' "$compose" \
    | sed -E 's/^[[:space:]]*-[[:space:]]*"?([0-9]+):.*/\1/'
}

# Pre-check the ports this specific example binds. Sets RESULT/RESULT_REASON
# and returns 1 on conflict so the caller can record it without aborting the
# whole run. Skips silently if the example has no docker-compose.yml — not
# every example uses compose (e.g. retrofit examples are non-runnable).
check_example_ports() {
  local ex_dir="$1"
  local compose="${ex_dir}/docker-compose.yml"
  [[ -f "$compose" ]] || return 0

  local ports=()
  local p
  while IFS= read -r p; do
    [[ -n "$p" ]] && ports+=("$p")
  done < <(example_host_ports "$compose")
  [[ ${#ports[@]} -eq 0 ]] && return 0

  local conflicts=()
  for p in "${ports[@]}"; do
    if port_in_use "$p"; then
      conflicts+=("$p")
    fi
  done
  if [[ ${#conflicts[@]} -gt 0 ]]; then
    RESULT="FAIL"
    RESULT_REASON="port conflict on ${conflicts[*]} (example binds ${ports[*]})"
    err "  ${RESULT_REASON}"
    err "  stop the conflicting process(es) and retry"
    return 1
  fi
  return 0
}

# -----------------------------------------------------------------------------
# Example discovery
# -----------------------------------------------------------------------------

discover_examples() {
  # Emit example dirs (absolute paths), sorted, matching examples/<lang>/<NN-name>/.
  [[ -d "$EXAMPLES_ROOT" ]] || return 0

  # Two levels deep: <lang>/<NN-name>. NN must start with a digit to match the
  # documented numbered-example layout; this also keeps stray dirs (like _shared)
  # from being treated as examples.
  local lang_dir name_dir
  while IFS= read -r -d '' lang_dir; do
    [[ -d "$lang_dir" ]] || continue
    while IFS= read -r -d '' name_dir; do
      [[ -d "$name_dir" ]] || continue
      local base
      base="$(basename "$name_dir")"
      [[ "$base" =~ ^[0-9] ]] || continue
      printf '%s\0' "$name_dir"
    done < <(find "$lang_dir" -mindepth 1 -maxdepth 1 -type d -print0 | sort -z)
  done < <(find "$EXAMPLES_ROOT" -mindepth 1 -maxdepth 1 -type d -print0 | sort -z)
}

# Path relative to examples/, e.g. "python/01-hello".
rel_example() {
  local abs="$1"
  printf '%s' "${abs#"$EXAMPLES_ROOT"/}"
}

# Glob match against the example's relative path.
matches_filter() {
  local rel="$1"
  [[ -z "$FILTER" ]] && return 0
  # shellcheck disable=SC2053  # intentional glob match, not literal compare
  [[ "$rel" == $FILTER ]]
}

# -----------------------------------------------------------------------------
# Per-example execution
# -----------------------------------------------------------------------------

# Trap state for the currently running example. Set before `make run`, cleared
# after `make clean` succeeds. The outer script trap reads these to guarantee
# cleanup on SIGINT / unexpected exit.
CURRENT_EXAMPLE_DIR=""
CURRENT_STDERR_LOG=""

# shellcheck disable=SC2329  # invoked indirectly via `trap cleanup_current ...`
cleanup_current() {
  local rc=$?
  if [[ -n "$CURRENT_EXAMPLE_DIR" ]]; then
    warn "trap: tearing down $(rel_example "$CURRENT_EXAMPLE_DIR")"
    # Run clean from the example dir; ignore its exit code — we're already
    # bailing and want to avoid masking the real failure.
    (cd "$CURRENT_EXAMPLE_DIR" && make clean) >/dev/null 2>&1 || true
    CURRENT_EXAMPLE_DIR=""
  fi
  if [[ -n "$CURRENT_STDERR_LOG" && -f "$CURRENT_STDERR_LOG" ]]; then
    rm -f "$CURRENT_STDERR_LOG" || true
    CURRENT_STDERR_LOG=""
  fi
  exit "$rc"
}

trap cleanup_current EXIT INT TERM

# Poll the discovery endpoint until it returns 200 or we hit the timeout.
wait_for_health() {
  local deadline=$(( $(date +%s) + HEALTH_TIMEOUT_SECS ))
  local code
  while [[ $(date +%s) -lt $deadline ]]; do
    code="$(curl -fsS -o /dev/null -w '%{http_code}' --max-time 2 "$DISCOVERY_URL" 2>/dev/null || true)"
    if [[ "$code" == "200" ]]; then
      return 0
    fi
    sleep 1
  done
  return 1
}

# Run a single example. Echoes "PASS", "FAIL", or "SKIP" via the global RESULT;
# never exits the script directly (caller decides bail vs keep-going).
RESULT=""
RESULT_REASON=""

run_one() {
  local ex_dir="$1"
  local rel; rel="$(rel_example "$ex_dir")"
  local stderr_log
  stderr_log="$(mktemp -t "docssmoke.${rel//\//_}.XXXXXX")"
  RESULT=""
  RESULT_REASON=""

  log "${C_BOLD}── ${rel} ──${C_RESET}"

  # Explicit opt-out: an example may ship a `.docssmoke-skip` file when it is
  # not independently runnable under the run -> health -> verify model (e.g.
  # tier-02 agents that have no stack of their own and talk to the tier-01
  # MCP server). The file's first non-empty line is the human-readable reason.
  if [[ -f "${ex_dir}/.docssmoke-skip" ]]; then
    local reason
    reason="$(grep -m1 -v '^[[:space:]]*$' "${ex_dir}/.docssmoke-skip" 2>/dev/null || true)"
    RESULT="SKIP"
    RESULT_REASON="${reason:-marked .docssmoke-skip}"
    warn "skip: ${rel} — ${RESULT_REASON}"
    rm -f "$stderr_log"
    return 0
  fi

  # Skip examples that don't define a Makefile or a `verify` target at all.
  if [[ ! -f "${ex_dir}/Makefile" ]]; then
    RESULT="SKIP"
    RESULT_REASON="no Makefile"
    warn "skip: ${rel} has no Makefile"
    rm -f "$stderr_log"
    return 0
  fi
  if ! (cd "$ex_dir" && make -n verify) >/dev/null 2>&1; then
    RESULT="SKIP"
    RESULT_REASON="no \`verify\` target"
    warn "skip: ${rel} has no \`verify\` target"
    rm -f "$stderr_log"
    return 0
  fi

  # --- per-example port pre-check ---
  # Catch host-port conflicts before `make run` exits with an opaque
  # docker error. The global REQUIRED_PORTS check at startup only covers
  # the AS ports (9000/9001); examples may bind additional ports such as
  # 8080 (a sample MCP server). RESULT/RESULT_REASON are set by the helper.
  if ! check_example_ports "$ex_dir"; then
    rm -f "$stderr_log"
    return 1
  fi

  # Isolate this example's compose project. Docker derives the project name
  # from the directory basename, so go/04, python/04 and typescript/04 (all
  # `04-broker-upstream/`) would otherwise share images/volumes/networks named
  # `04-broker-upstream-*` and stomp on each other — e.g. one language's `agent`
  # image getting reused for another's `docker compose run agent`. A per-rel
  # project name keeps each example's compose state private. Exported so the
  # child `make` (run/verify/clean) and the trap-driven cleanup all agree.
  export COMPOSE_PROJECT_NAME="docssmoke_${rel//[^a-zA-Z0-9]/_}"

  # Arm the trap.
  CURRENT_EXAMPLE_DIR="$ex_dir"
  CURRENT_STDERR_LOG="$stderr_log"

  # --- make run ---
  log "  make run"
  if ! (cd "$ex_dir" && make run) >>"$stderr_log" 2>&1; then
    RESULT="FAIL"
    RESULT_REASON="make run failed"
    err "  make run failed (last 20 lines of output):"
    tail -n 20 "$stderr_log" >&2 || true
    (cd "$ex_dir" && make clean) >/dev/null 2>&1 || true
    CURRENT_EXAMPLE_DIR=""
    CURRENT_STDERR_LOG=""
    rm -f "$stderr_log"
    return 1
  fi

  # --- wait for health ---
  log "  waiting for ${DISCOVERY_URL} (max ${HEALTH_TIMEOUT_SECS}s)"
  if ! wait_for_health; then
    RESULT="FAIL"
    RESULT_REASON="authserver discovery never returned 200 within ${HEALTH_TIMEOUT_SECS}s"
    err "  ${RESULT_REASON}"
    (cd "$ex_dir" && make clean) >/dev/null 2>&1 || true
    CURRENT_EXAMPLE_DIR=""
    CURRENT_STDERR_LOG=""
    rm -f "$stderr_log"
    return 1
  fi

  # --- make verify ---
  log "  make verify"
  if ! (cd "$ex_dir" && make verify) >>"$stderr_log" 2>&1; then
    RESULT="FAIL"
    RESULT_REASON="make verify failed"
    err "  make verify failed (last 30 lines of output):"
    tail -n 30 "$stderr_log" >&2 || true
    (cd "$ex_dir" && make clean) >/dev/null 2>&1 || true
    CURRENT_EXAMPLE_DIR=""
    CURRENT_STDERR_LOG=""
    rm -f "$stderr_log"
    return 1
  fi

  # --- make clean ---
  log "  make clean"
  (cd "$ex_dir" && make clean) >/dev/null 2>&1 || warn "  make clean returned non-zero (continuing)"
  CURRENT_EXAMPLE_DIR=""
  CURRENT_STDERR_LOG=""
  rm -f "$stderr_log"

  RESULT="PASS"
  ok "  PASS"
  return 0
}

# -----------------------------------------------------------------------------
# Main
# -----------------------------------------------------------------------------

log "image: ${SMOKE_AUTHSERVER_IMAGE}"
log "examples root: ${EXAMPLES_ROOT}"
[[ -n "$FILTER" ]] && log "filter: ${FILTER}"

check_ports

# Collect examples (NUL-delimited so paths with spaces survive).
EXAMPLES=()
while IFS= read -r -d '' d; do
  EXAMPLES+=("$d")
done < <(discover_examples)

if [[ ${#EXAMPLES[@]} -eq 0 ]]; then
  warn "no examples found under ${EXAMPLES_ROOT} (looking for <lang>/<NN-name>/)"
  exit 0
fi

# Filter & run.
declare -a PASS_LIST=() FAIL_LIST=() SKIP_LIST=()
RAN=0

for ex_dir in "${EXAMPLES[@]}"; do
  rel="$(rel_example "$ex_dir")"
  if ! matches_filter "$rel"; then
    continue
  fi
  RAN=$((RAN + 1))

  # run_one returns non-zero on FAIL; we don't want `set -e` to abort the loop.
  set +e
  run_one "$ex_dir"
  rc=$?
  set -e

  case "$RESULT" in
    PASS) PASS_LIST+=("$rel") ;;
    FAIL) FAIL_LIST+=("$rel — ${RESULT_REASON}") ;;
    SKIP) SKIP_LIST+=("$rel — ${RESULT_REASON}") ;;
  esac

  if [[ $rc -ne 0 && $BAIL -eq 1 ]]; then
    warn "bailing on first failure (--bail)"
    break
  fi
done

# -----------------------------------------------------------------------------
# Report
# -----------------------------------------------------------------------------

echo
log "${C_BOLD}── summary ──${C_RESET}"

if [[ $RAN -eq 0 ]]; then
  warn "0 examples matched filter '${FILTER}'"
  exit 0
fi

if [[ ${#PASS_LIST[@]} -gt 0 ]]; then
  ok "PASS (${#PASS_LIST[@]}):"
  for n in "${PASS_LIST[@]}"; do printf '  %s%s%s %s\n' "$C_GREEN" "+" "$C_RESET" "$n"; done
fi
if [[ ${#SKIP_LIST[@]} -gt 0 ]]; then
  warn "SKIP (${#SKIP_LIST[@]}):"
  for n in "${SKIP_LIST[@]}"; do printf '  %s%s%s %s\n' "$C_YELLOW" "~" "$C_RESET" "$n"; done
fi
if [[ ${#FAIL_LIST[@]} -gt 0 ]]; then
  err "FAIL (${#FAIL_LIST[@]}):"
  for n in "${FAIL_LIST[@]}"; do printf '  %s%s%s %s\n' "$C_RED" "x" "$C_RESET" "$n"; done >&2
  exit 1
fi

ok "all green (${#PASS_LIST[@]} passed, ${#SKIP_LIST[@]} skipped)"
exit 0
