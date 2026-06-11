#!/usr/bin/env bash
# Manages a long-running background process (an MCP server) for the
# native-flow examples. Stores stdout/stderr in `.run/<name>.log` and the
# PID in `.run/<name>.pid` so the parent Makefile can stop/inspect it.
#
# Usage:
#   examples/_shared/native-proc.sh start <name> <command...>
#       Launches `command...` in the background, writing logs and PID.
#       Any env vars set in the caller's environment are inherited.
#
#   examples/_shared/native-proc.sh stop <name>
#       Sends SIGTERM to the recorded PID (and its process group, to
#       catch tsx/node and similar wrappers that spawn children).
#
#   examples/_shared/native-proc.sh status <name>
#       Prints "running pid=N" or "not running".
#
#   examples/_shared/native-proc.sh logs <name>
#       Tails the last 40 lines of the captured log.
#
# All operations are idempotent. State lives in `./.run/`.

set -e

mkdir -p .run

cmd="${1:-}"; name="${2:-}"; shift 2 || true
pidf=".run/$name.pid"
logf=".run/$name.log"

case "$cmd" in
  start)
    [[ -z "$name" || $# -eq 0 ]] && { echo "usage: $0 start <name> <command...>" >&2; exit 2; }
    # `exec` inside the subshell replaces the subshell with the target
    # process so the recorded PID is the target itself (not a wrapper
    # sh). On the cleanup side we still SIGTERM the whole process group
    # to catch grandchild node workers (tsx) that exec spawns.
    ( exec "$@" ) >"$logf" 2>&1 &
    echo $! > "$pidf"
    echo "  $name:       pid=$(cat "$pidf") log=$logf"
    ;;
  stop)
    [[ -z "$name" ]] && { echo "usage: $0 stop <name>" >&2; exit 2; }
    if [[ -f "$pidf" ]]; then
      pid=$(cat "$pidf")
      # Try SIGTERM on the process group first, then the bare PID as a
      # fallback. Ignore failures: the process may already be gone.
      kill -TERM -"$pid" 2>/dev/null || kill -TERM "$pid" 2>/dev/null || true
      sleep 0.2
      kill -KILL -"$pid" 2>/dev/null || kill -KILL "$pid" 2>/dev/null || true
      rm -f "$pidf"
    fi
    ;;
  status)
    [[ -z "$name" ]] && { echo "usage: $0 status <name>" >&2; exit 2; }
    if [[ -f "$pidf" ]] && kill -0 "$(cat "$pidf")" 2>/dev/null; then
      echo "$name:       running pid=$(cat "$pidf")"
    else
      echo "$name:       not running"
    fi
    ;;
  logs)
    [[ -z "$name" ]] && { echo "usage: $0 logs <name>" >&2; exit 2; }
    if [[ -f "$logf" ]]; then
      tail -40 "$logf"
    else
      echo "($name: no log yet)"
    fi
    ;;
  *)
    echo "usage: $0 {start|stop|status|logs} <name> [command...]" >&2
    exit 2
    ;;
esac
