#!/usr/bin/env bash
# examples/run-all-smokes.sh — lightweight example sanity check for CI.
#
# Goal: catch the most common breakage cheaply, without a running compose
# stack:
#   1. every Go example module compiles (`go vet ./...` — type-checks
#      without emitting binaries, so it leaves no build artifacts), and
#   2. every shipped shell script parses (`bash -n`).
#
# This complements the heavier `make docs-smoke` (tools/docssmoke/run.sh),
# which boots each example's compose stack and drives its primary flow.
# docs-smoke skips examples that aren't independently runnable (a
# `.docssmoke-skip` marker) and the tier-02 agents; this script still
# compile-checks those, so a code change that breaks a skipped example's
# import surface is caught here.
#
# Usage:  bash examples/run-all-smokes.sh
# Exit 0 if everything builds + parses; non-zero otherwise.

set -euo pipefail

cd "$(git rev-parse --show-toplevel 2>/dev/null || pwd)"

failures=0

# --- 1. compile every Go example module -------------------------------------
# Each Go example is its own module (own go.mod) so it can depend on the
# published SDK without dragging in the server. Discover them by go.mod.
GO_EXAMPLES=()
while IFS= read -r modfile; do
  GO_EXAMPLES+=("$(dirname "${modfile}")")
done < <(find examples -mindepth 2 -maxdepth 4 -name 'go.mod' -type f | sort)

if [ "${#GO_EXAMPLES[@]}" -eq 0 ]; then
  echo "run-all-smokes: no Go example modules found"
else
  for dir in "${GO_EXAMPLES[@]}"; do
    echo "==> go vet: ${dir}"
    if (cd "${dir}" && go vet ./... 2>&1); then
      echo "    ok"
    else
      echo "    FAIL — go vet failed in ${dir}"
      failures=$((failures + 1))
    fi
  done
fi

# --- 2. syntax-check every shipped example shell script ---------------------
# `bash -n` catches the common slip (a syntax error in a verify.sh /
# setup script) without needing to execute it.
SCRIPTS=()
while IFS= read -r script; do
  SCRIPTS+=("${script}")
done < <(find examples -name '*.sh' -type f | sort)

for s in "${SCRIPTS[@]}"; do
  echo "==> bash -n: ${s}"
  if bash -n "${s}"; then
    echo "    ok"
  else
    echo "    FAIL — syntax error in ${s}"
    failures=$((failures + 1))
  fi
done

if [ "${failures}" -gt 0 ]; then
  echo ""
  echo "run-all-smokes: ${failures} check(s) failed"
  exit 1
fi

echo ""
echo "run-all-smokes: ${#GO_EXAMPLES[@]} Go module(s) built, ${#SCRIPTS[@]} script(s) parsed — all clean"
