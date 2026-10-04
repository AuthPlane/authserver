*Context: this is part of [Contribute](README.md). Start with the primer if you haven't.*

# Running tests

authserver's test surface is layered. Each layer answers a different
question and runs at a different speed; together they make up the
"ready to push" gate.

## The gate: `make ci-local`

The single command you must run before `git push`. From the
[`Makefile`](../../Makefile):

```
ci-local: build lint check-imports check-drift check-oss test-unit test-integration coverage-check vulncheck
```

It runs, in order:

| Step | Command | Catches |
|---|---|---|
| Build | `make build` | The binary compiles with `CGO_ENABLED=0` |
| Lint | `make lint` (`golangci-lint v2.11+`) | Style + static-analysis violations |
| Import boundaries | `make check-imports` | Hexagonal layer violations + Gate 0 + Gate 1 + Gate 2 |
| Drift gates | `make check-drift` | A metric, audit action, env var or quoted log message that exists in code but not in its consumer (dashboard, catalog, reference, runbook), or the reverse — see `scripts/{metricslint,auditlint,envlint,runbooklint}` |
| OSS hygiene | `make check-oss` | Internal Linear tickets / planning paths / workspace URLs in public-scope files |
| Unit | `make test-unit` | Domain logic, crypto, config, brokerproto registry |
| Integration | `make test-integration` | Services, adapters (SQLite in-process) and HTTP handlers — about 80% of the test functions |
| Coverage floor | `make coverage-check` | The merged unit + integration profile below `COVERAGE_FLOOR` (59%, the merged total measured when the gate was added) |
| Vulnerabilities | `make vulncheck` (`govulncheck`) | Third-party CVEs in all three Go modules — the root, `e2e/`, `compliance/` (stdlib-only findings warn) |

If `ci-local` is red, do **not** push. If it goes green but you've
touched the postgres adapter, schema or migrations, additionally run
`make test-integration-postgres`; for an upstream-provider adapter or a
user-facing flow, `make test-e2e` as well (see the table below).

## Per-layer targets

### `make test-unit`

Pure unit tests with no Docker, no filesystem, no network. Scope:
`internal/domain/`, `internal/crypto/`, `internal/config/`,
`internal/brokerproto/`. Sub-second feedback; run on every save.

### `make test-integration`

Runs `go test -tags=integration` against `internal/adapters/...`,
`internal/services/...`, `api/...`. Brings up SQLite in-process — no
external services required. Tests that touch the storage layer use the
shared adapter suite under `testdata/`.

The Makefile auto-detects the packages so you don't have to enumerate
them. `test-unit` and `test-integration` each write a coverage profile
(`coverage-unit.out`, `coverage-integration.out`); `make coverage-check`
merges them, prints the three totals and fails when the merged total is
below `COVERAGE_FLOOR` (59%, the merged total measured when the gate was added). The floor is a ratchet: raise it when
coverage rises; never lower it to make a red run green. `go tool cover
-html=coverage-merged.out` shows what the last run missed.

### `make test-integration-postgres`

Boots a PostgreSQL container via
`deploy/docker-compose.test-postgres.yml` on `AUTHSERVER_TEST_PG_PORT`
(default `5433`), runs `go test -tags=integration_postgres` against
`internal/adapters/postgres/...`, then tears the container down.
Required before merging any postgres-adapter change.

### `make test-race`

`go test -race -short ./...`. Catches data races under concurrency. Run
before shipping anything that touches shared state — caches, registries,
session storage. `-short` skips the two wall-clock timing assertions
(bcrypt cost uniformity), which are noise under race instrumentation;
both still run unskipped under `test-unit` and `test-integration`.

### `make test-compliance`

Runs the OAuth/MCP compliance suite under [`compliance/`](../../compliance/)
(its own Go module): the registration tests first, then the `e2e`-tagged
journeys with a 15-minute timeout. `make compliance-report` regenerates
`compliance/report/latest.{json,md}` from it; `make compliance-gate` is the
CI form that fails on any regression against that report.

### `make test-e2e`

Build-tagged `e2e`. The scenarios under
[`e2e/scenarios/`](../../e2e/scenarios/) boot the binary via
[`e2e/harness.go`](../../e2e/harness.go) and drive it through HTTP.
The hard rule (Gate 0): e2e tests **must not import `internal/...`** —
the harness is the only seam. `make check-imports` enforces it.

### `make docs-smoke`

Walks `examples/<lang>/<NN-name>/` and runs each example's
`make run` → wait for health → `make verify` → `make clean` cycle via
[`tools/docssmoke/run.sh`](../../tools/docssmoke/run.sh). This is the
contract test that documentation examples actually work against the
current binary.

Today this passes for the TypeScript and Python examples; the Go
examples are still wiring up `make verify`.

### `make docs-check`

Runs `make docs-gen` then `git diff --exit-code -- docs/reference/`.
If your change altered a CLI flag, env var, config key, or HTTP DTO
without regenerating the reference, this fails. Always regenerate via
`make docs-gen` — never hand-edit `docs/reference/{cli,http-api,env-vars,configuration}.md`.

## Picking the right loop

| Working on… | Tight loop | Pre-push |
|---|---|---|
| A domain entity | `go test ./internal/domain/<pkg>/... -count=1` | `make ci-local` |
| A service | `go test ./internal/services/... -tags=integration -run TestYour -count=1` | `make ci-local` |
| An adapter | `go test ./internal/adapters/<driver>/... -tags=integration -count=1` | `make ci-local` (+ `test-integration-postgres` for the postgres adapter) |
| An HTTP handler | `go test ./api/<area>/... -tags=integration -count=1` | `make ci-local` |
| A CLI flag | `go test ./cmd/authserver/... -count=1` | `make ci-local && make docs-check` |
| A config key | `go test ./internal/config/... -count=1` | `make ci-local && make docs-check` |
| An upstream-provider adapter | `go test ./internal/adapters/brokerproto/<name>/... -count=1` | `make ci-local && make test-e2e` |
| A user-facing flow | `cd e2e && go test ./scenarios/... -tags=e2e -run YourFlow -count=1` | `make ci-local && make test-e2e` |
| Documentation examples | `tools/docssmoke/run.sh <example>` | `make docs-smoke` |

## Test data and shared suites

[`testdata/`](../../testdata/) holds shared adapter test suites — the
same assertions run against every storage backend so the SQLite and
PostgreSQL adapters can't diverge in observable behaviour. If you add
a new method to an output port, extend the matching shared suite, not
the per-adapter test file.

## Prerequisites checklist

If `make ci-local` fails before it runs any test, you're probably
missing one of:

- Go 1.26.6+ (matches `go.mod`; `go version` should report ≥ 1.26.6)
- `golangci-lint v2.11+` (`brew install golangci-lint` or
  `curl -sSfL ...`)
- `govulncheck` (`make vulncheck` installs it if missing)
- Docker (for `test-integration-postgres`, `docs-smoke` examples that
  boot a sidecar, and `docker-build`)
- Node.js 22+ (only if you're touching `web/admin/` — the rest of the
  build is Go-only)
