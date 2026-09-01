# Contribute

**For:** Developers extending authserver — adding upstream providers, new grant types, transports, adapters; fixing bugs; shipping releases.
**Prereqs:** Go 1.26.6+ (matches `go.mod`), Node.js 22+ (admin UI build only), Docker, `golangci-lint v2.11+`. See [running-tests.md](running-tests.md) for the canonical matrix.
**Shared setup:** `make ci-local` is the floor for "ready to push" — runs build, lint, import-boundary check, OSS-leak check, unit tests, govulncheck.

## Reading order

1. [Repo tour](repo-tour.md) — what lives where.
2. [Hexagonal layers](hexagonal-layers.md) — where to put your code.
3. [Coding conventions](coding-conventions.md) — names, errors, factory patterns.
4. [Add an upstream provider](add-an-upstream-provider.md) — the most common extension.
5. [Add a grant type](add-a-grant-type.md) — the next most common extension.
6. [Running tests](running-tests.md) — unit, integration, e2e, docs-smoke.
7. [Release process](release-process.md) — tagging, goreleaser, Helm bump.

## Conventions used in this section

- Code paths cite `package/file.go:LINE` references against current `develop`.
- Every recipe ends with a "Verify" checklist mirroring `make ci-local` plus the recipe-specific assertions.
- The repo's full agent-facing protocol lives in [`AGENTS.md`](../../AGENTS.md). This section is the human-readable summary for contributors.
