# Contributing to Authplane

> [!IMPORTANT]
> **Authplane is open source (AGPL-3.0), but it is not open to external code
> contributions at this time.** We are **not accepting pull requests** from
> outside the AuthPlane organization. Please read the policy below before
> opening one — external PRs are closed automatically.

## Why we don't accept contributions (yet)

Authplane is published under the [GNU AGPL-3.0](LICENSE). To keep our options open
for the project's long-term licensing — including the possibility of offering
Authplane under a commercial or otherwise alternative license — **AuthPlane, Inc.
needs to retain clear, unambiguous copyright ownership of the entire codebase.**

Until we have finalized a Contributor License Agreement (CLA) strategy, we cannot
accept third-party code, because merging outside contributions would mix external
copyright into the project and remove our ability to relicense it later. This is a
deliberate — and common — stance for AGPL- and BSL-licensed projects.

This is **not** a judgment on the quality of any contribution; it is purely about
copyright provenance. We may open up to community contributions once a contributor
agreement is in place.

## What you *can* do

Authplane is genuinely open source. The AGPL-3.0 license guarantees your right to:

- **Use** Authplane for any purpose, including in production and commercially.
- **Study and modify** the source code.
- **Self-host** and run your own modified builds.
- **Redistribute** original or modified versions under the same AGPL-3.0 terms.

You are also very welcome to:

- 🐛 **Report bugs** — open an [issue](https://github.com/authplane/authserver/issues).
- 🔒 **Report security vulnerabilities** — follow [SECURITY.md](SECURITY.md). Please
  do **not** disclose security issues in public issues or discussions.
- 💬 **Ask questions or share feedback** — start a
  [discussion](https://github.com/authplane/authserver/discussions).
- 🍴 **Fork it** — and build on it under the AGPL-3.0 license.

## Building from source

You don't need to contribute to build Authplane — the AGPL guarantees your right to
build and modify it. To build and test locally:

### Prerequisites

- Go 1.26.6+
- Docker (for PostgreSQL / Vault integration tests)

### Build & test

```bash
make build              # Build binary
make test               # Unit + integration tests (SQLite)
make test-race          # Race detector
make check-imports      # Architecture import enforcement
make lint               # golangci-lint
```

### Run locally

```bash
make run                # SQLite dev mode
make run-postgres       # PostgreSQL (docker-compose)
```

For the repository map, architecture, and internal conventions, see
[AGENTS.md](AGENTS.md).

## Questions?

Open a [discussion](https://github.com/authplane/authserver/discussions) — we're
happy to help.
