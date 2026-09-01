# Retrofit — Add Authplane to an existing modelcontextprotocol/go-sdk server (Go)

You already have an MCP server. It works. It has tools. It has no auth.
You want to add auth without rewriting your code.

This example shows exactly what that looks like — a real
`modelcontextprotocol/go-sdk` MCP server in two states, **before** and
**after** Authplane is wired in. They sit side-by-side under `before/`
and `after/`, and the smoke-test brings up both at the same time to prove:

- **before** accepts a `tools/call` with no token → returns the tool result.
- **after** rejects the same call with 401 → then accepts it once you mint
  a bearer token. Same three tools either way.

## What changes — the actual diff

The Authplane integration is a single 5-line block between
`// authplane:begin` and `// authplane:end` markers in `after/main.go`.
A complete in-place retrofit also adds one import, one `context.Background()`,
two mount lines (PRM document handler + `AuthMiddleware` wrap), and a
six-line `must[T]` generic helper at the bottom of the file (or your own
explicit `if err != nil { ... }`). Realistic full diff: ~12–14 added lines.

```diff
  import (
      "context"
+     "os"
      ...
      "github.com/modelcontextprotocol/go-sdk/mcp"
+     "github.com/authplane/go-sdk/mcp/pkg/authplanemcp"
  )

  func main() {
+     ctx := context.Background()
      server := mcp.NewServer(&mcp.Implementation{Name: "retrofit-demo", Version: "1.0.0"}, nil)
      handler := mcp.NewStreamableHTTPHandler(...)
-     http.Handle("/mcp", handler)
+     // authplane:begin
+     adapter := must(authplanemcp.NewAdapter(ctx, authplanemcp.Options{
+         Issuer: os.Getenv("AUTHPLANE_ISSUER"), Resource: os.Getenv("AUTHPLANE_RESOURCE"),
+         Scopes: []string{"mcp:tools"}, DevMode: true,
+     }))
+     defer adapter.Close()
+     // authplane:end
+     http.Handle(adapter.WellKnownPRMPath(), adapter.ProtectedResourceMetadataHandler())
+     http.Handle("/mcp", adapter.AuthMiddleware(handler))
+
+ // must panics on a non-nil error; replace with explicit `if err != nil`
+ // handling in production code.
+ func must[T any](v T, err error) T { if err != nil { log.Fatal(err) }; return v }
```

`make diff` prints the same diff inline. The `// authplane:begin/end`
markers are what `tools/loccount` reads to enforce the "five lines" claim
in CI.

The `go.mod` change is one new import. Everything else — the tools, the
transport handler, `http.ListenAndServe` — stays put.

## Prereqs

The Makefile's `check-prereqs` target enforces these on every `make run`; it
fails loud with an install hint if any are missing.

| Tool | Version | Install (macOS / Linux) |
|---|---|---|
| **Go** | 1.25+ | `brew install go` / [go.dev/dl](https://go.dev/dl/) |
| **Docker** | 24+ (daemon running) | Docker Desktop / Rancher Desktop / [docker.com](https://www.docker.com/) |
| **curl** | any | preinstalled |
| **jq** | any | `brew install jq` / `apt install jq` |

The AS container needs ports **9000** (public) and **9001** (admin) free; the
two MCP servers bind **8080** (`before`) and **8090** (`after`). Conflicts
are the most common startup failure — see Troubleshooting below.

## Run it

```bash
make run        # builds the two demo binaries, starts the AS in a container, launches both natively
make verify     # proves: before accepts anything, after enforces auth
make diff       # shows the exact code change between before/ and after/
make logs       # tails the last 40 lines of each component's log
make status     # one-line health of the AS container + both Go processes
make clean      # stops processes + AS container; KEEPS .env
make distclean  # full reset including .env
```

The basic flow doesn't build any Dockerfiles. The AS is pulled as a published
image; the two MCP servers are plain Go binaries built with `go build` and
exec'd on the host. First run downloads the AS image (~30 MB) and the
modelcontextprotocol/go-sdk modules; subsequent runs start in seconds.
`make run` auto-creates `.env` from `.env.example` on first run.

If you also want to see what the example looks like when the MCP servers are
themselves containerised, run `make docker-run` / `make docker-clean`. That
path uses `docker-compose.yml` and the per-server Dockerfiles — same code,
same `make verify`, just longer first build (~1 min).

| | |
|---|---|
| **Time to run** | Under a minute warm-cache (`go build` of two small binaries + AS image pull) |
| **MCP framework** | `github.com/modelcontextprotocol/go-sdk v1.4.1` |
| **SDK** | `github.com/authplane/go-sdk/mcp v0.2.0` (in `after/` only) |

## Troubleshooting

The most common failures and what to do about them.

**`bind: address already in use` on `make run`**
Another Authplane example (or a stale container from this one) is sitting on
:9000, :9001, :8080, or :8090. Reset and retry:
```bash
make clean
docker ps -aq --filter name=authplane | xargs -r docker rm -f
make run
```

**`make verify` hangs at "waiting for ..."**
Something didn't come up. Inspect each component:
```bash
make status   # is everything actually running?
make logs     # last 40 lines from AS + before + after
```
The AS logs are the usual suspect — a typo'd `AUTHPLANE_SERVER_ISSUER`, a
missing required env var, or a session-secret length error.

**`make verify` Phase B.4 returns `invalid_token`**
You're hitting Authplane's #1 misconfiguration: the JWT audience doesn't
match. The three places the Resource URI appears must agree byte-for-byte
(scheme, host, port, path) — see "Adapting this to your project" below.
The default flow gets this right; you'll only hit it if you changed
`AFTER_PORT` or edited the Resource URI by hand.

**`ERROR: jq not found` from `make verify`**
The verify script depends on `jq` to parse the AS's JSON responses. Install
it with `brew install jq` (macOS) or `apt install jq` (Debian/Ubuntu).

**`go: cannot find module providing package github.com/authplane/go-sdk/mcp`**
The SDK is published to the public Go module proxy as
`github.com/authplane/go-sdk` v0.2.0. If you're behind a corporate proxy,
configure `GOPROXY` to allow it (or set `GOPRIVATE` if you mirror SDKs
internally).

**`missing go.sum entry for module providing package github.com/authplane/go-sdk/core/...`**
`go get github.com/authplane/go-sdk/mcp@v0.2.0` adds the `mcp` adapter but
*not* its transitive dependency `go-sdk/core`, so the very next `go build`
fails on the missing checksum. Run **`go mod tidy`** (or
`go get github.com/authplane/go-sdk/mcp/pkg/authplanemcp@v0.2.0`) to record
the `core` entries in `go.sum`. This example's committed `go.mod`/`go.sum`
already include them — you only hit this when wiring the adapter into your
own module.

**`make distclean` vs. `make clean`**
`make clean` stops processes and the AS container but keeps `.env` so your
edits survive iteration. `make distclean` is the full reset (clean + `.env`
removal) — use before sharing the directory or switching examples.

## What `make verify` proves

```text
Phase A — before  (no bearer)         → HTTP 200, tools/call add(17,25)=42
Phase B.1 — after (no bearer)         → HTTP 401   ← auth enforced
Phase B.2 — register Resource + Client at the AS
Phase B.3 — mint a client_credentials token
Phase B.4 — after (with bearer)       → HTTP 200, tools/call add(17,25)=42
```

The smoke-test runs the **same MCP request** against both servers. The
only thing that changes is the 5-line auth block in `after/main.go`.

## When to use this vs. tier-01

| Your situation | Start at |
|---|---|
| You have an existing go-sdk MCP server, you want the minimal diff to add auth | **You're already there.** Read `after/main.go` next to `before/main.go`. |
| You're writing a new MCP server from scratch | [`../01-mcp-server-basic/`](../01-mcp-server-basic/) — same five lines, fewer files. |
| You also need DPoP-bound tokens and per-tool scope enforcement | [`../03-mcp-server-dpop-scopes/`](../03-mcp-server-dpop-scopes/) |

## Adapting this to your project

> To run the AS against *your own* already-running server (not this
> example's `after/`) and provision + mint + call entirely by hand with
> `curl`, follow [Run the AS standalone and point it at your own MCP server](../../../docs/guides/integrate/standalone-as-by-hand.md).

The same two constraints from tier-01 apply (verbatim) when you copy
this into your own codebase:

**1. The two issuer URLs must share the same hostname.** The AS reads
`AUTHPLANE_SERVER_ISSUER`; the SDK inside your MCP server reads
`AUTHPLANE_ISSUER`. The SDK fails fast if `metadata.issuer != config.issuer`.

> **This is a decision, not a default — pick by topology and set both vars to the same host:**
> - **MCP server on the host, another machine, or public** → `http://localhost:9000` (or your real hostname) on both.
> - **MCP server in the same Docker network as the AS** → `http://authserver:9000` on both.
>
> Get it wrong and every call 401s with an opaque `invalid_token` — the token is valid, but the SDK discovered metadata at one host while the JWT's `iss` says another.

| Topology | `AUTHPLANE_SERVER_ISSUER` | `AUTHPLANE_ISSUER` |
|---|---|---|
| **AS in a container, MCP server on the host** (`make run` default, the common retrofit path) | `http://localhost:9000` | `http://localhost:9000` |
| Same docker network (`make docker-run`) | `http://authserver:9000` | `http://authserver:9000` |

The `.env.example` ships with the host-side defaults. Switch both URLs to `http://authserver:9000` before running `make docker-run`.

**2. The Resource URI is a join key across three places.** It's the JWT
audience byte-for-byte. If you change any of scheme, host, port, or path,
all three of these must agree:

| # | Where it appears |
|---|------------------|
| 1 | `Resource:` field on `authplanemcp.Options` (or the `AUTHPLANE_RESOURCE` env it reads) |
| 2 | `uri` field on `POST /admin/resources` when registering the Resource at the AS |
| 3 | `resource=...` form param on `POST /oauth/token` when minting a bearer |

Mismatches produce an opaque `invalid_token` on every call — the JWT `aud` won't match what the SDK expects. Most retrofit problems are this rule.

## Before production

The `after/` server is wired for local development. Before deploying:

| Setting | Dev value (here) | Production value | Why |
|---|---|---|---|
| `DevMode: true` in `authplanemcp.Options{...}` | `true` | **`false`** (or remove — it's the default) | Relaxes the SDK's SSRF guard so it accepts `http://`, `localhost`, and private-network issuers. Leaving it on in production weakens defense-in-depth against SSRF. |
| `AUTHPLANE_ISSUER` | `http://authserver:9000` | `https://auth.example.com` | Production issuers MUST be `https://`. The AS itself refuses to start with a non-localhost issuer unless cookies are also `Secure`. |
| `AUTHPLANE_SESSION_SECURE` | `true` | `true` | Required by the AS's startup validation whenever `server.issuer` is non-localhost. |
| `AUTHPLANE_ADMIN_API_KEY` | `dev-admin-key-change-me` | `openssl rand -hex 32` | Bearer for the entire admin surface. Treat like a root password. |
| Storage | SQLite in a Docker volume | PostgreSQL (`AUTHPLANE_STORAGE_DRIVER=postgres`) | SQLite is single-instance; PostgreSQL is required for HA. |
| Signing keys | Auto-generated in `/data/keys` | HashiCorp Vault Transit | See [`docs/guides/deploy/hashicorp-vault-transit.md`](../../../docs/guides/deploy/hashicorp-vault-transit.md). |
| Distroless base image | `gcr.io/distroless/static-debian12:nonroot` (no tzdata) | Embed tzdata via `import _ "time/tzdata"` or switch base to `gcr.io/distroless/base-debian12:nonroot` | The static distroless variant omits `/usr/share/zoneinfo`; `time.LoadLocation("America/New_York")` silently falls back to UTC. |
| `must[T]` helper | Five-line generic at the bottom of `after/main.go`, `log.Fatal` on error | Explicit `if err != nil { ... }` with retry, structured log, and graceful shutdown | The helper exists to keep the auth-setup block focused; it isn't production error handling. |

## What this example deliberately does not cover

- **Per-tool scope enforcement.** All three tools accept the same
  `mcp:tools` scope. For different scopes per tool, see
  [`../03-mcp-server-dpop-scopes/`](../03-mcp-server-dpop-scopes/).
- **DPoP-bound tokens.** Bearer-only here. See tier-03 for proof-of-
  possession.
- **Calling another resource from inside a tool.** See
  [`../02-agent-basic/`](../02-agent-basic/).
- **Fronting an upstream provider (GitHub, Slack, ...).** See
  [`../04-broker-upstream/`](../04-broker-upstream/).

## Use a locally-built authserver image

The default `make run` does `docker run authplane/authserver:latest`.
To run the AS from your own checkout instead, build the image once and
override the tag:

```bash
# from the repo root
docker build -t authplane/authserver:dev .
# back in this directory
AS_IMAGE=authplane/authserver:dev make run
```

For the docker-compose flow (`make docker-run`), edit `docker-compose.yml`
and replace the `image:` line under the `authserver:` service with the
`build:` block from
[`../../_shared/docker-compose.authserver.yml`](../../_shared/docker-compose.authserver.yml).
