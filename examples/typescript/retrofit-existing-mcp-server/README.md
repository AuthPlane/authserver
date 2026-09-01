# Retrofit — Add Authplane to an existing Express + MCP-SDK server (TypeScript)

You already have an MCP server. It works. It has tools. It has no auth.
You want to add auth without rewriting your code.

This example shows exactly what that looks like — a real Express +
`@modelcontextprotocol/sdk` server in two states, **before** and **after**
Authplane is wired in. They sit side-by-side under `before/` and
`after/`, and the smoke-test brings up both at the same time to prove:

- **before** accepts a `tools/call` with no token → returns the tool result.
- **after** rejects the same call with 401 → then accepts it once you mint
  a bearer token. Same three tools either way.

## What changes — the actual diff

The auth code is in a single 5-line block, between `// authplane:begin`
and `// authplane:end` markers in `after/server.ts`, plus two single-line
wirings (PRM document handler, bearer middleware on `/mcp`):

```diff
  import crypto from "node:crypto";
  import express from "express";
  import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
  import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
  import { z } from "zod";

+ import { authplaneMcpAuth } from "@authplane/mcp";
+ const auth = await authplaneMcpAuth({
+   issuer: process.env.AUTHPLANE_ISSUER!,
+   resource: process.env.AUTHPLANE_RESOURCE!,
+   scopes: ["mcp:tools"], devMode: true,
+ });

  const app = express();
  app.use(express.json());
+ app.get(auth.protectedResourceMetadataPath, auth.protectedResourceMetadataHandler);

- app.all("/mcp", async (req, res) => {
+ app.all("/mcp", auth.bearerAuth, async (req, res) => {
```

`make diff` prints the same diff inline. The `// authplane:begin/end`
markers are what `tools/loccount` reads to enforce the "five lines" claim
in CI.

The `package.json` change is two new dependencies (`@authplane/mcp` and
`@authplane/sdk`). Everything else — the tools, the transport, the
Express middleware chain — stays put.

## Prereqs

The Makefile's `check-prereqs` target enforces these on every `make run`; it
fails loud with an install hint if any are missing.

| Tool | Version | Install (macOS / Linux) |
|---|---|---|
| **Node.js** | 22+ | `brew install node@22` / [nodejs.org](https://nodejs.org/) / `nvm install 22 && nvm use 22` |
| **Docker** | 24+ (daemon running) | Docker Desktop / Rancher Desktop / [docker.com](https://www.docker.com/) |
| **curl** | any | preinstalled |
| **jq** | any | `brew install jq` / `apt install jq` |

`tsx` is invoked directly from each project's `node_modules/.bin/` to avoid
the `npx` wrapper's process-orphaning surprise — `make clean` reliably
terminates the Node server even though it's a child of `tsx`.

The AS container needs ports **9000** (public) and **9001** (admin) free; the
two MCP servers bind **8080** (`before`) and **8090** (`after`). Conflicts
are the most common startup failure — see Troubleshooting below.

## Run it

```bash
make run        # npm-installs (first run only), starts the AS in a container, launches both servers natively
make verify     # proves: before accepts anything, after enforces auth
make diff       # shows the exact code change between before/ and after/
make logs       # tails the last 40 lines of each component's log
make status     # one-line health of the AS container + both Node processes
make clean      # stops processes + AS container; KEEPS .env (and node_modules)
make distclean  # full reset including .env
```

The basic flow doesn't build any Dockerfiles. The AS is pulled as a
published image; the two MCP servers are plain Node processes run via
`tsx`. First run downloads the AS image (~30 MB) and `npm install`s both
projects' deps; subsequent runs start in seconds. `make run` auto-creates
`.env` from `.env.example` on first run.

If you also want to see what the example looks like when the MCP servers
are themselves containerised, run `make docker-run` / `make docker-clean`.
That path uses `docker-compose.yml` and the per-server Dockerfiles — same
code, same `make verify`, just longer first build (~1 min).

| | |
|---|---|
| **Time to run** | About a minute first-run (`npm install` + AS pull); ~15 s warm |
| **MCP framework** | `@modelcontextprotocol/sdk 1.29.0` on Express (matches both `package.json` files) |
| **SDK** | `@authplane/mcp` 0.3.0 (in `after/` only) |

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

**`ERROR: node v20.x.x is too old. Install Node.js 22+.`**
The Makefile's prereq check caught a too-old Node. Update via `brew upgrade node`,
or switch versions with `nvm install 22 && nvm use 22`, then retry.

**Orphan `node` listening on 8080 / 8090 after `make clean`**
This was a real bug; the fix is shipped. `tsx` spawns a child node worker;
`make clean` now sends SIGTERM to the whole process group via
`../../_shared/native-proc.sh`, so the child dies with the parent. If you
ever see a stale node holding the port, kill it manually:
```bash
lsof -ti :8080 | xargs kill -9
lsof -ti :8090 | xargs kill -9
```
and please file a bug — that pattern is supposed to be handled.

**`make verify` hangs at "waiting for ..."**
Something didn't come up. Inspect each component:
```bash
make status   # is everything actually running?
make logs     # last 40 lines from AS + before + after
```
A common Node-side cause: `await authplaneMcpAuth(...)` at module load
couldn't reach the AS (typo'd `AUTHPLANE_ISSUER`, AS still starting).
The error is logged in `.run/after.log`.

**`make verify` Phase B.4 returns `invalid_token`**
You're hitting Authplane's #1 misconfiguration: the JWT audience doesn't
match. The `resource` you passed to `authplaneMcpAuth({...})`, the Resource
URI registered at the AS, and the `resource=...` form param on the token
request must agree byte-for-byte. The default flow gets this right; you'll
only hit it if you changed `AFTER_PORT` or the `resource` value by hand.

**`ERROR: jq not found` from `make verify`**
The verify script depends on `jq` to parse the AS's JSON responses. Install
it with `brew install jq` (macOS) or `apt install jq` (Debian/Ubuntu).

**ESM import errors when copying this code into your own project**
`@authplane/mcp` and `@authplane/sdk` are ESM-only (no CJS build). Your
consuming project's `package.json` needs `"type": "module"` and you must
use `import`, not `require`. The example's `package.json` files show the
minimum config.

**`make distclean` vs. `make clean`**
`make clean` stops processes and the AS container but keeps `.env` and the
`node_modules/` directories (so the next run is fast). `make distclean` is
the full reset — use before sharing the directory or switching examples.

## What `make verify` proves

```text
Phase A — before  (no bearer)         → HTTP 200, tools/call add(17,25)=42
Phase B.1 — after (no bearer)         → HTTP 401   ← auth enforced
Phase B.2 — register Resource + Client at the AS
Phase B.3 — mint a client_credentials token
Phase B.4 — after (with bearer)       → HTTP 200, tools/call add(17,25)=42
```

The smoke-test runs the **same MCP request** against both servers. The
only thing that changes is the 5-line auth block in `after/server.ts`.

## When to use this vs. tier-01

| Your situation | Start at |
|---|---|
| You have an existing Express + MCP-SDK server, you want the minimal diff to add auth | **You're already there.** Read `after/server.ts` next to `before/server.ts`. |
| You're writing a new MCP server from scratch | [`../01-mcp-server-basic/`](../01-mcp-server-basic/) — same five lines, fewer files. |
| You also need DPoP-bound tokens and per-tool scope enforcement | [`../03-mcp-server-fastmcp-dpop/`](../03-mcp-server-fastmcp-dpop/) |

## Adapting this to your project

> To run the AS against *your own* already-running server (not this
> example's `after/`) and provision + mint + call entirely by hand with
> `curl`, follow [Run the AS standalone and point it at your own MCP server](../../../docs/guides/integrate/standalone-as-by-hand.md).

The same two constraints from tier-01 apply (verbatim) when you copy
this into your own codebase:

**1. The two issuer URLs must share the same hostname.** The AS reads
`AUTHPLANE_SERVER_ISSUER` (what hostname it bakes into every JWT's
`iss` claim). The SDK inside your MCP server reads `AUTHPLANE_ISSUER`
(where to fetch metadata). They MUST resolve to the same hostname or
the SDK's `metadata.issuer == config.issuer` check fails.

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

**2. The `resource` value you pass to `authplaneMcpAuth({...})` is the
JWT audience byte-for-byte.** It must match the URL your MCP server
actually serves on (path included). If you mount the MCP handler at a
path other than `/mcp`, change `resource` AND register the Resource at
the AS with that same URI — mismatches produce an opaque
`invalid_token` on every call.

## Before production

The `after/` server is wired for local development. Before deploying:

| Setting | Dev value (here) | Production value | Why |
|---|---|---|---|
| `devMode: true` in `authplaneMcpAuth(...)` | `true` | **`false`** (or remove — it's the default) | Relaxes the SDK's SSRF guard so it accepts `http://`, `localhost`, and private-network issuers. Leaving it on in production weakens defense-in-depth against SSRF. |
| `AUTHPLANE_ISSUER` | `http://authserver:9000` | `https://auth.example.com` | Production issuers MUST be `https://`. The AS itself refuses to start with a non-localhost issuer unless cookies are also `Secure`. |
| `AUTHPLANE_SESSION_SECURE` | `true` | `true` | Required by the AS's startup validation whenever `server.issuer` is non-localhost. |
| `AUTHPLANE_ADMIN_API_KEY` | `dev-admin-key-change-me` | `openssl rand -hex 32` | Bearer for the entire admin surface. Treat like a root password. |
| Storage | SQLite in a Docker volume | PostgreSQL (`AUTHPLANE_STORAGE_DRIVER=postgres`) | SQLite is single-instance; PostgreSQL is required for HA. |
| Signing keys | Auto-generated in `/data/keys` | HashiCorp Vault Transit | See [`docs/guides/deploy/hashicorp-vault-transit.md`](../../../docs/guides/deploy/hashicorp-vault-transit.md). |

## What this example deliberately does not cover

- **Per-tool scope enforcement.** All three tools accept the same
  `mcp:tools` scope. For different scopes per tool, see
  [`../03-mcp-server-fastmcp-dpop/`](../03-mcp-server-fastmcp-dpop/).
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
