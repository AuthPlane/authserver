# Authplane MCP examples

Runnable proofs that adding Authplane auth to your MCP server is **a
handful of extra lines** — every line CI-counted and verified.

## Tier ladder — 5 lines of auth, growing scope

The numbers are the auth-specific lines inside `// authplane:begin` /
`// authplane:end` markers in each example's main source file
(`server.py` / `server.ts` / `main.go`), excluding imports — measured
by `tools/loccount` and CI-enforced against the per-tier budget.

| Tier | What it shows | Go | TypeScript | Python |
|---|---|---|---|---|
| **01** basic server | MCP server protected by JWT, single tool, `client_credentials` token | [5 lines](go/01-mcp-server-basic/) | [5 lines](typescript/01-mcp-server-basic/) | [5 lines](python/01-mcp-server-basic/) |
| **02** calling another resource | The same MCP server mints a token via the SDK to call a second protected resource | [5 lines](go/02-agent-basic/) | [5 lines](typescript/02-agent-basic/) | [8 lines](python/02-agent-basic/) |
| **03** DPoP + per-tool scopes | RFC 9449 sender-constrained tokens, per-tool scope enforcement | [15 lines](go/03-mcp-server-dpop-scopes/) | [15 lines](typescript/03-mcp-server-fastmcp-dpop/) | [15 lines](python/03-mcp-server-dpop-scopes/) |
| **04** MCP server fronting a Broker | RFC 8693 token exchange against an upstream provider (GitHub), `ConsentRequiredError` handling | [19 lines](go/04-broker-upstream/) | [21 lines](typescript/04-broker-upstream/) | [26 lines](python/04-broker-upstream/) |

## Retrofit — add Authplane to an MCP server you already have

A separate before/after pair, not part of the tier ladder. Same three
tools in two versions (`before/` unauthed, `after/` with the 5-line
auth block applied). `make verify` brings up both side-by-side and
proves the same `tools/call` returns 200 to one and 401 to the other.

[Go](go/retrofit-existing-mcp-server/) · [TypeScript](typescript/retrofit-existing-mcp-server/) · [Python](python/retrofit-existing-mcp-server/)

## How to run any example

```bash
cd examples/<lang>/<tier>/
cp .env.example .env
make run     # bring up authserver + the example
make verify  # registers resource/client/policy, mints token, calls the tool
make clean   # tear down
```

## Use a locally-built authserver image

Every example defaults to `authplane/authserver:latest`. To
run against a locally-built image, follow the LOCAL BUILD ESCAPE HATCH
block inside [`_shared/docker-compose.authserver.yml`](_shared/docker-compose.authserver.yml).

## See also

- [docs/start/](../docs/start/) — guided tutorials wrapping these examples
- [docs/concepts/](../docs/concepts/) — vocabulary + mental model
- [docs/reference/](../docs/reference/) — generated CLI + HTTP API reference
