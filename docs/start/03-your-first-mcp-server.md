# 03 — Your first MCP server

**Time:** ~5 minutes. **Prereqs:** authserver running from
[step 02](02-quickstart-docker.md), plus a toolchain for whichever
language you pick.

You will register a resource server with Authplane, drop in the Resource
Server SDK, and serve one MCP tool that requires a valid Authplane
access token.

## Pick your language

The depth lives in the example READMEs. Each language has the same shape:
a tiny MCP server, a `make run`, and a `make verify` that mints a token
and calls the protected tool.

- **Go** -> [`examples/go/01-mcp-server-basic/`](../../examples/go/01-mcp-server-basic/)
  - Official `modelcontextprotocol/go-sdk` MCP server + `github.com/authplane/go-sdk/mcp` adapter (`authplanemcp.NewAdapter`).
- **TypeScript** -> [`examples/typescript/01-mcp-server-basic/`](../../examples/typescript/01-mcp-server-basic/)
  - Official `@modelcontextprotocol/sdk` MCP server on Express + `@authplane/mcp` adapter (`authplaneMcpAuth`).
- **Python** -> [`examples/python/01-mcp-server-basic/`](../../examples/python/01-mcp-server-basic/) (requires Python 3.12+)
  - [FastMCP](https://github.com/PrefectHQ/fastmcp) + `authplane-fastmcp` adapter on PyPI (`authplane_auth`).

These are the exact package names you `pip install` / `npm install` / `go get`. The packages are on the public registries and pinned to a working version in each example's manifest (`pyproject.toml`, `package.json`, `go.mod`).

> **Already have an MCP server?** Jump to the **retrofit** example for your language — it shows the exact 5-line diff applied to a real Express + MCP-SDK / FastMCP / go-sdk server, with a smoke-test that proves the auth toggle works:
>
> - **Python** -> [`examples/python/retrofit-existing-mcp-server/`](../../examples/python/retrofit-existing-mcp-server/)
> - **TypeScript** -> [`examples/typescript/retrofit-existing-mcp-server/`](../../examples/typescript/retrofit-existing-mcp-server/)
> - **Go** -> [`examples/go/retrofit-existing-mcp-server/`](../../examples/go/retrofit-existing-mcp-server/)

## What the example shows

Every tier-01 example demonstrates the same three things:

1. Calling the AS discovery endpoint (`/.well-known/oauth-authorization-server`)
   to fetch the JWKS URL.
2. Validating the bearer token on each MCP request (signature, audience,
   scope).
3. Returning a 401 with a `WWW-Authenticate` header that tells the agent
   where to authenticate (per the MCP Authorization spec).

If you want the prose version of those three things before you read the
code, see [Connect an MCP server](../guides/integrate/connect-mcp-server.md).

## What's next

Once tier-01 runs cleanly:

- Continue to [04 — Calling another resource from your MCP server](04-call-another-resource.md) when one of your tools needs to call a second protected resource.
- Or skip ahead to [Going further](05-going-further.md) for DPoP and broker.
