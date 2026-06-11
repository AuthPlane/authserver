# 04 — Calling another resource from your MCP server

**Time:** ~5 minutes. **Prereqs:** the tier-01 MCP server from
[step 03](03-your-first-mcp-server.md) running locally.

Authplane's SDKs are for **MCP server implementors**, not agent
implementors — the agent side is handled by your MCP client (Claude
Desktop, MCP Inspector, etc.). Tier-02 shows what an MCP server does
when one of its tools needs to call **another protected resource** on the
user's behalf: it acquires its own access token via the `client_credentials`
grant and presents it as a bearer to the second resource.

The "agent" in this example is your MCP server acting as a client of a
second resource — not a standalone agent process.

## Pick your language

- **Go** -> [`examples/go/02-agent-basic/`](../../examples/go/02-agent-basic/)
- **TypeScript** -> [`examples/typescript/02-agent-basic/`](../../examples/typescript/02-agent-basic/)
- **Python** -> [`examples/python/02-agent-basic/`](../../examples/python/02-agent-basic/)

Each example uses the [Auth Client SDK](../guides/integrate/sdk-auth-client.md)
from the language's official SDK repo (the same SDKs that wrap the verifier
in tier-01).

## What the example shows

1. Register an OAuth client of type `client_credentials` against Authplane
   (a one-time setup step the `make verify` target does for you).
2. From inside your MCP server, fetch an access token with `client_id` +
   `client_secret` + the right `resource` and `scope` parameters.
3. Call the second resource (here: the tier-01 MCP server), passing the
   token in the `Authorization` header.

If you want the prose grounding before reading the code:

- [Client credentials grant](../guides/integrate/client-credentials-grant.md)
- [Tokens and claims](../concepts/tokens-and-claims.md)

## What's next

Now you have one MCP server calling another through Authplane. Continue
to [05 — Going further](05-going-further.md) for DPoP, broker topologies,
and federation.
