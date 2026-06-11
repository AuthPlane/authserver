# Start here

A guided tutorial path from "I just heard about Authplane" to "my MCP
server vends DPoP-bound, scope-narrowed tokens and calls other resources
on the user's behalf."

- **For:** Builder (developer writing or hardening an MCP server).
  Authplane's SDKs are for MCP server implementors — the agent side
  (Claude Desktop, MCP Inspector, etc.) is handled by your MCP client.
- **Time:** ~10 minutes to first token; ~30 minutes for the full path.
- **Prereqs:** Docker. The DPoP and resource-to-resource steps
  additionally need Go 1.25+, Node 22+, or Python 3.12+ depending on the
  language you pick.
- **Conventions:** Commands assume macOS or Linux. Replace
  `http://localhost:9000` with your issuer URL once you deploy
  somewhere real. Every example in `examples/` works with the
  `authplane/authserver:latest` image so you do not have to
  build from source to follow along.

## Path

1. [What is Authplane](01-what-is-authplane.md) — 60-second recap before
   you touch a terminal.
2. [Quickstart: Docker](02-quickstart-docker.md) — get authserver
   running, hit the discovery endpoint, mint your first admin token.
3. [Your first MCP server](03-your-first-mcp-server.md) — drop in the
   Resource Server SDK in your language of choice.
4. [Calling another resource from your MCP server](04-call-another-resource.md)
   — what your MCP server does when a tool needs to call a second
   protected resource on the user's behalf.
5. [Going further](05-going-further.md) — DPoP, broker topologies, and
   where to read next.

When the tutorial ends, you should know which [topology](../topologies/)
you want for production and which [guides](../guides/) to read next.
