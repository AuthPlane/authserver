/**
 * Tier 03 — FastMCP server with DPoP + per-tool scopes (TypeScript).
 *
 * Minimal FastMCP server protected by Authplane-issued, DPoP-bound JWTs
 * (RFC 9449). Two scoped tools (`echo` requiring `mcp:echo`, `add_numbers`
 * requiring `mcp:add`) demonstrate per-tool scope enforcement via FastMCP's
 * `requireScopes` helper. The auth-specific lines are wrapped between
 * `// authplane:begin` / `// authplane:end` so `tools/loccount` can audit
 * the LOC budget for this tier.
 *
 * Run via the example's Makefile:
 *
 *     cp .env.example .env
 *     make run
 *     make verify
 */

// === transport / MCP boilerplate ===========================================
import { FastMCP } from "fastmcp";
import { z } from "zod";

// === Authplane integration =================================================
// authplane:begin
import { authplaneFastMcpAuth, type AuthplaneFastMcpSession } from "@authplane/fastmcp";
import { InMemoryDPoPReplayStore } from "@authplane/sdk/core";
import { requireScopes } from "fastmcp";
const auth = await authplaneFastMcpAuth({
  issuer: process.env.AUTHPLANE_ISSUER!, resource: process.env.AUTHPLANE_RESOURCE!,
  scopes: ["mcp:echo", "mcp:add"], inboundDPoP: { required: true }, devMode: true,
  // A replay store is required to honor DPoP proofs (RFC 9449 §11.1). Without
  // it the adapter ignores the DPoP header and rejects bound tokens with 401.
  // InMemory is fine for a single-process demo; use a shared store in prod.
  replayStore: new InMemoryDPoPReplayStore(),
});
// authplane:end

const server = new FastMCP<AuthplaneFastMcpSession>({
  name: "demo-server",
  version: "1.0.0",
  authenticate: auth.authenticate,
  oauth: auth.oauth,
});

// === your tools ============================================================
server.addTool({
  name: "echo",
  description: "Echo back the given text",
  parameters: z.object({ text: z.string() }),
  // authplane:begin
  canAccess: requireScopes("mcp:echo"),
  // authplane:end
  execute: async ({ text }) => ({ content: [{ type: "text" as const, text }] }),
});

server.addTool({
  name: "add_numbers",
  description: "Add two numbers",
  parameters: z.object({ a: z.number(), b: z.number() }),
  // authplane:begin
  canAccess: requireScopes("mcp:add"),
  // authplane:end
  execute: async ({ a, b }) => ({ content: [{ type: "text" as const, text: String(a + b) }] }),
});

await server.start({
  transportType: "httpStream",
  // host 0.0.0.0 so the server is reachable through the container's published
  // port; FastMCP defaults host to "localhost", which only binds the container
  // loopback and is unreachable from the host (and from the tier-02 agent).
  httpStream: { port: 8080, endpoint: "/mcp", host: "0.0.0.0" },
});
console.log("FastMCP server listening on :8080/mcp");
