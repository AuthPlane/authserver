/**
 * Tier 01 — Basic MCP server (TypeScript).
 *
 * Minimal MCP server protected by Authplane-issued JWTs. The auth-specific
 * code is wrapped between `// authplane:begin` / `// authplane:end` so the
 * `tools/loccount` tool can audit the LOC budget for this tier.
 *
 * Run via the example's Makefile:
 *
 *     cp .env.example .env
 *     make run
 *     make verify
 */

// === transport / MCP boilerplate ===========================================
import crypto from "node:crypto";
import express from "express";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { z } from "zod";

// === Authplane integration =================================================
// `authplaneMcpAuth()` does AS metadata discovery + JWKS fetch on import.
// The AS MUST be reachable when this module loads or the top-level `await`
// will reject and the process will fail to start. The example's
// docker-compose uses `depends_on:` + a healthcheck so this race never
// fires (see docker-compose.yml). If you run outside compose, either
// bring the AS up first or wrap the call:
//
//     let auth;
//     for (let i = 0; i < 30; i++) {
//       try { auth = await authplaneMcpAuth({...}); break; }
//       catch (e) { await new Promise(r => setTimeout(r, 1000)); }
//     }
//     if (!auth) throw new Error("authserver unreachable after 30s");
//
// `devMode: true` relaxes the SDK's SSRF guard so it will fetch from
// `http://` issuers, `localhost`, and private networks. It is for local
// development only — production issuers MUST be `https://` and `devMode`
// MUST be `false` (the default).
// authplane:begin
import { authplaneMcpAuth } from "@authplane/mcp";
const auth = await authplaneMcpAuth({
  issuer: process.env.AUTHPLANE_ISSUER!,
  resource: process.env.AUTHPLANE_RESOURCE!,
  scopes: ["mcp:echo"], devMode: true,
});
// authplane:end

const app = express();
app.use(express.json());
app.get(auth.protectedResourceMetadataPath, auth.protectedResourceMetadataHandler);

// === your tools ============================================================
const sessions = new Map<string, StreamableHTTPServerTransport>();

app.all("/mcp", auth.bearerAuth, async (req, res) => {
  const sessionId = req.headers["mcp-session-id"] as string | undefined;
  let transport = sessionId ? sessions.get(sessionId) : undefined;
  if (!transport) {
    const newSessionId = crypto.randomUUID();
    transport = new StreamableHTTPServerTransport({
      sessionIdGenerator: () => newSessionId,
    });
    const server = new McpServer({ name: "demo-server", version: "1.0.0" });
    type EchoArgs = { text: z.ZodString };
    const echoShape: EchoArgs = { text: z.string() };
    server.registerTool<EchoArgs, EchoArgs>(
      "echo",
      { inputSchema: echoShape },
      async ({ text }) => ({ content: [{ type: "text" as const, text }] }),
    );
    await server.connect(transport);
    sessions.set(newSessionId, transport);
  }
  await transport.handleRequest(req, res, req.body);
});

// Port is read from PORT for one-touch retargeting. Note: when you change
// it, also update AUTHPLANE_RESOURCE (the JWT audience) and the URI you
// register the Resource with at the AS — the three must agree byte-for-byte.
const PORT = Number(process.env.PORT ?? 8080);
app.listen(PORT, "0.0.0.0", () => {
  console.log(`MCP server listening on :${PORT}`);
});
