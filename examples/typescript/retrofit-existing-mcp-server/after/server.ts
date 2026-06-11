/**
 * Retrofit example — AFTER (Authplane added).
 *
 * This is the SAME server as `../before/server.ts` — same three tools,
 * same Express + MCP SDK boilerplate, same `app.listen(8080)`. The only
 * changes are:
 *
 *   (a) the `// authplane:begin` / `// authplane:end` block (5 lines),
 *   (b) `app.get(auth.protectedResourceMetadataPath, ...)` to serve the
 *       PRM document,
 *   (c) `auth.bearerAuth` middleware on `/mcp`.
 *
 * Compare side-by-side:
 *
 *     diff -u ../before/server.ts server.ts
 *
 * That diff is the cost of adding auth to an existing Express + MCP-SDK
 * server.
 */

import crypto from "node:crypto";
import express from "express";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { z } from "zod";

// === Authplane integration =================================================
// Five lines. `authplaneMcpAuth()` does AS metadata discovery + JWKS fetch
// on import — the AS must be reachable when this module loads.
// `devMode: true` relaxes the SDK's SSRF guard for local-dev only.
// authplane:begin
import { authplaneMcpAuth } from "@authplane/mcp";
const auth = await authplaneMcpAuth({
  issuer: process.env.AUTHPLANE_ISSUER!,
  resource: process.env.AUTHPLANE_RESOURCE!,
  scopes: ["mcp:tools"], devMode: true,
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
    const server = new McpServer({ name: "retrofit-demo", version: "1.0.0" });

    // tool: add
    server.registerTool(
      "add",
      {
        inputSchema: { a: z.number(), b: z.number() },
      },
      async ({ a, b }) => ({
        content: [{ type: "text" as const, text: String(a + b) }],
      }),
    );

    // tool: now_utc
    server.registerTool(
      "now_utc",
      { inputSchema: {} },
      async () => ({
        content: [{ type: "text" as const, text: new Date().toISOString() }],
      }),
    );

    // tool: roll_dice
    server.registerTool(
      "roll_dice",
      {
        inputSchema: { sides: z.number().default(6), count: z.number().default(1) },
      },
      async ({ sides, count }) => {
        const rolls = Array.from({ length: count }, () =>
          1 + Math.floor(Math.random() * sides),
        );
        return {
          content: [
            {
              type: "text" as const,
              text: JSON.stringify({ rolls, total: rolls.reduce((s, r) => s + r, 0), sides }),
            },
          ],
        };
      },
    );

    await server.connect(transport);
    sessions.set(newSessionId, transport);
  }
  await transport.handleRequest(req, res, req.body);
});

// Port is read from PORT for one-touch retargeting. When you change it,
// also update AUTHPLANE_RESOURCE so the JWT `aud` claim still matches.
const PORT = Number(process.env.PORT ?? 8080);
app.listen(PORT, "0.0.0.0", () => {
  console.log(`MCP server (auth-enforced) listening on :${PORT}`);
});
