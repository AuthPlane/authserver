/**
 * Retrofit example — BEFORE (unauthed).
 *
 * A perfectly ordinary Express + @modelcontextprotocol/sdk MCP server.
 * Three small tools, streamable-http transport on port 8080, no auth at all.
 * This is what 90% of MCP servers in the wild look like today.
 *
 * `../after/server.ts` shows the same server with Authplane wired in. The
 * diff between this file and that one is the cost of adding auth.
 */

import crypto from "node:crypto";
import express from "express";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { z } from "zod";

const app = express();
app.use(express.json());

// === your tools ============================================================
const sessions = new Map<string, StreamableHTTPServerTransport>();

app.all("/mcp", async (req, res) => {
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

const PORT = Number(process.env.PORT ?? 8080);
app.listen(PORT, "0.0.0.0", () => {
  console.log(`MCP server (unauthed) listening on :${PORT}`);
});
