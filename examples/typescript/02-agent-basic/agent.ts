/**
 * Tier 02 — Basic agent (TypeScript).
 *
 * A minimal MCP client that acquires an access token from Authplane via the
 * `client_credentials` grant and uses it to call the tier-01 MCP server's
 * `echo` tool. Auth-specific lines are wrapped between
 * `// authplane:begin` / `// authplane:end` so `tools/loccount` can audit
 * the LOC budget for this tier.
 *
 * Run via the example's Makefile (tier 01 must already be running):
 *
 *     # In examples/typescript/01-mcp-server-basic
 *     make run
 *
 *     # In examples/typescript/02-agent-basic
 *     cp .env.example .env
 *     make verify
 */

// === transport / HTTP client boilerplate =====================================
const MCP_URL = process.env.MCP_URL ?? "http://mcp-server:8080/mcp";
const ECHO_TEXT = process.env.ECHO_TEXT ?? "hello from tier 02";

async function mcpCall(accessToken: string, method: string, params: unknown, id: number): Promise<unknown> {
  const res = await fetch(MCP_URL, {
    method: "POST",
    headers: {
      "Authorization": `Bearer ${accessToken}`,
      "Content-Type": "application/json",
      "Accept": "application/json, text/event-stream",
    },
    body: JSON.stringify({ jsonrpc: "2.0", id, method, params }),
  });
  if (!res.ok) {
    throw new Error(`MCP ${method} returned HTTP ${res.status}: ${await res.text()}`);
  }
  // The streamable-http transport may reply as SSE; pull the first `data:` line.
  const body = await res.text();
  const dataLine = body.split("\n").find((l) => l.startsWith("data: "));
  const payload = dataLine ? dataLine.slice("data: ".length) : body;
  return JSON.parse(payload);
}

// === Authplane integration ===================================================
// authplane:begin
import { AuthplaneClient } from "@authplane/sdk/core";
const ap = await AuthplaneClient.create({
  issuer: process.env.AUTHPLANE_ISSUER!,
  auth: { clientId: process.env.AUTHPLANE_CLIENT_ID!, clientSecret: process.env.AUTHPLANE_CLIENT_SECRET! },
});
const token = await ap.clientCredentials(["mcp:echo"], [process.env.AUTHPLANE_RESOURCE!]);
// authplane:end

// === call the MCP tool =======================================================
const initResult = await mcpCall(token.accessToken, "initialize", {
  protocolVersion: "2024-11-05",
  capabilities: {},
  clientInfo: { name: "tier-02-agent", version: "1.0" },
}, 1);
console.log(`[agent] initialize OK: ${JSON.stringify(initResult)}`);

const echoResult = await mcpCall(token.accessToken, "tools/call", {
  name: "echo",
  arguments: { text: ECHO_TEXT },
}, 2);
console.log(`[agent] echo OK: ${JSON.stringify(echoResult)}`);

await ap.close();
