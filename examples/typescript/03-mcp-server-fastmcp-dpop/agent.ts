/**
 * Tier 03 — Agent with DPoP-bound tokens (TypeScript).
 *
 * Acquires a DPoP-bound (RFC 9449) access token from Authplane via the
 * `client_credentials` grant with both `mcp:echo` and `mcp:add` scopes, then
 * calls the tier-03 FastMCP server's `echo` and `add_numbers` tools. Each
 * outbound MCP request attaches a fresh DPoP proof bound to the same
 * keypair the AS bound the token to (`cnf.jkt`). The auth-specific lines
 * are wrapped between `// authplane:begin` / `// authplane:end` so
 * `tools/loccount` can audit the LOC budget for this tier.
 *
 * Run via the example's Makefile (the FastMCP server must already be up):
 *
 *     cp .env.example .env
 *     make run
 *     make verify
 */

// === transport / HTTP client boilerplate =====================================
import { generateKeyPairSync } from "node:crypto";
// MCP_URL is the network address the agent dials (Docker service DNS).
// DPOP_HTU is the URL the DPoP proof's `htu` claim must carry — and it is the
// resource origin (AUTHPLANE_RESOURCE), NOT the dial address: the FastMCP
// adapter reconstructs the expected `htu` from its own configured resource
// host (localhost:8080), so a proof signed for the Docker-DNS dial address
// (mcp-server:8080) would be rejected with "DPoP proof htu mismatch". RFC 9449 §4.2.
const MCP_URL = process.env.MCP_URL ?? "http://mcp-server:8080/mcp";
const DPOP_HTU = process.env.AUTHPLANE_RESOURCE ?? "http://localhost:8080/mcp";
const ECHO_TEXT = process.env.ECHO_TEXT ?? "hello from tier 03";

// Per-agent DPoP keypair. Plain Node crypto, no Authplane involvement.
const { privateKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
const pem = privateKey.export({ type: "pkcs8", format: "pem" }).toString();

// === Authplane integration ===================================================
// authplane:begin
import { AuthplaneClient, DPoPKeyMaterial, DPoPProvider } from "@authplane/sdk/core";
const dpop = new DPoPProvider({ keyMaterial: await DPoPKeyMaterial.fromPem(pem) });
// devMode relaxes the SDK's HTTPS/SSRF guard so the agent can discover metadata
// from the local http:// issuer. Local development only — production issuers must
// be https:// and devMode must be false (the default).
const ap = await AuthplaneClient.create({
  issuer: process.env.AUTHPLANE_ISSUER!,
  auth: { clientId: process.env.AUTHPLANE_CLIENT_ID!, clientSecret: process.env.AUTHPLANE_CLIENT_SECRET! },
  dpopProvider: dpop, devMode: true,
});
const token = await ap.clientCredentials(["mcp:echo", "mcp:add"], [process.env.AUTHPLANE_RESOURCE!]);
// authplane:end

// === call the MCP tools ======================================================
// MCP streamable-http session id. `initialize` returns it in the
// `Mcp-Session-Id` response header; every subsequent request (including the
// `notifications/initialized` handshake) must echo it back or the server
// rejects with 400 "No valid session ID provided".
let sessionId: string | undefined;

// `id` is omitted for JSON-RPC notifications (e.g. notifications/initialized),
// which carry no `id` and get a 202 with an empty body.
async function mcpCall(method: string, params: unknown, id?: number): Promise<unknown> {
  // authplane:begin
  const proof = await dpop.createProof({ method: "POST", url: DPOP_HTU, accessToken: token.accessToken });
  // Send the access token under the `Bearer` scheme (not RFC 9449's `DPoP`
  // scheme): FastMCP's bearer auth backend only inspects `Bearer `-prefixed
  // Authorization headers. The DPoP binding is still enforced — the server
  // verifies the access token's `cnf.jkt` against the `DPoP` proof header
  // regardless of the Authorization scheme.
  const authHeaders = { Authorization: `Bearer ${token.accessToken}`, DPoP: proof };
  // authplane:end
  const message: Record<string, unknown> = { jsonrpc: "2.0", method, params };
  if (id !== undefined) message.id = id;
  const res = await fetch(MCP_URL, {
    method: "POST",
    headers: {
      ...authHeaders,
      "Content-Type": "application/json",
      "Accept": "application/json, text/event-stream",
      ...(sessionId ? { "Mcp-Session-Id": sessionId } : {}),
    },
    body: JSON.stringify(message),
  });
  if (!res.ok) {
    throw new Error(`MCP ${method} returned HTTP ${res.status}: ${await res.text()}`);
  }
  // The server assigns the session on the initialize response; capture it for
  // every later request.
  const sid = res.headers.get("mcp-session-id");
  if (sid) sessionId = sid;
  // Notifications (no id) get 202 + empty body — nothing to parse.
  const body = await res.text();
  if (!body.trim()) return undefined;
  const dataLine = body.split("\n").find((l) => l.startsWith("data: "));
  const payload = dataLine ? dataLine.slice("data: ".length) : body;
  return JSON.parse(payload);
}

const initResult = await mcpCall("initialize", {
  protocolVersion: "2024-11-05",
  capabilities: {},
  clientInfo: { name: "tier-03-agent", version: "1.0" },
}, 1);
console.log(`[agent] initialize OK: ${JSON.stringify(initResult)}`);

// Complete the MCP lifecycle handshake: tools are not callable until the
// client confirms initialization. No id — this is a notification.
await mcpCall("notifications/initialized", {}, undefined);

const echoResult = await mcpCall("tools/call", {
  name: "echo",
  arguments: { text: ECHO_TEXT },
}, 2);
console.log(`[agent] echo OK: ${JSON.stringify(echoResult)}`);

const addResult = await mcpCall("tools/call", {
  name: "add_numbers",
  arguments: { a: 2, b: 3 },
}, 3);
console.log(`[agent] add_numbers OK: ${JSON.stringify(addResult)}`);

await ap.close();
