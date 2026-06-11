/**
 * Tier 04 — Broker upstream agent (TypeScript).
 *
 * Demonstrates the RFC 8693 Token Exchange grant against a Broker-backed
 * Resource and the `ConsentRequiredError` handshake the SDK surfaces when
 * the user hasn't connected the upstream provider yet.
 *
 * Flow:
 *  1. Acquire a subject token via `client_credentials` against the Broker
 *     resource the exchange targets — the direct-broker model the Go and
 *     Python tier-04 examples also use. The agent's client_id is bound to
 *     its actor-MCP Mint resource through `policy.runtime.client_ids`, so
 *     the Broker dispatch's agent-attestation gate resolves the actor from
 *     the client_id alone (verified against
 *     internal/services/token_exchange.go:1255); the subject token's
 *     audience is the broker, not the Mint. Minting against the Mint
 *     instead makes the AS classify this as a fronted Mint->Broker exchange
 *     and demand an operator-declared `fronting_links` row.
 *  2. Call `AuthplaneClient.exchange(...)` against the Broker resource.
 *     With no broker_grants row in the database (a real /connect/<provider>
 *     flow has never run for this user+provider), the AS returns
 *     `consent_required` with a `consent_url` pointing the user at the
 *     Connect surface. The SDK maps that to a `ConsentRequiredError`.
 *  3. The agent prints the consent URL and exits non-zero — the operator
 *     would normally hand that URL to the human, who runs the browser
 *     flow once, and the next `exchange(...)` call returns the upstream
 *     access token.
 *
 * Run via the example's Makefile:
 *
 *     cp .env.example .env
 *     make run
 *     make verify
 */

// === transport / config boilerplate ==========================================
const UPSTREAM_RESOURCE = process.env.UPSTREAM_RESOURCE ?? "github";
const BROKER_RESOURCE_URI = process.env.BROKER_RESOURCE_URI ?? "https://github.example.invalid";

// === Authplane integration ===================================================
// authplane:begin
import { AuthplaneClient, ConsentRequiredError } from "@authplane/sdk/core";
const ap = await AuthplaneClient.create({
  issuer: process.env.AUTHPLANE_ISSUER!,
  auth: { clientId: process.env.AUTHPLANE_CLIENT_ID!, clientSecret: process.env.AUTHPLANE_CLIENT_SECRET! },
  devMode: true,
});
const subject = await ap.clientCredentials(["repo"], [BROKER_RESOURCE_URI]);
try {
  const upstream = await ap.exchange({
    subjectToken: subject.accessToken,
    scope: "repo",
    resources: [UPSTREAM_RESOURCE],
  });
  console.log(`[agent] exchange OK: issued_token_type=${upstream.issuedTokenType} scope=${upstream.scope}`);
} catch (e) {
  if (e instanceof ConsentRequiredError) {
    console.log(`[agent] consent_required: visit ${e.consentUrl ?? "(no consent_url returned)"}`);
    await ap.close();
    process.exit(2);
  }
  throw e;
}
// authplane:end

await ap.close();
