//go:build e2e

package scenarios

import (
	"testing"

	"github.com/authplane/authserver/e2e"
)

// TestCrossResourceExchange_ViaPerMCPConsent is the replacement
// scenario.  deleted the coarse→fine `scope_mappings` translation
// table; v4's per-MCP `consent_grants` now solves the cross-resource
// exchange use case directly.
//
// Setup:
//   - Two Mint resources, mcp-a and mcp-b, each with scope `read`.
//   - Agent client `agent-a` (the bearer of the user's token).
//   - mcp-a registered as a confidential client with the token-exchange
//     grant (it's the caller of /oauth/token).
//   - Two consent grants: (alice, agent-a, mcp-a) AND (alice, agent-a,
//     mcp-b) — alice consented to agent-a at BOTH MCPs independently.
//
// Positive flow: agent-a invokes mcp-a, which exchanges its token for
// an mcp-b-scoped token. dispatchMint resolves consent against
// (alice, agent-a, mcp-b) — the row exists, exchange succeeds.
// JWT has aud = mcp-b URI, scope = read.
//
// Negative case: alice consented only to mcp-a, NOT mcp-b. Same
// exchange returns consent_required with cause=consent_missing and
// consent_url pointing at /authorize?resource=<mcp-b-slug>&scope=read.
func TestCrossResourceExchange_ViaPerMCPConsent(t *testing.T) {
	scopes := []string{"read"}
	h, servers := e2e.SetupE2E(t, e2e.HarnessConfig{
		EnableAdminAPI:             true,
		EnableTokenExchange:        true,
		TokenExchangeMaxChainDepth: 5,
		// No upstream provider — both targets are Mint resources, not
		// Broker resources.
	}, scopes, scopes)
	mcpAResourceServer := servers[0]

	h.RegisterScope(mcpAResourceServer.URI, "read", "Read mcp-a")
	h.RegisterScope(servers[1].URI, "read", "Read mcp-b")

	const email = "alice-cross@example.com"
	const password = "pass123"
	h.CreateUser(email, password)

	// Agent client. The user's auth-code flow runs as agent-a, so the
	// resulting JWT carries client_id=<agent> — exactly what
	// dispatchMint's consent lookup keys on. client_id auto-gen.
	agentClientID := h.AdminCreatePublicClient(
		"cross-resource agent",
		[]string{"authorization_code"},
		"read",
		nil,
	)

	// mcp-a registered as a confidential client with the token-exchange
	// grant — it's the caller of /oauth/token. client_id auto-gen.
	mcpAClientID, mcpASecret := h.AdminCreateConfidentialClient(
		"cross-resource mcp-a",
		[]string{"urn:ietf:params:oauth:grant-type:token-exchange"},
		"read",
	)

	// Resolve mcp-b's resource view to assert the exchanged JWT's aud
	// claim equals mcp-b's URI. Lookup goes through the public admin
	// API — the Gate-0 shortcut
	// h.ResourceStore().GetBySlug is gone. (mcp-a is referenced
	// throughout by slug "mcp-0" alone, so no admin lookup is needed
	// for it.)
	mcpBRes := h.AdminGetResourceBySlug("mcp-1")

	const redirectURI = "http://localhost:9999/callback"

	t.Run("HappyPath_ConsentForBothMCPs_ExchangeSucceeds", func(t *testing.T) {
		// Two consent grants: (alice, agent-a, mcp-a) AND
		// (alice, agent-a, mcp-b). Driven through the public per-MCP
		// consent flow (: replaces SeedConsentGrant, which wrote
		// directly to the consent_grants store). The cross-resource
		// exchange targets mcp-b, so dispatchMint reads the mcp-b row.
		_, _, _ = h.RunFlowC1Consent(
			email, password, agentClientID, redirectURI, "mcp-0",
			[]string{"read"}, []string{"read"},
		)
		_, _, _ = h.RunFlowC1Consent(
			email, password, agentClientID, redirectURI, "mcp-1",
			[]string{"read"}, []string{"read"},
		)

		// Drive the agent's auth-code flow against mcp-a so the JWT
		// has client_id=agent-a, sub=alice, aud=<mcp-a URI>.
		mcpClient := e2e.NewMCPClient(t, h, mcpAResourceServer, agentClientID, redirectURI)
		userTokens := mcpClient.FullFlow(email, password, "read", false)
		if userTokens.AccessToken == "" {
			t.Fatal("expected user access token from agent's auth-code flow")
		}

		// mcp-a now exchanges the user's token for an mcp-b-scoped
		// token. dispatchMint resolves consent against
		// (alice, agent-a, mcp-b) — present → SUCCESS.
		exch := h.TokenExchangeWithResource(
			mcpAClientID, mcpASecret,
			userTokens.AccessToken, "urn:ietf:params:oauth:token-type:access_token",
			"read",
			"mcp-1", // target mcp-b by slug
		)
		if exch.AccessToken == "" {
			t.Fatal("expected vended access token")
		}

		// JWT-level check: aud == mcp-b URI, scope == "read".
		claims := parseJWTClaims(t, exch.AccessToken)
		audClaim, ok := claims["aud"]
		if !ok {
			t.Fatal("expected aud claim on cross-resource exchange JWT")
		}
		// aud may be a string or []string; normalise.
		var audList []any
		switch v := audClaim.(type) {
		case string:
			audList = []any{v}
		case []any:
			audList = v
		default:
			t.Fatalf("aud claim has unexpected shape %T", audClaim)
		}
		var foundAud bool
		for _, a := range audList {
			if a == mcpBRes.URI {
				foundAud = true
				break
			}
		}
		if !foundAud {
			t.Errorf("aud claim = %v, want it to contain %q", audList, mcpBRes.URI)
		}
		if exch.Scope != "read" {
			t.Errorf("exchange scope = %q, want \"read\"", exch.Scope)
		}
	})

	// --- Negative case: only consent for mcp-a, NOT mcp-b. The
	// dispatcher must reject with consent_required, cause=consent_missing,
	// and a consent_url pointing at /authorize?resource=mcp-1&scope=read.
	t.Run("NegativeCase_NoConsentForTargetMCP_ConsentRequired", func(t *testing.T) {
		// Fresh user so we don't inherit the happy-path consent rows.
		const negEmail = "alice-cross-neg@example.com"
		const negPassword = "pass123"
		h.CreateUser(negEmail, negPassword)

		// Consent for mcp-a only — driven through /authorize+/consent
		//.
		_, _, _ = h.RunFlowC1Consent(
			negEmail, negPassword, agentClientID, redirectURI, "mcp-0",
			[]string{"read"}, []string{"read"},
		)
		// (No RunFlowC1Consent for mcp-1.)

		mcpClient := e2e.NewMCPClient(t, h, mcpAResourceServer, agentClientID, redirectURI)
		userTokens := mcpClient.FullFlow(negEmail, negPassword, "read", false)
		if userTokens.AccessToken == "" {
			t.Fatal("expected user access token")
		}

		oe := h.TokenExchangeWithResourceExpectError(
			mcpAClientID, mcpASecret,
			userTokens.AccessToken, "urn:ietf:params:oauth:token-type:access_token",
			"read",
			"mcp-1", // target mcp-b
		)
		if oe.Error != "consent_required" {
			t.Errorf("error = %q, want consent_required", oe.Error)
		}
		if oe.Cause != "consent_missing" {
			t.Errorf("cause = %q, want consent_missing (no consent_grants row for mcp-b)", oe.Cause)
		}
		// cause=consent_missing carries no MissingScopes (the user has
		// not consented at all), so the consent_url omits the &scope=
		// query — the user re-runs the full per-MCP consent screen at
		// the AS, picking which scopes to grant. ( reserves the
		// scope hint for cause=scope_insufficient where the missing
		// subset is known.)
		wantURL := h.Issuer + "/authorize?resource=mcp-1"
		if oe.ConsentURL != wantURL {
			t.Errorf("consent_url = %q, want %q", oe.ConsentURL, wantURL)
		}
	})
}
