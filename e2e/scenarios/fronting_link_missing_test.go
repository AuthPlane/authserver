//go:build e2e

package scenarios

import (
	"strings"
	"testing"

	"github.com/authplane/authserver/e2e"
)

// TestNonFrontedMintToBroker_ReturnsFrontingLinkMissing pins the fail-fast
// contract: when an agent calls token-exchange against a Broker Resource
// and the subject token's `aud` resolves to a Mint Resource for which no
// fronting_links row connects to the target Broker, the AS returns HTTP
// 400 + error=invalid_request + a description that names both slugs and
// the canonical topology doc — instead of falling through to the legacy
// bound-B agent-attestation gate (whose `consent_required:
// agent_attestation_required` response pointed operators at the wrong fix).
//
// Fixture mirrors gatewayFanoutBrokerSetup but deliberately OMITS the
// fronting_links row. Everything else is identical so we isolate the
// failure to the missing link.
func TestNonFrontedMintToBroker_ReturnsFrontingLinkMissing(t *testing.T) {
	fix := nonFrontedBrokerSetup(t)
	h := fix.h

	// Drive the user → GW auth-code dance so we have a Mint JWT whose `aud`
	// resolves to fb-mcp-gw (the source Mint Resource).
	code, verifier, _ := h.RunFlowC1Consent(
		fbEmail, fbPassword,
		fix.gwClient, fbGWRedirect,
		fbGWSlug,
		[]string{"tool:list"},
		[]string{"tool:list"},
	)
	if code == "" {
		t.Fatal("RunFlowC1Consent returned empty code")
	}
	gwTokens := h.ExchangeCode(code, verifier, fix.gwClient, fbGWRedirect)
	if gwTokens.AccessToken == "" {
		t.Fatal("ExchangeCode returned empty access_token")
	}

	// Agent token-exchange against the Broker target. No fronting_links
	// row exists, so dispatchBroker should fail fast with the new typed
	// error rather than fall through to bound-B.
	oe := h.TokenExchangeWithResourceExpectError(
		fix.agentClient, fix.agentSecret,
		gwTokens.AccessToken,
		"urn:ietf:params:oauth:token-type:access_token",
		"readonly",
		fbCalSlug,
	)

	if oe.StatusCode != 400 {
		t.Errorf("status = %d, want 400", oe.StatusCode)
	}
	if oe.Error != "invalid_request" {
		t.Errorf("error = %q, want invalid_request", oe.Error)
	}
	for _, want := range []string{
		fbGWSlug,         // source slug named
		fbCalSlug,        // target slug named
		"fronting_links", // operator-facing keyword
		"docs/how-to/topologies/mcp-gateway-broker.md", // doc pointer
	} {
		if !strings.Contains(oe.ErrorDescription, want) {
			t.Errorf("error_description missing %q\ngot: %s", want, oe.ErrorDescription)
		}
	}
}

// nonFrontedBrokerSetup is gatewayFanoutBrokerSetup with the
// AdminCreateFrontingLink call deliberately omitted, to isolate the
// missing-link failure mode. Everything else is identical so any drift
// in the shared fixture is reflected here too.
func nonFrontedBrokerSetup(t *testing.T) fanoutBrokerFixture {
	t.Helper()

	h, _ := e2e.SetupE2E(t, e2e.HarnessConfig{
		EnableAdminAPI:             true,
		EnableTokenExchange:        true,
		TokenExchangeMaxChainDepth: 5,
		Connectors: []e2e.ConnectorConfig{
			{
				Service:      fbCalProviderSlug,
				Scopes:       []string{"calendar.readonly", "calendar.events"},
				AccessToken:  "goog_fb_mock_token",
				RefreshToken: "goog_fb_mock_token",
				ExpiresIn:    3600,
			},
		},
	}, []string{"placeholder"})

	h.CreateUser(fbEmail, fbPassword)

	gwClient := h.AdminCreatePublicClient(
		"non-fronted fanout gateway",
		[]string{"authorization_code"},
		fbGWScope,
		[]string{fbGWRedirect},
	)

	agentClient, agentSecret := h.AdminCreateAgentClient(
		"non-fronted exchange agent",
		[]string{"urn:ietf:params:oauth:grant-type:token-exchange"},
		"tool:list tool:create calendar.readonly calendar.events",
		"non-fronted exchange agent",
	)

	h.AdminCreateResource(e2e.CreateResourceSpec{
		Slug:        fbGWSlug,
		URI:         fbGWURI,
		BackendKind: "mint",
		DisplayName: "MCP Gateway (non-fronted fixture)",
		Scopes: []e2e.AdminScope{
			{Name: "tool:list"},
			{Name: "tool:create"},
		},
	})

	mockBase := h.MockUpstreamURL(fbCalProviderSlug)
	h.AdminCreateBrokerProvider(e2e.CreateBrokerProviderSpec{
		Slug:        fbCalProviderSlug,
		DisplayName: "Google Calendar (mock)",
		Protocol:    "oauth",
		ConfigData: map[string]any{
			"client_id":         "mock-google-client-id",
			"client_secret_ref": "CONNECTOR_E2E_MOCK_SECRET",
			"authorize_url":     mockBase + "/authorize",
			"token_url":         mockBase + "/token",
			"response_format":   "standard",
		},
	})
	h.AdminCreateResource(e2e.CreateResourceSpec{
		Slug:               fbCalSlug,
		URI:                fbCalURI,
		BackendKind:        "broker",
		BrokerProviderSlug: fbCalProviderSlug,
		DisplayName:        "Google Calendar (non-fronted fixture)",
		Scopes: []e2e.AdminScope{
			{Name: "readonly", Upstream: "calendar.readonly"},
			{Name: "events", Upstream: "calendar.events"},
		},
		Policy: &e2e.AdminPolicy{
			Exchange: e2e.AdminExchangePolicy{
				AllowedClientIDs: []string{agentClient},
			},
		},
	})

	// NOTE: NO AdminCreateFrontingLink call — this is the non-fronted
	// repro condition (operator forgot the fronting_links row).

	return fanoutBrokerFixture{h: h, gwClient: gwClient, agentClient: agentClient, agentSecret: agentSecret}
}
