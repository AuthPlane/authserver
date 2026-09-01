//go:build e2e

package scenarios

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/authplane/authserver/e2e"
)

// TestRunFlowConnect_Smoke is the wiring smoke test for the
// RunFlowConnect helper introduced under the  fan-out.
// RunFlowConnect drives the /connect/{provider} dance against the
// harness's mock upstream so consuming tests can replace
// h.SeedConnection (Gate-0 shortcut, ) with a single call that
// produces a BrokerGrant via the public surface.
//
// The smoke test asserts the post-condition the helper guarantees:
// after RunFlowConnect returns, GET /connections includes one entry
// for the provider — meaning the BrokerGrant was persisted via the
// real /connect/{provider} → mock-upstream → callback dance, not via
// a direct store write.
//
// This is the reference template the remaining sub-tasks should
// pattern-match for SeedConnection / SeedAgentAttestation migrations.
func TestRunFlowConnect_Smoke(t *testing.T) {
	scopes := []string{"tools/echo"}
	h, _ := e2e.SetupE2E(t, e2e.HarnessConfig{
		EnableAdminAPI:             true,
		EnableTokenExchange:        true,
		TokenExchangeMaxChainDepth: 5,
		Connectors: []e2e.ConnectorConfig{
			// RefreshToken is required by the brokerproto/oauth adapter
			// (rejects upstream responses missing one) — same constraint
			// connect_flow_test.go honours.
			{Service: "github", Scopes: []string{"repo"}, AccessToken: "gho_runflow_smoke", RefreshToken: "ghr_runflow_smoke", ExpiresIn: 3600},
		},
	}, scopes)

	// Register the provider + Broker resource through the public admin
	// API. Same shape as connect_flow_test.go (the canonical
	// migration) so this smoke also documents the full setup path.
	mockBase := h.MockUpstreamURL("github")
	h.AdminCreateBrokerProvider(e2e.CreateBrokerProviderSpec{
		Slug:        "github",
		DisplayName: "github",
		Protocol:    "oauth",
		ConfigData: map[string]any{
			"client_id":         "mock-client-id",
			"client_secret_ref": "CONNECTOR_E2E_MOCK_SECRET",
			"authorize_url":     mockBase + "/authorize",
			"token_url":         mockBase + "/token",
			"response_format":   "standard",
		},
	})
	h.AdminCreateResource(e2e.CreateResourceSpec{
		Slug:               "github",
		URI:                "https://github.test",
		BackendKind:        "broker",
		BrokerProviderSlug: "github",
		DisplayName:        "github",
		Scopes:             []e2e.AdminScope{{Name: "repo", Upstream: "repo"}},
	})

	const email = "runflow-connect@example.com"
	const password = "pass123"
	h.CreateUser(email, password)

	// One call replaces the entire SeedConnection shortcut: drives login
	// + /connect dance + mock upstream callback + BrokerGrant persistence
	// through the public surface.
	h.RunFlowConnect(email, password, "github")

	// Post-condition: the BrokerGrant is observable via /connections,
	// the same endpoint an operator would hit. We re-login with a fresh
	// http.Client to prove the grant survives independent of the dance's
	// session.
	httpClient := h.NewClient()
	h.Login(httpClient, email, password, "")
	resp, err := httpClient.Get(h.Issuer + "/connections")
	if err != nil {
		t.Fatalf("GET /connections: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("/connections status %d, want 200", resp.StatusCode)
	}
	var connections []map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&connections); err != nil {
		t.Fatalf("decode /connections: %v", err)
	}
	if len(connections) != 1 {
		t.Fatalf("/connections returned %d entries, want 1: %v", len(connections), connections)
	}
	if got, _ := connections[0]["provider"].(string); got != "github" {
		t.Errorf("connection provider = %q, want %q", got, "github")
	}
}
