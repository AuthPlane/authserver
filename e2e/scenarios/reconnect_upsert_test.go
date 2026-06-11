//go:build e2e

package scenarios

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/authplane/authserver/e2e"
)

// TestReConnectUpsert_AP319 is the regression test for a second
// /connect dance for an already-bound (user, provider) used to 500 because
// the connect-callback handler used a lookup → revoke → create pattern and
// the UNIQUE (user_id, broker_provider_id) constraint covered both active
// AND soft-deleted rows.  replaced the path with a single Upsert
// (INSERT … ON CONFLICT DO UPDATE) so re-connect is a one-call no-conflict
// operation.
//
// The test exercises three scenarios in one process:
//
//  1. First connect — RunFlowConnect("github") populates a fresh
//     broker_grants row. /connections returns one entry.
//  2. Re-connect over an active grant — RunFlowConnect("github") AGAIN
//     should succeed (was 500 pre-fix). /connections still returns
//     exactly one entry, not two — the upsert overwrote the row, it
//     did not insert a sibling.
//  3. Re-connect after revoke — DELETE /connections/github soft-deletes
//     the row; RunFlowConnect("github") AGAIN must resurrect it
//     (revoked_at cleared, version bumped) and /connections must show
//     it back.
//
// Stays Gate-0 clean: no internal/* imports, drives the public surface
// only via the harness Admin* + RunFlow* helpers.
func TestReConnectUpsert_AP319(t *testing.T) {
	scopes := []string{"tools/echo"}
	h, _ := e2e.SetupE2E(t, e2e.HarnessConfig{
		EnableAdminAPI:             true,
		EnableTokenExchange:        true,
		TokenExchangeMaxChainDepth: 5,
		Connectors: []e2e.ConnectorConfig{
			// brokerproto/oauth requires a refresh_token in the upstream
			// response — same constraint connect_flow_test.go honours.
			{Service: "github", Scopes: []string{"repo"}, AccessToken: "gho_reconnect", RefreshToken: "ghr_reconnect", ExpiresIn: 3600},
		},
	}, scopes)

	mockBase := h.MockUpstreamURL("github")
	h.AdminCreateBrokerProvider(e2e.CreateBrokerProviderSpec{
		Slug:        "github",
		DisplayName: "github",
		Protocol:    "oauth",
		ConfigData: map[string]any{
			"client_id":         "mock-client-id",
			"client_secret_env": "CONNECTOR_E2E_MOCK_SECRET",
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

	const email = "ap319-reconnect@example.com"
	const password = "pass123"
	h.CreateUser(email, password)

	// 1. First connect.
	h.RunFlowConnect(email, password, "github")
	if got := connectionsCount(t, h, email, password); got != 1 {
		t.Fatalf("after first connect: /connections has %d entries, want 1", got)
	}

	// 2. Re-connect over active grant. Pre- this 500'd because the
	//    UNIQUE (user_id, broker_provider_id) constraint blocked the
	//    INSERT inside CompleteConnect.
	h.RunFlowConnect(email, password, "github")
	if got := connectionsCount(t, h, email, password); got != 1 {
		t.Fatalf("after re-connect over active: /connections has %d entries, want 1 (upsert, not insert)", got)
	}

	// 3. Re-connect after revoke must resurrect the soft-deleted row.
	disconnect(t, h, email, password, "github")
	if got := connectionsCount(t, h, email, password); got != 0 {
		t.Fatalf("after disconnect: /connections has %d entries, want 0", got)
	}
	h.RunFlowConnect(email, password, "github")
	if got := connectionsCount(t, h, email, password); got != 1 {
		t.Fatalf("after re-connect post-revoke: /connections has %d entries, want 1 (resurrected row)", got)
	}
}

// connectionsCount logs in fresh and counts the user's /connections list.
// Uses a new http.Client so we never reuse a prior session's cookie jar.
func connectionsCount(t *testing.T, h *e2e.TestHarness, email, password string) int {
	t.Helper()
	client := h.NewClient()
	h.Login(client, email, password, "")
	resp, err := client.Get(h.Issuer + "/connections")
	if err != nil {
		t.Fatalf("GET /connections: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("/connections status = %d, want 200", resp.StatusCode)
	}
	var entries []map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&entries); err != nil {
		t.Fatalf("decode /connections: %v", err)
	}
	return len(entries)
}

// disconnect issues DELETE /connections/{provider} as the logged-in user.
func disconnect(t *testing.T, h *e2e.TestHarness, email, password, providerSlug string) {
	t.Helper()
	client := h.NewClient()
	h.Login(client, email, password, "")
	req, _ := http.NewRequest(http.MethodDelete, h.Issuer+"/connections/"+providerSlug, nil)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("DELETE /connections/%s: %v", providerSlug, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("DELETE /connections/%s: status = %d, want 204", providerSlug, resp.StatusCode)
	}
}
