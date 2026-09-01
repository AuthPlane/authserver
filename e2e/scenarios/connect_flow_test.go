//go:build e2e

package scenarios

import (
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/authplane/authserver/e2e"
)

// TestConnectFlow_RoundTrip exercises the full /connect/{provider} dance
// end-to-end ( §"E2E"):
//
//  1. Seed a broker_providers row + a Broker resource via the harness.
//  2. GET /connect/github?return_url=… → 302 to the mock upstream's
//     authorize endpoint.
//  3. Mock upstream redirects to /connect/github/callback?code=…&state=…
//     (the AS handler runs CompleteConnect and persists a BrokerGrant).
//  4. GET /connections returns one entry; DELETE /connections/github
//     revokes; GET /connections returns empty.
//
// Beyond regression coverage this is the load-bearing test for the
// /vault/connect/* → /connect/* route rename.
func TestConnectFlow_RoundTrip(t *testing.T) {
	scopes := []string{"tools/echo"}
	h, _ := e2e.SetupE2E(t, e2e.HarnessConfig{
		EnableAdminAPI:             true,
		EnableTokenExchange:        true,
		TokenExchangeMaxChainDepth: 5,
		Connectors: []e2e.ConnectorConfig{
			// Mock upstream that the brokerproto/oauth adapter will hit
			// for the authorize redirect + token exchange. RefreshToken is
			// required because the brokerproto/oauth adapter rejects
			// upstream responses missing a refresh_token (see adapter.go's
			// "oauth upstream did not return a refresh_token" guard).
			{Service: "github", Scopes: []string{"repo"}, AccessToken: "gho_mock", RefreshToken: "ghr_mock", ExpiresIn: 3600},
		},
	}, scopes)

	// 1. Register the broker provider + resource via the public admin API
	//. Replaces the Gate-0 shortcut (SeedConnectionResourceOnly
	// → direct brokerProviderStore.Create + resourceStore.Create). The
	// config_data wires the brokerproto/oauth adapter at the harness's
	// in-process mock upstream — without this the /connect dance below
	// would 502 on the token-exchange call.
	mockBase := h.MockUpstreamURL("github")
	configData := map[string]any{
		"client_id":         "mock-client-id",
		"client_secret_ref": "CONNECTOR_E2E_MOCK_SECRET",
		"authorize_url":     mockBase + "/authorize",
		"token_url":         mockBase + "/token",
		"response_format":   "standard",
	}
	h.AdminCreateBrokerProvider(e2e.CreateBrokerProviderSpec{
		Slug:        "github",
		DisplayName: "github",
		Protocol:    "oauth",
		ConfigData:  configData,
	})
	h.AdminCreateResource(e2e.CreateResourceSpec{
		Slug:               "github",
		URI:                "https://github.test",
		BackendKind:        "broker",
		BrokerProviderSlug: "github",
		DisplayName:        "github",
		Scopes:             []e2e.AdminScope{{Name: "repo", Upstream: "repo"}},
	})

	// 2. Authenticated client (cookie jar follows redirects so we can
	// inspect each hop).
	h.CreateUser("connect-flow@example.com", "pass123")
	httpClient := h.NewClient()
	h.Login(httpClient, "connect-flow@example.com", "pass123", "")

	// 3. Trigger StartConnect — the AS persists a pending state and
	// redirects the user to the mock upstream's /authorize.
	returnURL := h.Issuer + "/connections" // AS-self bypass per
	startResp, err := httpClient.Get(h.Issuer + "/connect/github?return_url=" + url.QueryEscape(returnURL))
	if err != nil {
		t.Fatalf("GET /connect/github: %v", err)
	}
	defer startResp.Body.Close()
	if startResp.StatusCode != http.StatusFound {
		body, _ := io.ReadAll(startResp.Body)
		t.Fatalf("StartConnect status = %d, want 302; body=%s", startResp.StatusCode, body)
	}
	upstreamLoc := startResp.Header.Get("Location")
	if upstreamLoc == "" || !strings.Contains(upstreamLoc, "/authorize") {
		t.Fatalf("Location header = %q, want mock-upstream authorize URL", upstreamLoc)
	}

	// RFC 6749 §4.1.3: redirect_uri sent on the authorize URL must equal the
	// AS's per-provider callback URL. Defense-in-depth e2e assertion that
	// the value reaches the upstream over the wire — not just the adapter.
	wantCallback := h.Issuer + "/connect/github/callback"
	if !strings.Contains(upstreamLoc, "redirect_uri="+url.QueryEscape(wantCallback)) {
		t.Errorf("authorize Location does not carry redirect_uri=%q: %s", wantCallback, upstreamLoc)
	}

	// 4. The mock upstream's /authorize redirects back to the AS's
	// /connect/github/callback with code=mock-auth-code&state=<state>.
	upstreamResp, err := httpClient.Get(upstreamLoc)
	if err != nil {
		t.Fatalf("GET upstream authorize: %v", err)
	}
	defer upstreamResp.Body.Close()
	if upstreamResp.StatusCode != http.StatusFound {
		t.Fatalf("upstream authorize status = %d, want 302", upstreamResp.StatusCode)
	}
	callbackLoc := upstreamResp.Header.Get("Location")
	if !strings.Contains(callbackLoc, "/connect/github/callback") {
		t.Fatalf("upstream callback Location = %q, want /connect/github/callback", callbackLoc)
	}
	if !strings.Contains(callbackLoc, "code=mock-auth-code") {
		t.Fatalf("upstream callback Location = %q missing code", callbackLoc)
	}

	// 5. Hit the AS callback URL — CompleteConnect runs, the brokerproto
	// adapter exchanges the code for a credential, and the AS persists a
	// BrokerGrant. Final 302 redirects to the original return_url.
	callbackResp, err := httpClient.Get(callbackLoc)
	if err != nil {
		t.Fatalf("GET callback: %v", err)
	}
	defer callbackResp.Body.Close()
	if callbackResp.StatusCode != http.StatusFound {
		body, _ := io.ReadAll(callbackResp.Body)
		t.Fatalf("callback status = %d, want 302; body=%s", callbackResp.StatusCode, body)
	}
	if got := callbackResp.Header.Get("Location"); got != returnURL {
		t.Errorf("post-callback Location = %q, want %q", got, returnURL)
	}

	// RFC 6749 §4.1.3 end-to-end check: the redirect_uri sent at the
	// upstream's /authorize endpoint MUST equal the redirect_uri in the
	// /token POST body. The mock recorder lets us assert what the AS
	// actually wrote to the wire — this is the regression guard for
	// flows that pass against a permissive mock but fail against a real
	// provider that enforces RFC 6749 §4.1.3.
	authorizeReqs := h.AuthorizeRequests("github")
	if len(authorizeReqs) != 1 {
		t.Fatalf("authorize requests at upstream = %d, want 1", len(authorizeReqs))
	}
	if got := authorizeReqs[0].Get("redirect_uri"); got != wantCallback {
		t.Errorf("authorize redirect_uri = %q, want %q", got, wantCallback)
	}
	tokenReqs := h.TokenRequests("github")
	if len(tokenReqs) != 1 {
		t.Fatalf("token requests at upstream = %d, want 1", len(tokenReqs))
	}
	if got := tokenReqs[0].Get("redirect_uri"); got != wantCallback {
		t.Errorf("token-endpoint redirect_uri = %q, want %q (RFC 6749 §4.1.3 mismatch)", got, wantCallback)
	}

	// 6. GET /connections returns one entry for the github provider.
	listResp, err := httpClient.Get(h.Issuer + "/connections")
	if err != nil {
		t.Fatalf("GET /connections: %v", err)
	}
	defer listResp.Body.Close()
	if listResp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(listResp.Body)
		t.Fatalf("/connections list status = %d, want 200; body=%s", listResp.StatusCode, body)
	}
	var listed []map[string]any
	if err := json.NewDecoder(listResp.Body).Decode(&listed); err != nil {
		t.Fatalf("decode /connections: %v", err)
	}
	if len(listed) != 1 {
		t.Fatalf("/connections returned %d entries, want 1: %v", len(listed), listed)
	}
	if got, _ := listed[0]["provider"].(string); got != "github" {
		t.Errorf("connection provider = %q, want github", got)
	}

	// 7. DELETE /connections/github revokes; subsequent list is empty.
	delReq, _ := http.NewRequest(http.MethodDelete, h.Issuer+"/connections/github", nil)
	delResp, err := httpClient.Do(delReq)
	if err != nil {
		t.Fatalf("DELETE /connections/github: %v", err)
	}
	delResp.Body.Close()
	if delResp.StatusCode != http.StatusNoContent {
		t.Fatalf("DELETE status = %d, want 204", delResp.StatusCode)
	}

	listResp2, err := httpClient.Get(h.Issuer + "/connections")
	if err != nil {
		t.Fatalf("GET /connections (post-delete): %v", err)
	}
	defer listResp2.Body.Close()
	var listed2 []map[string]any
	if err := json.NewDecoder(listResp2.Body).Decode(&listed2); err != nil {
		t.Fatalf("decode /connections (post-delete): %v", err)
	}
	if len(listed2) != 0 {
		t.Errorf("/connections after revoke returned %d entries, want 0: %v", len(listed2), listed2)
	}
}

// TestConnectFlow_LegacyRoutesReturn404 pins 's route rename: the old
// /vault/connect/{service} path no longer resolves.
func TestConnectFlow_LegacyRoutesReturn404(t *testing.T) {
	h, _ := e2e.SetupE2E(t, e2e.HarnessConfig{
		EnableTokenExchange:        true,
		TokenExchangeMaxChainDepth: 5,
		Connectors: []e2e.ConnectorConfig{
			{Service: "github", Scopes: []string{"repo"}, AccessToken: "gho_mock"},
		},
	}, []string{"tools/echo"})

	for _, p := range []string{
		"/vault/connect/github",
		"/vault/callback/github",
		"/vault/connections",
		"/vault/connections/github",
	} {
		resp, err := http.Get(h.Issuer + p)
		if err != nil {
			t.Fatalf("GET %s: %v", p, err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusNotFound {
			t.Errorf("legacy %s status = %d, want 404 ( retired the route)", p, resp.StatusCode)
		}
	}
}
