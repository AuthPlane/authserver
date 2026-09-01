//go:build e2e

package scenarios

import (
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/authplane/authserver/e2e"
)

// When /connect/{provider} omits ?resource= and the provider has
// multiple Broker-backed resources, the AS must reject with 400 rather
// than silently picking one. The picked resource governs both the
// return-URL allowlist and the upstream scope catalog, so a silent pick
// is a security/policy hazard.
//
// The test seeds two Broker resources backed by the same provider via
// the public admin API and confirms /connect/<provider> with no
// ?resource= returns 400.
func TestConnect_AmbiguousBrokerResource_RequiresExplicitResource(t *testing.T) {
	scopes := []string{"tools/echo"}
	h, _ := e2e.SetupE2E(t, e2e.HarnessConfig{
		EnableAdminAPI: true,
		Connectors: []e2e.ConnectorConfig{
			{Service: "github", Scopes: []string{"repo"}, AccessToken: "gho_mock", RefreshToken: "ghr_mock", ExpiresIn: 3600},
		},
	}, scopes)

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

	// Two Broker resources backed by the same provider — the silent
	// rows[0] anchor pick is exactly the hazard this test pins.
	h.AdminCreateResource(e2e.CreateResourceSpec{
		Slug:               "github-repo",
		URI:                "https://github-repo.test",
		BackendKind:        "broker",
		BrokerProviderSlug: "github",
		DisplayName:        "github-repo",
		Scopes:             []e2e.AdminScope{{Name: "repo", Upstream: "repo"}},
	})
	h.AdminCreateResource(e2e.CreateResourceSpec{
		Slug:               "github-issues",
		URI:                "https://github-issues.test",
		BackendKind:        "broker",
		BrokerProviderSlug: "github",
		DisplayName:        "github-issues",
		Scopes:             []e2e.AdminScope{{Name: "issues", Upstream: "issues"}},
	})

	h.CreateUser("connect-ambig@example.com", "pass123")
	httpClient := h.NewClient()
	h.Login(httpClient, "connect-ambig@example.com", "pass123", "")

	returnURL := h.Issuer + "/connections"

	// Without ?resource= → 400 (ambiguous).
	resp, err := httpClient.Get(h.Issuer + "/connect/github?return_url=" + url.QueryEscape(returnURL))
	if err != nil {
		t.Fatalf("GET /connect/github (no resource): %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected 400, got %d; body=%s", resp.StatusCode, body)
	}
	body, _ := io.ReadAll(resp.Body)
	// Assert the actionable hint from ErrAmbiguousBrokerResource reaches
	// the wire — "resource" alone matches too many error envelopes.
	if !strings.Contains(string(body), "specify ?resource=") {
		t.Errorf("error body should tell the caller to specify ?resource=: %s", body)
	}
	if !strings.Contains(string(body), "broker-backed resources") {
		t.Errorf("error body should explain why (multiple broker-backed resources): %s", body)
	}

	// With ?resource=github-repo → 302 to upstream authorize URL.
	resp2, err := httpClient.Get(h.Issuer + "/connect/github?resource=github-repo&return_url=" + url.QueryEscape(returnURL))
	if err != nil {
		t.Fatalf("GET /connect/github?resource=github-repo: %v", err)
	}
	defer resp2.Body.Close()
	if resp2.StatusCode != http.StatusFound {
		body, _ := io.ReadAll(resp2.Body)
		t.Fatalf("expected 302, got %d; body=%s", resp2.StatusCode, body)
	}
	loc := resp2.Header.Get("Location")
	if !strings.Contains(loc, "/authorize") {
		t.Fatalf("Location = %q, want upstream /authorize URL", loc)
	}
	// Regression guard: the named resource's scope drives the upstream
	// scope param, not some other resource's catalog.
	if !strings.Contains(loc, "scope=repo") {
		t.Errorf("upstream scope should be 'repo' (from github-repo resource): %s", loc)
	}
}
