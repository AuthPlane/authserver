//go:build e2e

package scenarios

import (
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/authplane/authserver/e2e"
)

// TestStaleSession_ConnectRejected reproduces a session cookie that
// is HMAC-valid but references a deleted user must NOT reach a handler that
// inserts a row keyed on user_id (e.g., broker_grants), which would 500 on
// the FK constraint.
//
// Repro shape (matches the demo failure: docker compose down -v + setup-as.sh
// re-issues a fresh user table while the operator's browser still holds the
// old cookie):
//
//  1. Create user, log in, capture the session cookie.
//  2. Hard-delete the user (force=true).
//  3. GET /connect/<provider> with the stale cookie still attached.
//  4. Expect a redirect to /login (no userID on context → handler 302s),
//     NOT a 500 with FK details. Set-Cookie clears the stale cookie.
func TestStaleSession_ConnectRejected(t *testing.T) {
	scopes := []string{"tools/echo"}
	h, _ := e2e.SetupE2E(t, e2e.HarnessConfig{
		EnableAdminAPI: true,
		Connectors: []e2e.ConnectorConfig{
			{Service: "github", Scopes: []string{"repo"}, AccessToken: "gho_mock", RefreshToken: "ghr_mock", ExpiresIn: 3600},
		},
	}, scopes)

	// Wire the broker provider + resource so /connect/github is a real route
	// (matches connect_flow_test.go). Without this the request would 400 on
	// "unknown provider", which would mask the FK regression we are guarding.
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

	// 1. Create user, log in, capture the session cookie.
	userID := h.CreateUser("stale@example.com", "pass123")
	httpClient := h.NewClient()
	h.Login(httpClient, "stale@example.com", "pass123", "")
	sessionCookie := h.GetSessionCookie(httpClient)
	if sessionCookie == "" {
		t.Fatal("no session cookie after login")
	}

	// 2. Hard-delete the user. force=true revokes the token family the
	// Login flow created so DeleteUser doesn't fail with ErrUserHasActiveTokens.
	h.DeleteUser(userID, true)

	// 3. GET /connect/github with the stale cookie still attached. Use a
	// clean client (no jar) so we can inspect the response without the jar
	// silently dropping the cleared cookie before the test reads it.
	returnURL := h.Issuer + "/connections"
	req, err := http.NewRequest(http.MethodGet,
		h.Issuer+"/connect/github?return_url="+url.QueryEscape(returnURL), nil)
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	req.AddCookie(&http.Cookie{Name: "authserver_session", Value: sessionCookie})

	bareClient := &http.Client{
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	resp, err := bareClient.Do(req)
	if err != nil {
		t.Fatalf("GET /connect/github: %v", err)
	}
	defer resp.Body.Close()

	// 4a. The connect handler redirects to /login when no userID is on the
	// context — which is exactly what SessionMiddleware should produce after
	// dropping the stale cookie. Anything 5xx (especially 500 from the
	// broker_grants FK) is the regression we are guarding.
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("status = %d, want 302 redirect-to-login (stale-session reject). "+
			"A 5xx here is the regression: cookie reached a handler that "+
			"writes user_id and tripped the FK constraint.", resp.StatusCode)
	}
	loc := resp.Header.Get("Location")
	if !strings.HasPrefix(loc, "/login") {
		t.Errorf("Location = %q, want /login… (stale session should bounce to login)", loc)
	}

	// 4b. Set-Cookie must clear the session cookie (MaxAge < 0).
	var cleared bool
	for _, c := range resp.Cookies() {
		if c.Name == "authserver_session" && c.Value == "" && c.MaxAge < 0 {
			cleared = true
			break
		}
	}
	if !cleared {
		t.Errorf("Set-Cookie did not clear the stale session cookie; got %v", resp.Cookies())
	}
}
