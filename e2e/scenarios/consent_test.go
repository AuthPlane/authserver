//go:build e2e

package scenarios

import (
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/authplane/authserver/e2e"
	"github.com/authplane/authserver/internal/crypto"
)

func TestConsent_GrantAllScopes(t *testing.T) {
	h, rs := setupConsentHarness(t)
	h.CreateUser("consent@example.com", "pass123")
	h.RegisterScope(rs.URI, "tools/echo", "Echo tool")
	h.RegisterScope(rs.URI, "tools/db_query", "DB query tool")

	redirectURI := "http://localhost:9999/callback"
	clientID := e2e.RegisterClientViaHarness(t, h, redirectURI)
	client := e2e.NewMCPClient(t, h, rs, clientID, redirectURI)

	tokens := client.FullFlow("consent@example.com", "pass123", "tools/echo tools/db_query", false)
	if tokens.AccessToken == "" {
		t.Fatal("expected access token")
	}
}

// TestConsent_ZeroScopesAllow_RejectedAsBadRequest covers the audit
// regression: submitting the consent form with action=allow but no
// "scopes" values must be treated as "you must approve at least one" —
// not as "approve every requested scope." Before the fix, the service
// silently defaulted to the full session scope.
func TestConsent_ZeroScopesAllow_RejectedAsBadRequest(t *testing.T) {
	h, rs := setupConsentHarness(t)
	h.CreateUser("zero@example.com", "pass123")
	h.RegisterScope(rs.URI, "tools/echo", "Echo tool")
	h.RegisterScope(rs.URI, "tools/admin", "Admin tool")

	redirectURI := "http://localhost:9999/callback"
	clientID := e2e.RegisterClientViaHarness(t, h, redirectURI)

	httpClient := h.NewClient()
	verifier := crypto.GenerateVerifier()
	challenge := crypto.ComputeS256Challenge(verifier)

	params := url.Values{
		"response_type":         {"code"},
		"client_id":             {clientID},
		"redirect_uri":          {redirectURI},
		"scope":                 {"tools/echo tools/admin"},
		"resource":              {rs.URI},
		"code_challenge":        {challenge},
		"code_challenge_method": {"S256"},
		"state":                 {"test"},
	}

	result := h.Authorize(httpClient, params)
	if !result.NeedsLogin {
		t.Fatal("expected login redirect")
	}
	loginRedirect := extractRedirectParam(result.Location)
	h.Login(httpClient, "zero@example.com", "pass123", loginRedirect)

	result = h.Authorize(httpClient, params)
	if !result.NeedsConsent {
		t.Fatal("expected consent redirect")
	}

	// POST consent with action=allow but NO scope values. Pre-fix this
	// silently approved both scopes and returned a 303 with a code; the
	// fixed behavior is 400 with the "No Permissions Selected" page.
	resp := h.PostConsentRaw(httpClient, result.SessionID, nil)
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected 400 for zero-scope allow, got %d, body: %s", resp.StatusCode, string(body))
	}
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "No Permissions Selected") {
		t.Errorf("response body missing the expected error title; got: %s", string(body))
	}

	// And no auth code was issued: a second authorize should still need
	// consent (the form rejection did not consume the session).
	result = h.Authorize(httpClient, params)
	if !result.NeedsConsent {
		if result.Code != "" {
			t.Fatalf("zero-scope allow must not produce an auth code, got: %q", result.Code)
		}
	}
}

func TestConsent_DenyConsent(t *testing.T) {
	h, rs := setupConsentHarness(t)
	h.CreateUser("deny@example.com", "pass123")
	h.RegisterScope(rs.URI, "tools/echo", "Echo tool")

	redirectURI := "http://localhost:9999/callback"
	clientID := e2e.RegisterClientViaHarness(t, h, redirectURI)

	httpClient := h.NewClient()
	verifier := crypto.GenerateVerifier()
	challenge := crypto.ComputeS256Challenge(verifier)

	params := url.Values{
		"response_type":         {"code"},
		"client_id":             {clientID},
		"redirect_uri":          {redirectURI},
		"scope":                 {"tools/echo"},
		"resource":              {rs.URI},
		"code_challenge":        {challenge},
		"code_challenge_method": {"S256"},
		"state":                 {"test"},
	}

	// Authorize → login redirect.
	result := h.Authorize(httpClient, params)
	if !result.NeedsLogin {
		t.Fatal("expected login redirect")
	}
	loginRedirect := extractRedirectParam(result.Location)
	h.Login(httpClient, "deny@example.com", "pass123", loginRedirect)

	// Re-authorize → consent redirect.
	result = h.Authorize(httpClient, params)
	if !result.NeedsConsent {
		t.Fatal("expected consent redirect")
	}

	// Deny consent.
	h.DenyConsent(httpClient, result.SessionID)

	// A second authorize attempt should still require consent.
	result = h.Authorize(httpClient, params)
	if !result.NeedsConsent {
		if result.Code != "" {
			t.Fatal("expected consent required after denial, but got a code")
		}
	}
}

func TestConsent_RememberSkipsConsent(t *testing.T) {
	h, rs := setupConsentHarness(t)
	h.CreateUser("remember@example.com", "pass123")
	h.RegisterScope(rs.URI, "tools/echo", "Echo tool")

	redirectURI := "http://localhost:9999/callback"
	clientID := e2e.RegisterClientViaHarness(t, h, redirectURI)

	httpClient := h.NewClient()
	verifier := crypto.GenerateVerifier()
	challenge := crypto.ComputeS256Challenge(verifier)

	params := url.Values{
		"response_type":         {"code"},
		"client_id":             {clientID},
		"redirect_uri":          {redirectURI},
		"scope":                 {"tools/echo"},
		"resource":              {rs.URI},
		"code_challenge":        {challenge},
		"code_challenge_method": {"S256"},
		"state":                 {"test"},
	}

	// First flow: login + consent with remember.
	result := h.Authorize(httpClient, params)
	if !result.NeedsLogin {
		t.Fatal("expected login redirect")
	}
	loginRedirect := extractRedirectParam(result.Location)
	h.Login(httpClient, "remember@example.com", "pass123", loginRedirect)

	result = h.Authorize(httpClient, params)
	if !result.NeedsConsent {
		t.Fatal("expected consent redirect on first flow")
	}

	scopes := strings.Fields("tools/echo")
	code := h.GrantConsent(httpClient, result.SessionID, scopes, true) // remember=true
	if code == "" {
		t.Fatal("expected auth code")
	}

	// Exchange the code to complete the first flow.
	tokens := h.ExchangeCode(code, verifier, clientID, redirectURI)
	if tokens.AccessToken == "" {
		t.Fatal("expected access token")
	}

	// Second flow: should skip consent (remembered).
	verifier2 := crypto.GenerateVerifier()
	challenge2 := crypto.ComputeS256Challenge(verifier2)
	params.Set("code_challenge", challenge2)

	result = h.Authorize(httpClient, params)
	// Should get a code directly without consent.
	if result.NeedsConsent {
		t.Fatal("expected consent to be skipped due to remember")
	}
	if result.Code == "" {
		t.Fatalf("expected auth code from remembered consent, got: %+v", result)
	}

	// Exchange the code.
	tokens2 := h.ExchangeCode(result.Code, verifier2, clientID, redirectURI)
	if tokens2.AccessToken == "" {
		t.Fatal("expected access token from remembered consent flow")
	}
}

func setupConsentHarness(t *testing.T) (*e2e.TestHarness, *e2e.MCPResourceServer) {
	t.Helper()
	scopes := []string{"tools/echo", "tools/db_query"}
	h, servers := e2e.SetupE2E(t, e2e.HarnessConfig{}, scopes)
	return h, servers[0]
}

func extractRedirectParam(location string) string {
	u, err := url.Parse(location)
	if err != nil {
		return ""
	}
	return u.Query().Get("redirect")
}
