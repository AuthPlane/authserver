//go:build e2e

package scenarios

import (
	"net/url"
	"testing"

	"github.com/authplane/authserver/e2e"
	"github.com/authplane/authserver/internal/crypto"
)

func TestPKCE_S256Works(t *testing.T) {
	h, rs := setupPKCEHarness(t)
	h.CreateUser("pkce@example.com", "pass123")
	h.RegisterScope(rs.URI, "tools/echo", "Echo tool")

	redirectURI := "http://localhost:9999/callback"
	clientID := e2e.RegisterClientViaHarness(t, h, redirectURI)
	client := e2e.NewMCPClient(t, h, rs, clientID, redirectURI)

	// Full flow with valid S256 PKCE.
	tokens := client.FullFlow("pkce@example.com", "pass123", "tools/echo", false)
	if tokens.AccessToken == "" {
		t.Fatal("expected access token with valid S256 PKCE")
	}
}

func TestPKCE_MissingChallenge(t *testing.T) {
	h, rs := setupPKCEHarness(t)
	h.CreateUser("pkce@example.com", "pass123")

	redirectURI := "http://localhost:9999/callback"
	clientID := e2e.RegisterClientViaHarness(t, h, redirectURI)

	httpClient := h.NewClient()

	// Authorize without code_challenge — should get an error.
	params := url.Values{
		"response_type": {"code"},
		"client_id":     {clientID},
		"redirect_uri":  {redirectURI},
		"scope":         {"tools/echo"},
		"resource":      {rs.URI},
		"state":         {"test"},
	}

	result := h.Authorize(httpClient, params)
	if result.Error == "" {
		t.Fatal("expected error for missing code_challenge")
	}
}

func TestPKCE_PlainRejected(t *testing.T) {
	h, rs := setupPKCEHarness(t)
	h.CreateUser("pkce@example.com", "pass123")

	redirectURI := "http://localhost:9999/callback"
	clientID := e2e.RegisterClientViaHarness(t, h, redirectURI)

	httpClient := h.NewClient()

	// Authorize with code_challenge_method=plain — should get an error.
	verifier := crypto.GenerateVerifier()
	params := url.Values{
		"response_type":         {"code"},
		"client_id":             {clientID},
		"redirect_uri":          {redirectURI},
		"scope":                 {"tools/echo"},
		"resource":              {rs.URI},
		"code_challenge":        {verifier},
		"code_challenge_method": {"plain"},
		"state":                 {"test"},
	}

	result := h.Authorize(httpClient, params)
	if result.Error == "" {
		t.Fatal("expected error for plain code_challenge_method")
	}
}

func TestPKCE_WrongVerifier(t *testing.T) {
	h, rs := setupPKCEHarness(t)
	h.CreateUser("pkce@example.com", "pass123")
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

	// Start flow: login first.
	result := h.Authorize(httpClient, params)
	if !result.NeedsLogin {
		t.Fatal("expected login redirect")
	}
	loginRedirect := extractRedirect(result.Location)
	h.Login(httpClient, "pkce@example.com", "pass123", loginRedirect)

	// Re-authorize.
	result = h.Authorize(httpClient, params)
	if !result.NeedsConsent {
		t.Fatal("expected consent redirect")
	}

	// Grant consent.
	code := h.GrantConsent(httpClient, result.SessionID, []string{"tools/echo"}, false)

	// Exchange with WRONG verifier.
	wrongVerifier := crypto.GenerateVerifier()
	oe := h.ExchangeCodeExpectError(code, wrongVerifier, clientID, redirectURI)
	if oe.Error != "invalid_grant" {
		t.Fatalf("expected invalid_grant, got %q", oe.Error)
	}
}

func setupPKCEHarness(t *testing.T) (*e2e.TestHarness, *e2e.MCPResourceServer) {
	t.Helper()
	scopes := []string{"tools/echo"}
	h, servers := e2e.SetupE2E(t, e2e.HarnessConfig{}, scopes)
	return h, servers[0]
}

func extractRedirect(location string) string {
	u, err := url.Parse(location)
	if err != nil {
		return ""
	}
	return u.Query().Get("redirect")
}
