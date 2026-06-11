//go:build e2e

package scenarios

import (
	"net/http"
	"net/url"
	"testing"

	"github.com/authplane/authserver/e2e"
	"github.com/authplane/authserver/internal/crypto"
)

// TestAuthCode_Reuse_Rejected verifies that using an authorization code
// twice results in the second attempt being rejected.
// Per RFC 6749 §4.1.2, auth codes are single-use.
func TestAuthCode_Reuse_Rejected(t *testing.T) {
	scopes := []string{"tools/echo"}
	h, servers := e2e.SetupE2E(t, e2e.HarnessConfig{}, scopes)
	rs := servers[0]

	h.CreateUser("code-reuse@example.com", "pass123")
	h.RegisterScope(rs.URI, "tools/echo", "Echo tool")

	redirectURI := "http://localhost:9999/callback"
	clientID := e2e.RegisterClientViaHarness(t, h, redirectURI)

	// Manually run the OAuth flow to capture the code.
	httpClient := h.NewClient()
	verifier := crypto.GenerateVerifier()
	challenge := crypto.ComputeS256Challenge(verifier)

	params := url.Values{
		"response_type":         {"code"},
		"client_id":             {clientID},
		"redirect_uri":          {redirectURI},
		"scope":                 {"tools/echo"},
		"state":                 {"test-state"},
		"code_challenge":        {challenge},
		"code_challenge_method": {"S256"},
		"resource":              {rs.URI},
	}

	// Authorize → login → consent → get code.
	result := h.Authorize(httpClient, params)
	if result.NeedsLogin {
		loginRedirect := extractRedirectParamLifecycle(result.Location)
		h.Login(httpClient, "code-reuse@example.com", "pass123", loginRedirect)
		result = h.Authorize(httpClient, params)
	}
	if result.NeedsConsent {
		code := h.GrantConsent(httpClient, result.SessionID, []string{"tools/echo"}, false)

		// First exchange — should succeed.
		tokens := h.ExchangeCode(code, verifier, clientID, redirectURI)
		if tokens.AccessToken == "" {
			t.Fatal("first code exchange should succeed")
		}

		// Second exchange with same code — should fail.
		oe := h.ExchangeCodeExpectError(code, verifier, clientID, redirectURI)
		if oe == nil {
			t.Fatal("second code exchange should have failed")
		}
		if oe.Error != "invalid_grant" {
			t.Errorf("error: got %q, want invalid_grant", oe.Error)
		}
	} else if result.Code != "" {
		// Already consented — use this code.
		tokens := h.ExchangeCode(result.Code, verifier, clientID, redirectURI)
		if tokens.AccessToken == "" {
			t.Fatal("first code exchange should succeed")
		}

		oe := h.ExchangeCodeExpectError(result.Code, verifier, clientID, redirectURI)
		if oe == nil {
			t.Fatal("second code exchange should have failed")
		}
		if oe.Error != "invalid_grant" {
			t.Errorf("error: got %q, want invalid_grant", oe.Error)
		}
	} else {
		t.Fatal("expected consent or code in authorize result")
	}
}

func extractRedirectParamLifecycle(location string) string {
	u, err := url.Parse(location)
	if err != nil {
		return ""
	}
	return u.Query().Get("redirect")
}

// TestRefreshToken_MultipleRotations verifies that refresh tokens can be
// rotated multiple times in sequence, each producing a new access + refresh token.
func TestRefreshToken_MultipleRotations(t *testing.T) {
	scopes := []string{"tools/echo"}
	h, servers := e2e.SetupE2E(t, e2e.HarnessConfig{}, scopes)
	rs := servers[0]

	h.CreateUser("rotate-multi@example.com", "pass123")
	h.RegisterScope(rs.URI, "tools/echo", "Echo tool")

	redirectURI := "http://localhost:9999/callback"
	clientID := e2e.RegisterClientViaHarness(t, h, redirectURI)
	client := e2e.NewMCPClient(t, h, rs, clientID, redirectURI)

	tokens := client.FullFlow("rotate-multi@example.com", "pass123", "tools/echo", false)
	if tokens.RefreshToken == "" {
		t.Fatal("expected refresh_token in initial response")
	}

	// Rotate 5 times in sequence — always use the latest refresh token.
	// Note: we do NOT try reusing old tokens here (that's TestTokenReuseDetection).
	currentRefresh := tokens.RefreshToken
	for i := 0; i < 5; i++ {
		newTokens := h.RefreshToken(currentRefresh, clientID)
		if newTokens.AccessToken == "" {
			t.Fatalf("rotation %d: missing access_token", i+1)
		}
		if newTokens.RefreshToken == "" {
			t.Fatalf("rotation %d: missing refresh_token", i+1)
		}
		if newTokens.RefreshToken == currentRefresh {
			t.Fatalf("rotation %d: refresh_token was not rotated", i+1)
		}

		currentRefresh = newTokens.RefreshToken
	}

	// Final refresh token should still work.
	finalTokens := h.RefreshToken(currentRefresh, clientID)
	if finalTokens.AccessToken == "" {
		t.Fatal("final refresh should produce access_token")
	}
}

// TestRevocation_RefreshToken_Cascades_To_AccessToken verifies that revoking
// a refresh token (family revocation) also blacklists the access token JTI,
// making it inactive on introspection.
func TestRevocation_RefreshToken_Cascades_To_AccessToken(t *testing.T) {
	scopes := []string{"tools/echo"}
	h, servers := e2e.SetupE2E(t, e2e.HarnessConfig{}, scopes)
	rs := servers[0]

	h.CreateUser("revoke-at@example.com", "pass123")
	h.RegisterScope(rs.URI, "tools/echo", "Echo tool")

	redirectURI := "http://localhost:9999/callback"
	clientID := e2e.RegisterClientViaHarness(t, h, redirectURI)
	client := e2e.NewMCPClient(t, h, rs, clientID, redirectURI)

	tokens := client.FullFlow("revoke-at@example.com", "pass123", "tools/echo", false)

	// Access token should be active before revocation.
	ir := h.IntrospectToken(tokens.AccessToken, clientID)
	if !ir.Active {
		t.Fatal("access token should be active before revocation")
	}

	// Revoke the refresh token — this revokes the entire token family,
	// which blacklists all access token JTIs in that family.
	status := h.RevokeToken(tokens.RefreshToken, clientID)
	if status != http.StatusOK {
		t.Fatalf("revoke: expected 200, got %d", status)
	}

	// Access token should now be inactive (JTI blacklisted via family revocation).
	ir = h.IntrospectToken(tokens.AccessToken, clientID)
	if ir.Active {
		t.Fatal("access token should be inactive after family revocation")
	}
}

// TestRevocation_UnknownToken_Succeeds verifies that revoking a token that
// doesn't exist returns 200 OK per RFC 7009 §2.2 (no error).
func TestRevocation_UnknownToken_Succeeds(t *testing.T) {
	h, servers := e2e.SetupE2E(t, e2e.HarnessConfig{}, []string{"tools/echo"})
	rs := servers[0]

	h.RegisterScope(rs.URI, "tools/echo", "Echo tool")
	h.CreateUser("revoke-unknown@example.com", "pass123")

	redirectURI := "http://localhost:9999/callback"
	clientID := e2e.RegisterClientViaHarness(t, h, redirectURI)

	// Revoke a completely fake token — should still return 200.
	status := h.RevokeToken("this-token-does-not-exist", clientID)
	if status != http.StatusOK {
		t.Fatalf("revoking unknown token: expected 200, got %d", status)
	}
}

// TestRefreshToken_ScopeNarrowing_Cannot_Widen verifies that refreshing
// with broader scope than originally granted is rejected.
func TestRefreshToken_ScopeNarrowing_Cannot_Widen(t *testing.T) {
	scopes := []string{"tools/echo", "tools/get_time"}
	h, servers := e2e.SetupE2E(t, e2e.HarnessConfig{}, scopes)
	rs := servers[0]

	h.CreateUser("scope-widen@example.com", "pass123")
	h.RegisterScope(rs.URI, "tools/echo", "Echo tool")
	h.RegisterScope(rs.URI, "tools/get_time", "Time tool")

	redirectURI := "http://localhost:9999/callback"
	clientID := e2e.RegisterClientViaHarness(t, h, redirectURI)
	client := e2e.NewMCPClient(t, h, rs, clientID, redirectURI)

	// Get tokens with only tools/echo scope.
	tokens := client.FullFlow("scope-widen@example.com", "pass123", "tools/echo", false)

	// Try to refresh with wider scope — should fail.
	oe := h.RefreshTokenWithScopeExpectError(tokens.RefreshToken, clientID, "tools/echo tools/get_time")
	if oe == nil {
		t.Fatal("widening scope on refresh should have been rejected")
	}
	if oe.Error != "invalid_scope" {
		t.Errorf("error: got %q, want invalid_scope", oe.Error)
	}
}

// TestTokenResponse_ExpiresIn verifies that token responses include
// a valid expires_in value.
func TestTokenResponse_ExpiresIn(t *testing.T) {
	h, servers := e2e.SetupE2E(t, e2e.HarnessConfig{
		EnableClientCredentials: true,
	}, []string{"tools/echo"})
	rs := servers[0]

	h.RegisterScope(rs.URI, "tools/echo", "Echo tool")

	clientID, clientSecret := h.RegisterConfidentialClient(
		[]string{"client_credentials"},
		"tools/echo",
	)

	tr := h.ClientCredentialsExchange(clientID, clientSecret, "tools/echo", "")
	if tr.ExpiresIn <= 0 {
		t.Errorf("expires_in should be positive, got %d", tr.ExpiresIn)
	}
	// Token should expire within a reasonable range (1 minute to 24 hours).
	if tr.ExpiresIn > 86400 {
		t.Errorf("expires_in seems too large: %d seconds", tr.ExpiresIn)
	}
}
