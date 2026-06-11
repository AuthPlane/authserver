//go:build e2e

package scenarios

import (
	"testing"

	"github.com/authplane/authserver/e2e"
)

func TestRefreshRotation(t *testing.T) {
	scopes := []string{"tools/echo"}
	h, servers := e2e.SetupE2E(t, e2e.HarnessConfig{}, scopes)
	rs := servers[0]

	h.CreateUser("refresh@example.com", "pass123")
	h.RegisterScope(rs.URI, "tools/echo", "Echo tool")

	redirectURI := "http://localhost:9999/callback"
	clientID := e2e.RegisterClientViaHarness(t, h, redirectURI)
	client := e2e.NewMCPClient(t, h, rs, clientID, redirectURI)

	// Get initial tokens.
	tokens1 := client.FullFlow("refresh@example.com", "pass123", "tools/echo", false)
	if tokens1.RefreshToken == "" {
		t.Fatal("expected refresh token")
	}

	// Refresh once → get new tokens.
	tokens2 := h.RefreshToken(tokens1.RefreshToken, clientID)
	if tokens2.AccessToken == "" {
		t.Fatal("expected new access token after refresh")
	}
	if tokens2.RefreshToken == "" {
		t.Fatal("expected new refresh token after refresh")
	}
	if tokens2.RefreshToken == tokens1.RefreshToken {
		t.Fatal("refresh token should have rotated")
	}

	// Use new refresh token → should succeed.
	tokens3 := h.RefreshToken(tokens2.RefreshToken, clientID)
	if tokens3.AccessToken == "" {
		t.Fatal("expected access token from second refresh")
	}

	// Use OLD refresh token (tokens1) → family should be revoked.
	oe := h.RefreshTokenExpectError(tokens1.RefreshToken, clientID)
	if oe.Error != "invalid_grant" {
		t.Fatalf("expected invalid_grant for old token, got %q", oe.Error)
	}

	// Now even the newer token (tokens3) should be invalid — family revoked.
	oe = h.RefreshTokenExpectError(tokens3.RefreshToken, clientID)
	if oe.Error != "invalid_grant" {
		t.Fatalf("expected invalid_grant for revoked family, got %q", oe.Error)
	}
}
