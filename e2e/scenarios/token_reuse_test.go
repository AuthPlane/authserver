//go:build e2e

package scenarios

import (
	"testing"

	"github.com/authplane/authserver/e2e"
)

func TestTokenReuseDetection(t *testing.T) {
	scopes := []string{"tools/echo"}
	h, servers := e2e.SetupE2E(t, e2e.HarnessConfig{}, scopes)
	rs := servers[0]

	h.CreateUser("reuse@example.com", "pass123")
	h.RegisterScope(rs.URI, "tools/echo", "Echo tool")

	redirectURI := "http://localhost:9999/callback"
	clientID := e2e.RegisterClientViaHarness(t, h, redirectURI)
	client := e2e.NewMCPClient(t, h, rs, clientID, redirectURI)

	// Get tokens via happy path.
	tokens1 := client.FullFlow("reuse@example.com", "pass123", "tools/echo", false)

	// Save old refresh token.
	oldRefresh := tokens1.RefreshToken

	// Refresh once to get new tokens.
	tokens2 := h.RefreshToken(oldRefresh, clientID)
	if tokens2.RefreshToken == "" {
		t.Fatal("expected new refresh token")
	}

	// Try to use the OLD (consumed) refresh token — should trigger family revocation.
	oe := h.RefreshTokenExpectError(oldRefresh, clientID)
	if oe.Error != "invalid_grant" {
		t.Fatalf("expected invalid_grant for reused token, got %q", oe.Error)
	}

	// Both old and new refresh tokens should now fail.
	oe = h.RefreshTokenExpectError(tokens2.RefreshToken, clientID)
	if oe.Error != "invalid_grant" {
		t.Fatalf("expected invalid_grant for new token after family revocation, got %q", oe.Error)
	}
}
