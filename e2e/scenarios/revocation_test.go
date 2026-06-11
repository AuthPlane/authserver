//go:build e2e

package scenarios

import (
	"net/http"
	"testing"

	"github.com/authplane/authserver/e2e"
	"github.com/authplane/authserver/internal/config"
)

func TestRevocation(t *testing.T) {
	scopes := []string{"tools/echo"}
	h, servers := e2e.SetupE2E(t, e2e.HarnessConfig{}, scopes)
	rs := servers[0]

	h.CreateUser("revoke@example.com", "pass123")
	h.RegisterScope(rs.URI, "tools/echo", "Echo tool")

	redirectURI := "http://localhost:9999/callback"
	clientID := e2e.RegisterClientViaHarness(t, h, redirectURI)
	client := e2e.NewMCPClient(t, h, rs, clientID, redirectURI)

	// Get tokens.
	tokens := client.FullFlow("revoke@example.com", "pass123", "tools/echo", false)

	// Revoke the refresh token.
	status := h.RevokeToken(tokens.RefreshToken, clientID)
	if status != http.StatusOK {
		t.Fatalf("revoke: expected 200, got %d", status)
	}

	// Try to refresh → should fail.
	oe := h.RefreshTokenExpectError(tokens.RefreshToken, clientID)
	if oe.Error != "invalid_grant" {
		t.Fatalf("expected invalid_grant after revocation, got %q", oe.Error)
	}
}

func TestRevocationAlwaysReturns200(t *testing.T) {
	h := e2e.NewTestHarness(t, e2e.HarnessConfig{
		Resources: []config.ResourceConfigUnified{
			{Slug: "test-mcp", URI: "http://localhost:9999", BackendKind: "mint", DisplayName: "test-mcp", Scopes: []config.ScopeConfig{{Name: "tools/echo"}}},
		},
	})

	redirectURI := "http://localhost:9999/callback"
	clientID := e2e.RegisterClientViaHarness(t, h, redirectURI)

	// Revoke a completely bogus token — should still return 200 per RFC 7009.
	status := h.RevokeToken("totally-invalid-token", clientID)
	if status != http.StatusOK {
		t.Fatalf("revoke bogus token: expected 200, got %d", status)
	}
}
