//go:build e2e

package scenarios

import (
	"testing"

	"github.com/authplane/authserver/e2e"
)

func TestUserDisable_InvalidatesTokens(t *testing.T) {
	scopes := []string{"tools/echo"}
	h, servers := e2e.SetupE2E(t, e2e.HarnessConfig{}, scopes)
	rs := servers[0]

	userID := h.CreateUser("disable@example.com", "pass123")
	h.RegisterScope(rs.URI, "tools/echo", "Echo tool")

	redirectURI := "http://localhost:9999/callback"
	clientID := e2e.RegisterClientViaHarness(t, h, redirectURI)
	client := e2e.NewMCPClient(t, h, rs, clientID, redirectURI)

	tokens := client.FullFlow("disable@example.com", "pass123", "tools/echo", false)

	// Verify introspection shows active before disable.
	ir := h.IntrospectToken(tokens.AccessToken, clientID)
	if !ir.Active {
		t.Fatal("expected active=true before user disable")
	}

	// Disable the user.
	h.DisableUser(userID)

	// Introspection should return inactive for disabled user.
	ir = h.IntrospectToken(tokens.AccessToken, clientID)
	if ir.Active {
		t.Fatal("expected active=false after user disable")
	}

	// Refresh should also fail.
	oe := h.RefreshTokenExpectError(tokens.RefreshToken, clientID)
	if oe.Error != "invalid_grant" {
		t.Errorf("expected invalid_grant error after user disable, got %q", oe.Error)
	}
}
