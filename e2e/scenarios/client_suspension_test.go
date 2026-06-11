//go:build e2e

package scenarios

import (
	"net/http"
	"testing"

	"github.com/authplane/authserver/e2e"
)

func TestClientSuspension_InvalidatesTokens(t *testing.T) {
	scopes := []string{"tools/echo"}
	h, servers := e2e.SetupE2E(t, e2e.HarnessConfig{}, scopes)
	rs := servers[0]

	h.CreateUser("suspend@example.com", "pass123")
	h.RegisterScope(rs.URI, "tools/echo", "Echo tool")

	redirectURI := "http://localhost:9999/callback"
	clientID := e2e.RegisterClientViaHarness(t, h, redirectURI)
	client := e2e.NewMCPClient(t, h, rs, clientID, redirectURI)

	tokens := client.FullFlow("suspend@example.com", "pass123", "tools/echo", false)

	// Verify token works before suspension.
	status, _ := client.CallTool("/tools/echo", tokens.AccessToken, `"test"`)
	if status != http.StatusOK {
		t.Fatalf("tool call before suspend: expected 200, got %d", status)
	}

	// Suspend the client.
	h.SuspendClient(clientID)

	// Introspection should return inactive for suspended client.
	// Note: we use a different client for introspection since the suspended
	// client can't authenticate. For public clients, form-body client_id is used.
	ir := h.IntrospectToken(tokens.AccessToken, clientID)
	if ir.Active {
		t.Fatal("expected active=false after client suspension")
	}

	// Refresh should also fail (client is suspended → returns invalid_client).
	oe := h.RefreshTokenExpectError(tokens.RefreshToken, clientID)
	if oe.Error != "invalid_client" {
		t.Errorf("expected invalid_client error after suspension, got %q", oe.Error)
	}
}
