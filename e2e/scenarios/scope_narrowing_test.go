//go:build e2e

package scenarios

import (
	"testing"

	"github.com/authplane/authserver/e2e"
)

func TestScopeNarrowingOnRefresh(t *testing.T) {
	scopes := []string{"tools/echo", "tools/db_query"}
	h, servers := e2e.SetupE2E(t, e2e.HarnessConfig{}, scopes)
	rs := servers[0]

	h.CreateUser("scope@example.com", "pass123")
	h.RegisterScope(rs.URI, "tools/echo", "Echo tool")
	h.RegisterScope(rs.URI, "tools/db_query", "DB query tool")

	redirectURI := "http://localhost:9999/callback"
	clientID := e2e.RegisterClientViaHarness(t, h, redirectURI)
	client := e2e.NewMCPClient(t, h, rs, clientID, redirectURI)

	// Get tokens with both scopes.
	tokens := client.FullFlow("scope@example.com", "pass123", "tools/echo tools/db_query", false)

	// Narrow scope on refresh to just tools/echo.
	narrowed := h.RefreshTokenWithScope(tokens.RefreshToken, clientID, "tools/echo")
	if narrowed.Scope != "tools/echo" {
		t.Errorf("narrowed scope: got %q, want %q", narrowed.Scope, "tools/echo")
	}

	// Verify narrowed token has correct scope via introspection.
	ir := h.IntrospectToken(narrowed.AccessToken, clientID)
	if !ir.Active {
		t.Fatal("narrowed token should be active")
	}
	if ir.Scope != "tools/echo" {
		t.Errorf("introspect scope: got %q, want %q", ir.Scope, "tools/echo")
	}

	// Attempt to widen scope beyond original — should fail.
	oe := h.RefreshTokenWithScopeExpectError(narrowed.RefreshToken, clientID, "tools/echo tools/admin")
	if oe.Error != "invalid_scope" {
		t.Errorf("expected invalid_scope for widened scope, got %q", oe.Error)
	}
}
