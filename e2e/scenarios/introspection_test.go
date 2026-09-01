//go:build e2e

package scenarios

import (
	"net/http"
	"testing"

	"github.com/authplane/authserver/e2e"
)

func TestIntrospection_ActiveToken(t *testing.T) {
	scopes := []string{"tools/echo"}
	h, servers := e2e.SetupE2E(t, e2e.HarnessConfig{}, scopes)
	rs := servers[0]

	h.CreateUser("intro@example.com", "pass123")
	h.RegisterScope(rs.URI, "tools/echo", "Echo tool")

	redirectURI := "http://localhost:9999/callback"
	clientID := e2e.RegisterClientViaHarness(t, h, redirectURI)
	client := e2e.NewMCPClient(t, h, rs, clientID, redirectURI)

	tokens := client.FullFlow("intro@example.com", "pass123", "tools/echo", false)

	ir := h.IntrospectAsResourceServer(tokens.AccessToken, rs.URI)
	if !ir.Active {
		t.Fatal("expected active=true for valid token")
	}
	if ir.Scope != "tools/echo" {
		t.Errorf("scope: got %q, want %q", ir.Scope, "tools/echo")
	}
	if ir.TokenType != "Bearer" {
		t.Errorf("token_type: got %q, want Bearer", ir.TokenType)
	}
	if ir.Iss != h.Issuer {
		t.Errorf("iss: got %q, want %q", ir.Iss, h.Issuer)
	}
}

func TestIntrospection_RevokedToken_Inactive(t *testing.T) {
	scopes := []string{"tools/echo"}
	h, servers := e2e.SetupE2E(t, e2e.HarnessConfig{}, scopes)
	rs := servers[0]

	h.CreateUser("intro-rev@example.com", "pass123")
	h.RegisterScope(rs.URI, "tools/echo", "Echo tool")

	redirectURI := "http://localhost:9999/callback"
	clientID := e2e.RegisterClientViaHarness(t, h, redirectURI)
	client := e2e.NewMCPClient(t, h, rs, clientID, redirectURI)

	tokens := client.FullFlow("intro-rev@example.com", "pass123", "tools/echo", false)

	// One credential pair on both sides of the revocation. Asserting only the
	// "after" would pass on an unauthorized resource server just as readily as
	// on the revocation this test exists to prove.
	rsClientID, rsSecret := h.ResourceServerClient(rs.URI)
	if ir := h.IntrospectToken(tokens.AccessToken, rsClientID, rsSecret); !ir.Active {
		t.Fatal("precondition: expected active=true before revocation")
	}

	// Revoke the refresh token (cascades to access token via JTI blacklist).
	status := h.RevokeToken(tokens.RefreshToken, clientID)
	if status != http.StatusOK {
		t.Fatalf("revoke: expected 200, got %d", status)
	}

	if ir := h.IntrospectToken(tokens.AccessToken, rsClientID, rsSecret); ir.Active {
		t.Fatal("expected active=false for revoked token")
	}
}
