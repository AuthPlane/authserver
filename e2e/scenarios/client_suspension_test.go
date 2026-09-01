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

	// Introspect as the resource server the token was minted for: the suspended
	// client is the token's own owner and could not authenticate here anyway,
	// and introspection refuses public clients outright.
	//
	// The same credentials are reused on both sides of the suspension so the
	// before/after pair isolates it. Without the "active before" assertion an
	// unbound resource server would also read active=false, and the test would
	// pass while covering nothing.
	rsClientID, rsSecret := h.ResourceServerClient(rs.URI)
	if ir := h.IntrospectToken(tokens.AccessToken, rsClientID, rsSecret); !ir.Active {
		t.Fatal("precondition: expected active=true before client suspension")
	}

	// Suspend the client.
	h.SuspendClient(clientID)

	// Introspection should return inactive for suspended client.
	if ir := h.IntrospectToken(tokens.AccessToken, rsClientID, rsSecret); ir.Active {
		t.Fatal("expected active=false after client suspension")
	}

	// Refresh should also fail (client is suspended → returns invalid_client).
	oe := h.RefreshTokenExpectError(tokens.RefreshToken, clientID)
	if oe.Error != "invalid_client" {
		t.Errorf("expected invalid_client error after suspension, got %q", oe.Error)
	}
}

// TestClientSuspension_RevocationDoesNotLeakStatus pins that /oauth/revoke
// stays a 200-always endpoint for public clients whatever their status.
//
// A public client_id is public by construction — it travels in the authorize
// URL and in browser redirects — so answering invalid_client for a suspended
// one and 200 for an active one would let anyone probe client status with no
// credential at all. RFC 7009 reserves the error response for authentication
// failures, and an anonymous caller has authenticated nothing.
func TestClientSuspension_RevocationDoesNotLeakStatus(t *testing.T) {
	scopes := []string{"tools/echo"}
	h, servers := e2e.SetupE2E(t, e2e.HarnessConfig{}, scopes)
	rs := servers[0]

	h.CreateUser("suspend-revoke@example.com", "pass123")
	h.RegisterScope(rs.URI, "tools/echo", "Echo tool")

	redirectURI := "http://localhost:9999/callback"
	clientID := e2e.RegisterClientViaHarness(t, h, redirectURI)
	client := e2e.NewMCPClient(t, h, rs, clientID, redirectURI)
	// Run the flow so the client is a real, used one rather than a bare
	// registration; the probes below deliberately use an unknown token.
	client.FullFlow("suspend-revoke@example.com", "pass123", "tools/echo", false)

	// An unknown token against an active public client: 200 per RFC 7009.
	if status := h.RevokeToken("not-a-real-token", clientID); status != http.StatusOK {
		t.Fatalf("revoke with active public client: got %d, want 200", status)
	}

	h.SuspendClient(clientID)

	// Same request, same shape — the status of the client must not show through.
	if status := h.RevokeToken("not-a-real-token", clientID); status != http.StatusOK {
		t.Fatalf("revoke with suspended public client: got %d, want 200 (status leak)", status)
	}

	// That the suspended client also revokes *nothing* cannot be asserted from
	// here: RFC 7009 mandates 200 either way, and the harness has no way to
	// reactivate the client and retry the refresh. The service-level
	// TestRevocation_SuspendedPublicClient_NoStatusLeak asserts the family
	// survives; this scenario covers only the wire-visible half.
}
