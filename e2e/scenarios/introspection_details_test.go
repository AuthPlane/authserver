//go:build e2e

package scenarios

import (
	"testing"
	"time"

	"github.com/authplane/authserver/e2e"
)

// TestIntrospection_ActiveTokenContainsAllFields verifies that introspection
// of an active access token returns the full set of RFC 7662 response fields.
func TestIntrospection_ActiveTokenContainsAllFields(t *testing.T) {
	scopes := []string{"tools/echo", "tools/get_time"}
	h, servers := e2e.SetupE2E(t, e2e.HarnessConfig{}, scopes)
	rs := servers[0]

	h.CreateUser("intro-full@example.com", "pass123")
	h.RegisterScope(rs.URI, "tools/echo", "Echo tool")
	h.RegisterScope(rs.URI, "tools/get_time", "Time tool")

	redirectURI := "http://localhost:9999/callback"
	clientID := e2e.RegisterClientViaHarness(t, h, redirectURI)
	client := e2e.NewMCPClient(t, h, rs, clientID, redirectURI)

	tokens := client.FullFlow("intro-full@example.com", "pass123", "tools/echo tools/get_time", false)

	ir := h.IntrospectToken(tokens.AccessToken, clientID)
	if !ir.Active {
		t.Fatal("expected active=true")
	}

	// Verify all standard fields are present.
	if ir.ClientID == "" {
		t.Error("missing client_id in introspection")
	}
	if ir.ClientID != clientID {
		t.Errorf("client_id: got %q, want %q", ir.ClientID, clientID)
	}
	if ir.Sub == "" {
		t.Error("missing sub (subject) in introspection")
	}
	if ir.Iss == "" {
		t.Error("missing iss (issuer) in introspection")
	}
	if ir.Iss != h.Issuer {
		t.Errorf("iss: got %q, want %q", ir.Iss, h.Issuer)
	}
	if ir.Exp == 0 {
		t.Error("missing exp (expiry) in introspection")
	}
	// exp should be in the future.
	if ir.Exp <= time.Now().Unix() {
		t.Errorf("exp should be in future, got %d (now=%d)", ir.Exp, time.Now().Unix())
	}
	if ir.Iat == 0 {
		t.Error("missing iat (issued at) in introspection")
	}
	if ir.Jti == "" {
		t.Error("missing jti (token ID) in introspection")
	}
	if ir.TokenType != "Bearer" {
		t.Errorf("token_type: got %q, want Bearer", ir.TokenType)
	}
	if ir.Scope == "" {
		t.Error("missing scope in introspection")
	}
}

// TestIntrospection_MachineTokenFields verifies introspection of a
// client_credentials token returns correct machine-specific fields.
func TestIntrospection_MachineTokenFields(t *testing.T) {
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

	ir := h.IntrospectToken(tr.AccessToken, clientID, clientSecret)
	if !ir.Active {
		t.Fatal("expected active=true")
	}

	// For machine tokens, sub should equal client_id.
	if ir.Sub != clientID {
		t.Errorf("machine token sub: got %q, want %q (client_id)", ir.Sub, clientID)
	}
	if ir.ClientID != clientID {
		t.Errorf("client_id: got %q, want %q", ir.ClientID, clientID)
	}
	if ir.TokenType != "Bearer" {
		t.Errorf("token_type: got %q, want Bearer", ir.TokenType)
	}
	if ir.Exp == 0 {
		t.Error("missing exp in machine token introspection")
	}
	if ir.Jti == "" {
		t.Error("missing jti in machine token introspection")
	}
}

// TestIntrospection_InvalidToken_Inactive verifies that introspecting
// a completely invalid token returns active=false (not an error).
// Per RFC 7662 §2.2, the server MUST respond with {"active":false}.
func TestIntrospection_InvalidToken_Inactive(t *testing.T) {
	h, servers := e2e.SetupE2E(t, e2e.HarnessConfig{
		EnableClientCredentials: true,
	}, []string{"tools/echo"})
	rs := servers[0]

	h.RegisterScope(rs.URI, "tools/echo", "Echo tool")

	clientID, clientSecret := h.RegisterConfidentialClient(
		[]string{"client_credentials"},
		"tools/echo",
	)

	// Introspect a completely bogus token.
	ir := h.IntrospectToken("this-is-not-a-real-token", clientID, clientSecret)
	if ir.Active {
		t.Fatal("expected active=false for invalid token")
	}
}

// TestIntrospection_UniqueJTI verifies that each token gets a unique jti.
func TestIntrospection_UniqueJTI(t *testing.T) {
	h, servers := e2e.SetupE2E(t, e2e.HarnessConfig{
		EnableClientCredentials: true,
	}, []string{"tools/echo"})
	rs := servers[0]

	h.RegisterScope(rs.URI, "tools/echo", "Echo tool")

	clientID, clientSecret := h.RegisterConfidentialClient(
		[]string{"client_credentials"},
		"tools/echo",
	)

	// Issue two tokens.
	tr1 := h.ClientCredentialsExchange(clientID, clientSecret, "tools/echo", "")
	tr2 := h.ClientCredentialsExchange(clientID, clientSecret, "tools/echo", "")

	ir1 := h.IntrospectToken(tr1.AccessToken, clientID, clientSecret)
	ir2 := h.IntrospectToken(tr2.AccessToken, clientID, clientSecret)

	if ir1.Jti == "" || ir2.Jti == "" {
		t.Fatal("expected non-empty jti for both tokens")
	}
	if ir1.Jti == ir2.Jti {
		t.Errorf("two different tokens should have different jti values, both got %q", ir1.Jti)
	}
}
