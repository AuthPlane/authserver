//go:build e2e

package scenarios

import (
	"net/http"
	"testing"

	"github.com/authplane/authserver/e2e"
)

// TestIntrospection_ForeignClient_Inactive proves a client cannot introspect a
// token it neither issued nor serves — the check RevocationService has always
// performed and introspection never did.
func TestIntrospection_ForeignClient_Inactive(t *testing.T) {
	scopes := []string{"tools/echo"}
	h, servers := e2e.SetupE2E(t, e2e.HarnessConfig{}, scopes)
	rs := servers[0]

	h.CreateUser("intro-foreign@example.com", "pass123")
	h.RegisterScope(rs.URI, "tools/echo", "Echo tool")

	redirectURI := "http://localhost:9999/callback"
	clientID := e2e.RegisterClientViaHarness(t, h, redirectURI)
	client := e2e.NewMCPClient(t, h, rs, clientID, redirectURI)
	tokens := client.FullFlow("intro-foreign@example.com", "pass123", "tools/echo", false)

	// Control: the token really is introspectable, by a caller entitled to it.
	// Without this the assertion below would hold just as well for a token that
	// was never valid in the first place.
	rsClientID, rsSecret := h.ResourceServerClient(rs.URI)
	if ir := h.IntrospectToken(tokens.AccessToken, rsClientID, rsSecret); !ir.Active {
		t.Fatal("precondition: the entitled resource server should see this token active")
	}

	// A confidential client with no relationship to the token or its audience.
	strangerID, strangerSecret := h.RegisterConfidentialClient([]string{"authorization_code"}, "")

	ir := h.IntrospectToken(tokens.AccessToken, strangerID, strangerSecret)
	if ir.Active {
		t.Fatal("a foreign client must not learn the token is active")
	}
	// The refusal must be indistinguishable from an invalid token (RFC 7662 §4).
	if ir.Sub != "" || ir.ClientID != "" || ir.Scope != "" {
		t.Errorf("inactive response leaked claims: %+v", ir)
	}
}

// TestIntrospection_ResourceServer_RequiresRuntimeBinding covers the canonical
// RFC 7662 caller in both directions: a resource server asking about a token
// one of its clients presented, before and after the binding that authorizes
// it to act AS the Resource.
func TestIntrospection_ResourceServer_RequiresRuntimeBinding(t *testing.T) {
	scopes := []string{"tools/echo"}
	h, servers := e2e.SetupE2E(t, e2e.HarnessConfig{}, scopes)
	rs := servers[0]

	h.CreateUser("intro-rs@example.com", "pass123")
	h.RegisterScope(rs.URI, "tools/echo", "Echo tool")

	redirectURI := "http://localhost:9999/callback"
	clientID := e2e.RegisterClientViaHarness(t, h, redirectURI)
	client := e2e.NewMCPClient(t, h, rs, clientID, redirectURI)
	tokens := client.FullFlow("intro-rs@example.com", "pass123", "tools/echo", false)

	rsClientID, rsSecret := h.RegisterConfidentialClient([]string{"authorization_code"}, "")

	// Unbound: the AS has no way to know this client speaks for the Resource.
	if ir := h.IntrospectToken(tokens.AccessToken, rsClientID, rsSecret); ir.Active {
		t.Fatal("an unbound client must not introspect on the Resource's behalf")
	}

	// Bound via policy.runtime.client_ids — the operator's
	// `authserver admin resource runtime-client add` equivalent.
	h.AuthorizeRuntimeClient(rs.URI, rsClientID)

	ir := h.IntrospectToken(tokens.AccessToken, rsClientID, rsSecret)
	if !ir.Active {
		t.Fatal("the bound resource server must be able to introspect")
	}
	if ir.ClientID != clientID {
		t.Errorf("client_id = %q, want the token's owner %q", ir.ClientID, clientID)
	}
	if ir.Scope != "tools/echo" {
		t.Errorf("scope = %q, want tools/echo", ir.Scope)
	}
}

// TestIntrospection_PublicClient_Unauthorized enforces RFC 6749 §2.3 on the
// wire: a secret-less client carries no identity to authorize, which is what
// the discovery document has always advertised.
func TestIntrospection_PublicClient_Unauthorized(t *testing.T) {
	scopes := []string{"tools/echo"}
	h, servers := e2e.SetupE2E(t, e2e.HarnessConfig{}, scopes)
	rs := servers[0]

	h.CreateUser("intro-public@example.com", "pass123")
	h.RegisterScope(rs.URI, "tools/echo", "Echo tool")

	redirectURI := "http://localhost:9999/callback"
	clientID := e2e.RegisterClientViaHarness(t, h, redirectURI)
	client := e2e.NewMCPClient(t, h, rs, clientID, redirectURI)
	tokens := client.FullFlow("intro-public@example.com", "pass123", "tools/echo", false)

	// The public client asking about its own token is still refused: the
	// endpoint has no authenticated identity to act on.
	_, status := h.IntrospectTokenStatus(tokens.AccessToken, clientID, "")
	if status != http.StatusUnauthorized {
		t.Fatalf("public client introspection: got %d, want 401", status)
	}
}

// TestIntrospection_SuspendedCaller_Unauthorized covers the gap the audit
// missed: suspending a client left its introspection access untouched.
func TestIntrospection_SuspendedCaller_Unauthorized(t *testing.T) {
	scopes := []string{"tools/echo"}
	h, servers := e2e.SetupE2E(t, e2e.HarnessConfig{}, scopes)
	rs := servers[0]

	h.CreateUser("intro-susp@example.com", "pass123")
	h.RegisterScope(rs.URI, "tools/echo", "Echo tool")

	redirectURI := "http://localhost:9999/callback"
	clientID := e2e.RegisterClientViaHarness(t, h, redirectURI)
	client := e2e.NewMCPClient(t, h, rs, clientID, redirectURI)
	tokens := client.FullFlow("intro-susp@example.com", "pass123", "tools/echo", false)

	rsClientID, rsSecret := h.ResourceServerClient(rs.URI)
	if ir := h.IntrospectToken(tokens.AccessToken, rsClientID, rsSecret); !ir.Active {
		t.Fatal("precondition: the bound resource server should introspect")
	}

	h.SuspendClient(rsClientID)

	_, status := h.IntrospectTokenStatus(tokens.AccessToken, rsClientID, rsSecret)
	if status != http.StatusUnauthorized {
		t.Fatalf("suspended caller introspection: got %d, want 401", status)
	}
}
