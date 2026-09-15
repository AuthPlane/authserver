//go:build e2e

package scenarios

import (
	"testing"

	"github.com/authplane/authserver/e2e"
)

// RFC 9207 closes the authorization-server mix-up hole: without iss, a client
// talking to several ASes cannot tell which one produced a given code, and can
// be induced to redeem it at the wrong token endpoint. The MCP 2026-07-28
// authorization spec adopts it and ties client rejection behavior to the
// metadata flag — so the advertisement and the redirect must agree, end to end,
// against a real running server.
func TestISS_AdvertisedAndStampedOnAuthorizationResponse(t *testing.T) {
	scopes := []string{"tools/echo"}
	h, servers := e2e.SetupE2E(t, e2e.HarnessConfig{}, scopes)
	rs := servers[0]

	h.CreateUser("alice@example.com", "password123")
	h.RegisterScope(rs.URI, "tools/echo", "Echo tool")

	redirectURI := "http://localhost:9999/callback"
	clientID := e2e.RegisterClientViaHarness(t, h, redirectURI)
	client := e2e.NewMCPClient(t, h, rs, clientID, redirectURI)

	meta := client.DiscoverASMetadata(h.Issuer)
	if !meta.AuthorizationResponseIssParameterSupported {
		t.Fatal("AS metadata must advertise authorization_response_iss_parameter_supported (RFC 9207 §2.3)")
	}

	// Consent once with remember=true so the next authorize returns a code
	// directly, which is the redirect an already-onboarded client sees.
	if tok := client.FullFlow("alice@example.com", "password123", "tools/echo", true); tok.AccessToken == "" {
		t.Fatal("initial flow did not produce an access token")
	}

	_, challenge := client.GeneratePKCE()
	params := client.BuildAuthorizeParams("tools/echo", rs.URI, challenge, "test-state")
	result := h.Authorize(client.HTTPClient, params)

	if result.Code == "" {
		t.Fatalf("expected a direct code redirect after remembered consent, got %+v", result)
	}
	if result.Iss == "" {
		t.Fatal("authorization response carries no iss parameter (RFC 9207 §2)")
	}
	// Byte-exact: the spec forbids the client from normalizing before comparing,
	// so the issuer announced in discovery and the issuer stamped on the redirect
	// must be the identical string.
	if result.Iss != meta.Issuer {
		t.Errorf("iss = %q, want the discovery issuer %q (byte-exact)", result.Iss, meta.Issuer)
	}
	if result.State != "test-state" {
		t.Errorf("state = %q, want %q — iss must be additive, not displace other params", result.State, "test-state")
	}
}

// The spec requires iss on error responses too, and forbids the client from
// acting on or displaying error, error_description or error_uri when the issuer
// does not match. An unattributed error redirect is exactly the payload an
// attacker would want rendered, so this path is pinned separately.
func TestISS_StampedOnErrorAuthorizationResponse(t *testing.T) {
	scopes := []string{"tools/echo"}
	h, servers := e2e.SetupE2E(t, e2e.HarnessConfig{}, scopes)
	rs := servers[0]

	h.CreateUser("alice@example.com", "password123")
	h.RegisterScope(rs.URI, "tools/echo", "Echo tool")

	redirectURI := "http://localhost:9999/callback"
	clientID := e2e.RegisterClientViaHarness(t, h, redirectURI)
	client := e2e.NewMCPClient(t, h, rs, clientID, redirectURI)

	_, challenge := client.GeneratePKCE()
	params := client.BuildAuthorizeParams("tools/echo", rs.URI, challenge, "test-state")
	// A missing code_challenge yields ErrInvalidPKCE, which falls to the default
	// branch of handleAuthorizeError and so is reported to the registered
	// redirect_uri. client_id and redirect_uri stay valid on purpose: the errors
	// that invalidate either one render an error page instead, precisely so the
	// AS never redirects to an attacker-supplied URI.
	params.Del("code_challenge")
	params.Del("code_challenge_method")

	result := h.Authorize(client.HTTPClient, params)
	if result.Error == "" {
		t.Fatalf("expected an error redirect for a missing code_challenge, got %+v", result)
	}
	if result.Iss == "" {
		t.Error("error authorization response carries no iss; RFC 9207 §2 requires it on error responses too")
	}
	if result.Iss != h.Issuer {
		t.Errorf("iss = %q, want %q (byte-exact)", result.Iss, h.Issuer)
	}
}
