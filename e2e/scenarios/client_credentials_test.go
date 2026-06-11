//go:build e2e

package scenarios

import (
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"testing"

	"github.com/authplane/authserver/e2e"
)

// TestClientCredentials_HappyPath verifies a full client_credentials exchange:
// register confidential client → exchange → introspect → revoke.
func TestClientCredentials_HappyPath(t *testing.T) {
	scopes := []string{"tools/echo", "tools/query"}
	h, servers := e2e.SetupE2E(t, e2e.HarnessConfig{
		EnableClientCredentials: true,
	}, scopes)
	rs := servers[0]

	h.RegisterScope(rs.URI, "tools/echo", "Echo tool")
	h.RegisterScope(rs.URI, "tools/query", "Query tool")

	clientID, clientSecret := h.RegisterConfidentialClient(
		[]string{"client_credentials"},
		"tools/echo tools/query",
	)

	// 1. Exchange: get machine access token.
	tr := h.ClientCredentialsExchange(clientID, clientSecret, "tools/echo", "")
	if tr.AccessToken == "" {
		t.Fatal("expected non-empty access_token")
	}
	if tr.TokenType != "Bearer" {
		t.Errorf("token_type: got %q, want Bearer", tr.TokenType)
	}
	if tr.ExpiresIn <= 0 {
		t.Errorf("expires_in: got %d, want > 0", tr.ExpiresIn)
	}
	if tr.Scope != "tools/echo" {
		t.Errorf("scope: got %q, want %q", tr.Scope, "tools/echo")
	}
	if tr.RefreshToken != "" {
		t.Errorf("expected no refresh_token, got %q", tr.RefreshToken)
	}

	// 2. Introspect the machine token.
	ir := h.IntrospectToken(tr.AccessToken, clientID, clientSecret)
	if !ir.Active {
		t.Fatal("expected active=true for fresh machine token")
	}
	if ir.Sub != clientID {
		t.Errorf("sub: got %q, want %q (sub==client_id for machine tokens)", ir.Sub, clientID)
	}
	if ir.ClientID != clientID {
		t.Errorf("client_id: got %q, want %q", ir.ClientID, clientID)
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

	// 3. Revoke the machine token (using access token value).
	status := h.RevokeToken(tr.AccessToken, clientID, clientSecret)
	if status != http.StatusOK {
		t.Fatalf("revoke: expected 200, got %d", status)
	}

	// 4. Introspect again — should be inactive.
	ir2 := h.IntrospectToken(tr.AccessToken, clientID, clientSecret)
	if ir2.Active {
		t.Fatal("expected active=false after revocation")
	}
}

// TestClientCredentials_WrongSecret verifies that wrong credentials are rejected.
func TestClientCredentials_WrongSecret(t *testing.T) {
	h, _ := e2e.SetupE2E(t, e2e.HarnessConfig{
		EnableClientCredentials: true,
	}, []string{"tools/echo"})

	clientID, _ := h.RegisterConfidentialClient(
		[]string{"client_credentials"},
		"tools/echo",
	)

	oe := h.ClientCredentialsExchangeExpectError(clientID, "wrong-secret", "")
	if oe.Error != "invalid_client" {
		t.Errorf("error: got %q, want invalid_client", oe.Error)
	}
}

// TestClientCredentials_GrantTypeNotAllowed verifies that clients without client_credentials grant type are rejected.
func TestClientCredentials_GrantTypeNotAllowed(t *testing.T) {
	h, _ := e2e.SetupE2E(t, e2e.HarnessConfig{
		EnableClientCredentials: true,
	}, []string{"tools/echo"})

	// Register with only authorization_code, not client_credentials.
	clientID, clientSecret := h.RegisterConfidentialClient(
		[]string{"authorization_code"},
		"tools/echo",
	)

	oe := h.ClientCredentialsExchangeExpectError(clientID, clientSecret, "")
	if oe.Error != "unauthorized_client" {
		t.Errorf("error: got %q, want unauthorized_client", oe.Error)
	}
}

// TestClientCredentials_ScopeRestriction verifies that requesting scopes beyond client's registered scopes is rejected.
func TestClientCredentials_ScopeRestriction(t *testing.T) {
	h, _ := e2e.SetupE2E(t, e2e.HarnessConfig{
		EnableClientCredentials: true,
	}, []string{"tools/echo", "tools/admin"})

	clientID, clientSecret := h.RegisterConfidentialClient(
		[]string{"client_credentials"},
		"tools/echo", // client only has tools/echo
	)

	oe := h.ClientCredentialsExchangeExpectError(clientID, clientSecret, "tools/admin")
	if oe.Error != "invalid_scope" {
		t.Errorf("error: got %q, want invalid_scope", oe.Error)
	}
}

// TestClientCredentials_OverbroadScope_PartialOverlap_Rejected covers the
// fail-closed correction: a request that includes a registered scope AND an
// unregistered scope must be rejected, not silently narrowed to just the
// registered scope. Previously the service intersected and returned the
// overlap, hiding client misconfiguration.
func TestClientCredentials_OverbroadScope_PartialOverlap_Rejected(t *testing.T) {
	h, _ := e2e.SetupE2E(t, e2e.HarnessConfig{
		EnableClientCredentials: true,
	}, []string{"tools/echo", "tools/admin"})

	clientID, clientSecret := h.RegisterConfidentialClient(
		[]string{"client_credentials"},
		"tools/echo", // client registered for echo only
	)

	// Request mixes registered (echo) + unregistered (admin). The
	// pre-fix behavior silently narrowed to "tools/echo"; the
	// post-fix behavior rejects with invalid_scope.
	oe := h.ClientCredentialsExchangeExpectError(clientID, clientSecret, "tools/echo tools/admin")
	if oe.Error != "invalid_scope" {
		t.Errorf("error: got %q, want invalid_scope (partial overlap must fail closed)", oe.Error)
	}
}

// TestClientCredentials_ASMetadata verifies that client_credentials appears in grant_types_supported.
func TestClientCredentials_ASMetadata(t *testing.T) {
	h, _ := e2e.SetupE2E(t, e2e.HarnessConfig{
		EnableClientCredentials: true,
	}, []string{"tools/echo"})

	resp, err := http.Get(h.Issuer + "/.well-known/oauth-authorization-server")
	if err != nil {
		t.Fatalf("GET AS metadata: %v", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	var metadata map[string]interface{}
	if err := json.Unmarshal(body, &metadata); err != nil {
		t.Fatalf("decode metadata: %v", err)
	}

	grantTypes, ok := metadata["grant_types_supported"].([]interface{})
	if !ok {
		t.Fatal("grant_types_supported not found or not an array")
	}

	found := false
	for _, gt := range grantTypes {
		if gt == "client_credentials" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("grant_types_supported does not contain client_credentials: %v", grantTypes)
	}
}

// TestClientCredentials_Disabled verifies that client_credentials is rejected when not enabled.
func TestClientCredentials_Disabled(t *testing.T) {
	h, _ := e2e.SetupE2E(t, e2e.HarnessConfig{
		EnableClientCredentials: false,
	}, []string{"tools/echo"})

	// Even with a valid client, client_credentials should be rejected.
	form := url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {"any-client"},
		"client_secret": {"any-secret"},
	}

	resp, err := http.PostForm(h.Issuer+"/oauth/token", form)
	if err != nil {
		t.Fatalf("POST /oauth/token: %v", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode == http.StatusOK {
		t.Fatal("expected error when client_credentials is disabled, got 200")
	}

	var oe struct {
		Error string `json:"error"`
	}
	json.Unmarshal(body, &oe)
	if oe.Error != "unsupported_grant_type" {
		t.Errorf("error: got %q, want unsupported_grant_type", oe.Error)
	}
}

// TestClientCredentials_ResourceBinding verifies that resource parameter sets audience.
func TestClientCredentials_ResourceBinding(t *testing.T) {
	h, servers := e2e.SetupE2E(t, e2e.HarnessConfig{
		EnableClientCredentials: true,
	}, []string{"tools/echo"})
	resourceURI := servers[0].URI

	h.RegisterScope(resourceURI, "tools/echo", "Echo tool")

	clientID, clientSecret := h.RegisterConfidentialClient(
		[]string{"client_credentials"},
		"tools/echo",
	)

	tr := h.ClientCredentialsExchange(clientID, clientSecret, "tools/echo", resourceURI)
	if tr.AccessToken == "" {
		t.Fatal("expected non-empty access_token")
	}

	// Introspect to verify audience.
	ir := h.IntrospectToken(tr.AccessToken, clientID, clientSecret)
	if !ir.Active {
		t.Fatal("expected active=true")
	}
	if ir.Aud != resourceURI {
		t.Errorf("aud: got %q, want %q", ir.Aud, resourceURI)
	}
}
