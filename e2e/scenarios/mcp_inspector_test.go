//go:build e2e

package scenarios

import (
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/authplane/authserver/e2e"
	"github.com/authplane/authserver/internal/crypto"
	"github.com/authplane/authserver/internal/ports/input"
)

// setupInspectorHarness creates a standard harness for MCP Inspector tests.
func setupInspectorHarness(t *testing.T) (*e2e.TestHarness, *e2e.MCPResourceServer) {
	t.Helper()
	scopes := []string{"tools/echo", "tools/db_query"}
	h, servers := e2e.SetupE2E(t, e2e.HarnessConfig{}, scopes)
	rs := servers[0]

	h.CreateUser("inspector@example.com", "pass123")
	h.RegisterScope(rs.URI, "tools/echo", "Echo tool")
	h.RegisterScope(rs.URI, "tools/db_query", "Database query tool")

	return h, rs
}

// Matrix: 22.1 — AS and PRM metadata discovery.
func TestMCPInspector_MetadataDiscovery(t *testing.T) {
	h, rs := setupInspectorHarness(t)

	// 1. GET /.well-known/oauth-authorization-server → 200.
	asResp, err := http.Get(h.Issuer + "/.well-known/oauth-authorization-server")
	if err != nil {
		t.Fatalf("AS metadata fetch: %v", err)
	}
	defer asResp.Body.Close()

	if asResp.StatusCode != http.StatusOK {
		t.Fatalf("AS metadata status: got %d, want 200", asResp.StatusCode)
	}

	var asMeta map[string]any
	if err := json.NewDecoder(asResp.Body).Decode(&asMeta); err != nil {
		t.Fatalf("decode AS metadata: %v", err)
	}

	// Verify required fields.
	if asMeta["issuer"] != h.Issuer {
		t.Errorf("issuer: got %v, want %s", asMeta["issuer"], h.Issuer)
	}
	for _, field := range []string{
		"authorization_endpoint",
		"token_endpoint",
		"registration_endpoint",
		"jwks_uri",
		"response_types_supported",
		"grant_types_supported",
		"code_challenge_methods_supported",
	} {
		if asMeta[field] == nil {
			t.Errorf("AS metadata missing field: %s", field)
		}
	}

	// Verify scopes_supported contains registered scopes.
	scopesRaw, ok := asMeta["scopes_supported"].([]any)
	if !ok {
		t.Fatal("scopes_supported is not an array")
	}
	scopeSet := make(map[string]bool)
	for _, s := range scopesRaw {
		scopeSet[s.(string)] = true
	}
	if !scopeSet["tools/echo"] {
		t.Error("scopes_supported missing tools/echo")
	}
	if !scopeSet["tools/db_query"] {
		t.Error("scopes_supported missing tools/db_query")
	}

	// Verify code_challenge_methods_supported includes S256.
	ccms, _ := asMeta["code_challenge_methods_supported"].([]any)
	hasS256 := false
	for _, m := range ccms {
		if m == "S256" {
			hasS256 = true
		}
	}
	if !hasS256 {
		t.Error("code_challenge_methods_supported missing S256")
	}

	// 2. GET /.well-known/oauth-protected-resource on resource server → 200.
	prmResp, err := http.Get(rs.URI + "/.well-known/oauth-protected-resource")
	if err != nil {
		t.Fatalf("PRM fetch: %v", err)
	}
	defer prmResp.Body.Close()

	if prmResp.StatusCode != http.StatusOK {
		t.Fatalf("PRM status: got %d, want 200", prmResp.StatusCode)
	}

	var prm map[string]any
	if err := json.NewDecoder(prmResp.Body).Decode(&prm); err != nil {
		t.Fatalf("decode PRM: %v", err)
	}

	// Verify authorization_servers points to harness issuer.
	authServers, ok := prm["authorization_servers"].([]any)
	if !ok || len(authServers) == 0 {
		t.Fatal("PRM: authorization_servers missing or empty")
	}
	if authServers[0] != h.Issuer {
		t.Errorf("PRM authorization_servers[0]: got %v, want %s", authServers[0], h.Issuer)
	}
}

// Matrix: 22.2 — DCR with Inspector-shaped payload (public client, no scope).
func TestMCPInspector_DCR(t *testing.T) {
	h, _ := setupInspectorHarness(t)

	// MCP Inspector sends: redirect_uris, token_endpoint_auth_method=none, no scope.
	resp, status := h.RegisterClient(input.RegisterClientRequest{
		RedirectURIs:            []string{"http://localhost:5173/callback"},
		TokenEndpointAuthMethod: "none",
		ClientName:              "MCP Inspector",
	})

	if status != http.StatusCreated {
		t.Fatalf("DCR status: got %d, want 201", status)
	}
	if resp == nil {
		t.Fatal("DCR response is nil")
	}
	if resp.ClientID == "" {
		t.Error("DCR response missing client_id")
	}
	if resp.ClientIDIssuedAt == 0 {
		t.Error("DCR response missing client_id_issued_at")
	}
}

// Matrix: 22.3 — PKCE flow (S256 accepted, plain rejected).
func TestMCPInspector_PKCEFlow(t *testing.T) {
	h, rs := setupInspectorHarness(t)

	redirectURI := "http://localhost:5173/callback"
	clientID := e2e.RegisterClientViaHarness(t, h, redirectURI)
	client := e2e.NewMCPClient(t, h, rs, clientID, redirectURI)

	// S256 works — full flow completes.
	tokens := client.FullFlow("inspector@example.com", "pass123", "tools/echo tools/db_query", false)
	if tokens.AccessToken == "" {
		t.Fatal("S256 PKCE flow failed: no access_token")
	}

	// Plain rejected.
	httpClient := h.NewClient()
	verifier := crypto.GenerateVerifier()
	params := url.Values{
		"response_type":         {"code"},
		"client_id":             {clientID},
		"redirect_uri":          {redirectURI},
		"scope":                 {"tools/echo"},
		"resource":              {rs.URI},
		"code_challenge":        {verifier},
		"code_challenge_method": {"plain"},
		"state":                 {"test-plain"},
	}

	result := h.Authorize(httpClient, params)
	if result.Error == "" {
		t.Error("plain code_challenge_method should be rejected")
	}
}

// Matrix: 22.4 — Token exchange: verify response shape + JWT claims.
func TestMCPInspector_TokenExchange(t *testing.T) {
	h, rs := setupInspectorHarness(t)

	redirectURI := "http://localhost:5173/callback"
	clientID := e2e.RegisterClientViaHarness(t, h, redirectURI)
	client := e2e.NewMCPClient(t, h, rs, clientID, redirectURI)

	tokens := client.FullFlow("inspector@example.com", "pass123", "tools/echo tools/db_query", false)

	// Verify token response fields.
	if tokens.AccessToken == "" {
		t.Fatal("access_token is empty")
	}
	if tokens.TokenType != "Bearer" {
		t.Errorf("token_type: got %q, want Bearer", tokens.TokenType)
	}
	if tokens.ExpiresIn <= 0 {
		t.Errorf("expires_in: got %d, want positive", tokens.ExpiresIn)
	}
	if tokens.RefreshToken == "" {
		t.Error("refresh_token is empty")
	}
	if tokens.Scope == "" {
		t.Error("scope is empty")
	}

	// Verify scope contains requested scopes.
	scopeSet := make(map[string]bool)
	for _, s := range strings.Fields(tokens.Scope) {
		scopeSet[s] = true
	}
	if !scopeSet["tools/echo"] {
		t.Errorf("scope missing tools/echo: got %q", tokens.Scope)
	}
	if !scopeSet["tools/db_query"] {
		t.Errorf("scope missing tools/db_query: got %q", tokens.Scope)
	}

	// Verify JWT claims.
	claims := client.VerifyJWTClaims(tokens.AccessToken)
	if claims.Issuer != h.Issuer {
		t.Errorf("JWT iss: got %q, want %q", claims.Issuer, h.Issuer)
	}
	if claims.Subject == "" {
		t.Error("JWT sub is empty")
	}
	if claims.ClientID != clientID {
		t.Errorf("JWT client_id: got %q, want %q", claims.ClientID, clientID)
	}
	if len(claims.Audience) == 0 || claims.Audience[0] != rs.URI {
		t.Errorf("JWT aud: got %v, want [%s]", claims.Audience, rs.URI)
	}
	if claims.JTI == "" {
		t.Error("JWT jti is empty")
	}
	if claims.Expiry == 0 {
		t.Error("JWT exp is zero")
	}
	if claims.Scope == "" {
		t.Error("JWT scope is empty")
	}
}

// Matrix: 22.5 — Token refresh with rotation.
func TestMCPInspector_TokenRefresh(t *testing.T) {
	h, rs := setupInspectorHarness(t)

	redirectURI := "http://localhost:5173/callback"
	clientID := e2e.RegisterClientViaHarness(t, h, redirectURI)
	client := e2e.NewMCPClient(t, h, rs, clientID, redirectURI)

	tokens := client.FullFlow("inspector@example.com", "pass123", "tools/echo", false)
	if tokens.RefreshToken == "" {
		t.Fatal("no refresh_token from initial flow")
	}

	// Refresh.
	refreshed := h.RefreshToken(tokens.RefreshToken, clientID)
	if refreshed.AccessToken == "" {
		t.Fatal("refreshed access_token is empty")
	}
	if refreshed.RefreshToken == "" {
		t.Fatal("refreshed refresh_token is empty")
	}
	if refreshed.RefreshToken == tokens.RefreshToken {
		t.Error("refresh_token was not rotated")
	}

	// Old refresh token should be invalidated.
	oe := h.RefreshTokenExpectError(tokens.RefreshToken, clientID)
	if oe.Error != "invalid_grant" {
		t.Errorf("old refresh token error: got %q, want invalid_grant", oe.Error)
	}
}

// Matrix: 22.6 — Tool call with bearer token.
func TestMCPInspector_ListTools(t *testing.T) {
	h, rs := setupInspectorHarness(t)

	redirectURI := "http://localhost:5173/callback"
	clientID := e2e.RegisterClientViaHarness(t, h, redirectURI)
	client := e2e.NewMCPClient(t, h, rs, clientID, redirectURI)

	tokens := client.FullFlow("inspector@example.com", "pass123", "tools/echo tools/db_query", false)

	// Call echo tool with bearer token.
	status, result := client.CallTool("/tools/echo", tokens.AccessToken, `"hello inspector"`)
	if status != http.StatusOK {
		t.Fatalf("echo tool status: got %d, want 200", status)
	}
	if result["result"] != `"hello inspector"` {
		t.Errorf("echo result: got %v", result["result"])
	}

	// Call without token → 401.
	status = client.CallToolRaw("/tools/echo", "")
	if status != http.StatusUnauthorized {
		t.Errorf("unauthenticated call: got %d, want 401", status)
	}

	// Call with invalid token → 401.
	status = client.CallToolRaw("/tools/echo", "invalid-bearer-token")
	if status != http.StatusUnauthorized {
		t.Errorf("invalid token call: got %d, want 401", status)
	}
}
