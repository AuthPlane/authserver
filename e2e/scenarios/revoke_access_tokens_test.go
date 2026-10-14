//go:build e2e

package scenarios

import (
	"net/http"
	"testing"

	"github.com/authplane/authserver/e2e"
)

// /oauth/revoke must revoke every access token it accepts, whatever grant
// minted it. Only client_credentials tokens have a machine_tokens row; an
// authorization-code, refresh-grant or registered-resource exchange token
// used to get a 200 and stay active. Each case below shows the token
// working before the revoke and refused after it, at introspection and as
// a token-exchange subject_token.

type revokeFixture struct {
	h              *e2e.TestHarness
	rs             *e2e.MCPResourceServer
	email          string
	password       string
	webAppClientID string
	mcpClientID    string
	mcpSecret      string
	mcpSlug        string
	mcpURI         string
}

func newRevokeFixture(t *testing.T) *revokeFixture {
	t.Helper()
	h, servers := e2e.SetupE2E(t, e2e.HarnessConfig{
		EnableAdminAPI:                 true,
		EnableTokenExchange:            true,
		TokenExchangeMaxChainDepth:     5,
		TokenExchangeAllowSelfExchange: true,
	}, []string{"tools/echo"})
	rs := servers[0]
	h.RegisterScope(rs.URI, "tools/echo", "Echo tool")

	f := &revokeFixture{h: h, rs: rs, email: "revoke-at@example.com", password: "pass123", mcpSlug: "revoke-mcp"}
	f.mcpURI = "https://" + f.mcpSlug + ".test"
	h.CreateUser(f.email, f.password)
	f.webAppClientID = h.AdminCreatePublicClient("revoke-webapp", []string{"authorization_code", "refresh_token"}, "tools/echo", nil)
	f.mcpClientID, f.mcpSecret = h.AdminCreateConfidentialClient("revoke-mcp",
		[]string{"urn:ietf:params:oauth:grant-type:token-exchange"}, "tools/echo")
	h.AdminCreateResource(e2e.CreateResourceSpec{
		Slug:        f.mcpSlug,
		URI:         f.mcpURI,
		BackendKind: "mint",
		DisplayName: "mcp:" + f.mcpSlug,
		Scopes:      []e2e.AdminScope{{Name: "tools/echo"}},
		Policy: &e2e.AdminPolicy{
			Runtime:  e2e.AdminRuntimePolicy{ClientIDs: []string{f.mcpClientID}},
			Exchange: e2e.AdminExchangePolicy{AllowedClientIDs: []string{f.mcpClientID}},
		},
	})
	h.RunFlowC1Consent(f.email, f.password, f.webAppClientID, "http://localhost:9999/callback",
		f.mcpSlug, []string{"tools/echo"}, []string{"tools/echo"})
	return f
}

func (f *revokeFixture) userTokens(t *testing.T) *e2e.TokenResponse {
	t.Helper()
	tokens := e2e.NewMCPClient(t, f.h, f.rs, f.webAppClientID, "http://localhost:9999/callback").
		FullFlow(f.email, f.password, "tools/echo", false)
	if tokens.AccessToken == "" || tokens.RefreshToken == "" {
		t.Fatal("expected access and refresh tokens from the authorization-code flow")
	}
	return tokens
}

// exchange spends tok as the MCP client's subject_token for the registered
// resource; it reports whether the AS issued a token.
func (f *revokeFixture) exchange(t *testing.T, tok string) bool {
	t.Helper()
	status, _ := f.h.TokenExchangeWithResourceRaw(f.mcpClientID, f.mcpSecret, tok, tokenTypeAccessToken, "tools/echo", f.mcpSlug)
	return status == http.StatusOK
}

// assertRevokes checks tok works, revokes it as (clientID, secret), and
// checks it no longer does. introspect is called with one fixed caller on
// both sides so a change in the answer can only come from the revoke.
func (f *revokeFixture) assertRevokes(t *testing.T, tok, clientID, secret string, introspect func() bool) {
	t.Helper()
	if !introspect() {
		t.Fatal("token inactive before the revoke; the test proves nothing")
	}
	if !f.exchange(t, tok) {
		t.Fatal("token refused as subject_token before the revoke; the test proves nothing")
	}
	if status := f.h.RevokeToken(tok, clientID, secret); status != http.StatusOK {
		t.Fatalf("revoke: status %d, want 200", status)
	}
	if introspect() {
		t.Error("token still introspects active after /oauth/revoke")
	}
	if f.exchange(t, tok) {
		t.Error("token still accepted as subject_token after /oauth/revoke")
	}
}

func TestRevoke_AuthorizationCodeAccessToken(t *testing.T) {
	f := newRevokeFixture(t)
	tokens := f.userTokens(t)
	rsID, rsSecret := f.h.ResourceServerClient(f.rs.URI)
	f.assertRevokes(t, tokens.AccessToken, f.webAppClientID, "", func() bool {
		return f.h.IntrospectToken(tokens.AccessToken, rsID, rsSecret).Active
	})
}

func TestRevoke_RefreshGrantAccessToken(t *testing.T) {
	f := newRevokeFixture(t)
	refreshed := f.h.RefreshToken(f.userTokens(t).RefreshToken, f.webAppClientID)
	if refreshed.AccessToken == "" {
		t.Fatal("expected an access token from the refresh grant")
	}
	rsID, rsSecret := f.h.ResourceServerClient(f.rs.URI)
	f.assertRevokes(t, refreshed.AccessToken, f.webAppClientID, "", func() bool {
		return f.h.IntrospectToken(refreshed.AccessToken, rsID, rsSecret).Active
	})
}

func TestRevoke_RegisteredResourceExchangeToken(t *testing.T) {
	f := newRevokeFixture(t)
	exch := f.h.TokenExchangeWithResource(f.mcpClientID, f.mcpSecret,
		f.userTokens(t).AccessToken, tokenTypeAccessToken, "tools/echo", f.mcpSlug)
	if exch.AccessToken == "" {
		t.Fatal("expected a token from the registered-resource exchange")
	}
	f.assertRevokes(t, exch.AccessToken, f.mcpClientID, f.mcpSecret, func() bool {
		return f.h.IntrospectToken(exch.AccessToken, f.mcpClientID, f.mcpSecret).Active
	})
}

// Revoking a token the caller does not own changes nothing.
func TestRevoke_AccessTokenOfAnotherClient_NotRevoked(t *testing.T) {
	f := newRevokeFixture(t)
	tokens := f.userTokens(t)
	if status := f.h.RevokeToken(tokens.AccessToken, f.mcpClientID, f.mcpSecret); status != http.StatusOK {
		t.Fatalf("revoke: status %d, want 200", status)
	}
	if !f.h.IntrospectAsResourceServer(tokens.AccessToken, f.rs.URI).Active {
		t.Error("another client's revoke deactivated the token")
	}
	if !f.exchange(t, tokens.AccessToken) {
		t.Error("another client's revoke made the token unusable as subject_token")
	}
}
