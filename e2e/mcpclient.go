//go:build e2e

package e2e

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/go-jose/go-jose/v4"

	"github.com/authplane/authserver/internal/crypto"
)

// MCPClient is a programmatic MCP OAuth client for E2E tests.
type MCPClient struct {
	T              *testing.T
	Harness        *TestHarness
	ResourceServer *MCPResourceServer
	ClientID       string
	RedirectURI    string
	HTTPClient     *http.Client
}

// NewMCPClient creates a client pre-configured for a resource server.
func NewMCPClient(t *testing.T, h *TestHarness, rs *MCPResourceServer, clientID, redirectURI string) *MCPClient {
	t.Helper()
	return &MCPClient{
		T:              t,
		Harness:        h,
		ResourceServer: rs,
		ClientID:       clientID,
		RedirectURI:    redirectURI,
		HTTPClient:     h.NewClient(),
	}
}

// DiscoverPRM fetches the Protected Resource Metadata and returns the AS issuer.
func (c *MCPClient) DiscoverPRM() string {
	c.T.Helper()

	resp, err := http.Get(c.ResourceServer.URI + "/.well-known/oauth-protected-resource")
	if err != nil {
		c.T.Fatalf("discover PRM: %v", err)
	}
	defer resp.Body.Close()

	var prm struct {
		Resource             string   `json:"resource"`
		AuthorizationServers []string `json:"authorization_servers"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&prm); err != nil {
		c.T.Fatalf("decode PRM: %v", err)
	}

	if len(prm.AuthorizationServers) == 0 {
		c.T.Fatal("PRM has no authorization_servers")
	}
	return prm.AuthorizationServers[0]
}

// DiscoverASMetadata fetches the AS metadata and returns key endpoints.
func (c *MCPClient) DiscoverASMetadata(issuer string) ASMetadata {
	c.T.Helper()

	resp, err := http.Get(issuer + "/.well-known/oauth-authorization-server")
	if err != nil {
		c.T.Fatalf("discover AS metadata: %v", err)
	}
	defer resp.Body.Close()

	var meta ASMetadata
	if err := json.NewDecoder(resp.Body).Decode(&meta); err != nil {
		c.T.Fatalf("decode AS metadata: %v", err)
	}
	return meta
}

// ASMetadata holds the AS discovery response fields we need.
type ASMetadata struct {
	Issuer                string   `json:"issuer"`
	AuthorizationEndpoint string   `json:"authorization_endpoint"`
	TokenEndpoint         string   `json:"token_endpoint"`
	RegistrationEndpoint  string   `json:"registration_endpoint"`
	RevocationEndpoint    string   `json:"revocation_endpoint"`
	JWKSURI               string   `json:"jwks_uri"`
	ScopesSupported       []string `json:"scopes_supported"`
	GrantTypesSupported   []string `json:"grant_types_supported"`
}

// GeneratePKCE generates a PKCE verifier and S256 challenge.
func (c *MCPClient) GeneratePKCE() (verifier, challenge string) {
	verifier = crypto.GenerateVerifier()
	challenge = crypto.ComputeS256Challenge(verifier)
	return
}

// BuildAuthorizeParams constructs the authorize URL parameters.
func (c *MCPClient) BuildAuthorizeParams(scope, resource, challenge, state string) url.Values {
	return url.Values{
		"response_type":         {"code"},
		"client_id":             {c.ClientID},
		"redirect_uri":          {c.RedirectURI},
		"scope":                 {scope},
		"resource":              {resource},
		"code_challenge":        {challenge},
		"code_challenge_method": {"S256"},
		"state":                 {state},
	}
}

// FullFlow executes the complete OAuth flow: login → authorize → consent → token.
// Returns the token response.
func (c *MCPClient) FullFlow(email, password, scope string, remember bool) *TokenResponse {
	c.T.Helper()

	verifier, challenge := c.GeneratePKCE()
	params := c.BuildAuthorizeParams(scope, c.ResourceServer.URI, challenge, "test-state")

	// 1. Authorize (expect login redirect).
	result := c.Harness.Authorize(c.HTTPClient, params)
	if !result.NeedsLogin {
		c.T.Fatal("expected login redirect")
	}

	// 2. Login — extract the redirect parameter from the Location header.
	loginRedirect := extractRedirectParam(result.Location)
	c.Harness.Login(c.HTTPClient, email, password, loginRedirect)

	// 3. Re-authorize (now logged in, expect consent redirect).
	result = c.Harness.Authorize(c.HTTPClient, params)
	if !result.NeedsConsent {
		if result.Code != "" {
			// Already consented, exchange code.
			return c.Harness.ExchangeCode(result.Code, verifier, c.ClientID, c.RedirectURI)
		}
		c.T.Fatalf("expected consent redirect, got: %+v", result)
	}

	// 4. Grant consent.
	scopes := strings.Fields(scope)
	code := c.Harness.GrantConsent(c.HTTPClient, result.SessionID, scopes, remember)

	// 5. Exchange code for tokens.
	return c.Harness.ExchangeCode(code, verifier, c.ClientID, c.RedirectURI)
}

// CallTool calls a tool endpoint on the resource server with the given access token.
func (c *MCPClient) CallTool(toolPath, accessToken, body string) (int, map[string]any) {
	c.T.Helper()

	req, err := http.NewRequest("POST", c.ResourceServer.URI+toolPath, strings.NewReader(body))
	if err != nil {
		c.T.Fatalf("build tool request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		c.T.Fatalf("call tool: %v", err)
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)
	var result map[string]any
	json.Unmarshal(respBody, &result)

	return resp.StatusCode, result
}

// CallToolRaw calls a tool endpoint and returns the raw status code.
func (c *MCPClient) CallToolRaw(toolPath, accessToken string) int {
	c.T.Helper()

	req, err := http.NewRequest("POST", c.ResourceServer.URI+toolPath, strings.NewReader("{}"))
	if err != nil {
		c.T.Fatalf("build tool request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		c.T.Fatalf("call tool: %v", err)
	}
	resp.Body.Close()
	return resp.StatusCode
}

// VerifyJWTClaims parses a JWT and verifies key claims without calling the resource server.
func (c *MCPClient) VerifyJWTClaims(accessToken string) *crypto.AccessTokenClaims {
	c.T.Helper()

	resp, err := http.Get(c.Harness.Issuer + "/.well-known/jwks.json")
	if err != nil {
		c.T.Fatalf("fetch JWKS: %v", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	var jwks jose.JSONWebKeySet
	if err := json.Unmarshal(body, &jwks); err != nil {
		c.T.Fatalf("decode JWKS: %v", err)
	}

	claims, err := crypto.VerifyAccessToken(accessToken, &jwks)
	if err != nil {
		c.T.Fatalf("verify JWT: %v", err)
	}
	return claims
}

// RegisterClientViaHarness is a convenience for registering a public client.
func RegisterClientViaHarness(t *testing.T, h *TestHarness, redirectURI string) string {
	t.Helper()

	regReq := fmt.Sprintf(`{
		"redirect_uris": [%q],
		"client_name": "e2e-test-client",
		"token_endpoint_auth_method": "none"
	}`, redirectURI)

	resp, err := http.Post(h.Issuer+"/oauth/register", "application/json", strings.NewReader(regReq))
	if err != nil {
		t.Fatalf("register client: %v", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("register client: expected 201, got %d, body: %s", resp.StatusCode, string(body))
	}

	var reg struct {
		ClientID string `json:"client_id"`
	}
	if err := json.Unmarshal(body, &reg); err != nil {
		t.Fatalf("decode register response: %v", err)
	}
	return reg.ClientID
}

// extractRedirectParam pulls the redirect query parameter from a login URL.
func extractRedirectParam(loginLocation string) string {
	u, err := url.Parse(loginLocation)
	if err != nil {
		return ""
	}
	return u.Query().Get("redirect")
}
