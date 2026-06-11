//go:build e2e

package scenarios

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"

	"github.com/authplane/authserver/e2e"
	"github.com/authplane/authserver/internal/crypto"
	"github.com/authplane/authserver/internal/ports/input"
)

// TestXAA_BasicFlow tests the full XAA flow:
// Register IdP → Create policy → Sign ID-JAG → Exchange for access token → Verify at RS.
func TestXAA_BasicFlow(t *testing.T) {
	h, servers := e2e.SetupE2E(t, e2e.HarnessConfig{
		EnableXAA: true,
	}, []string{"tools/echo", "tools/query"})
	rs := servers[0]

	mockIdP := e2e.NewMockIdP(t)

	h.RegisterScope(rs.URI, "tools/echo", "Echo tool")
	h.RegisterScope(rs.URI, "tools/query", "Query tool")

	idpID := h.RegisterTrustedIDP(input.RegisterIDPRequest{
		Name:    "Test Corp IdP",
		Issuer:  mockIdP.Issuer,
		JWKSUri: mockIdP.Issuer + "/.well-known/jwks.json",
	})

	h.CreateXAAPolicy(input.CreatePolicyRequest{
		Name:  "Allow All",
		IDPID: idpID,
	})

	clientID, clientSecret := h.RegisterConfidentialClient(
		[]string{"urn:ietf:params:oauth:grant-type:jwt-bearer"},
		"tools/echo tools/query",
	)

	assertion := mockIdP.SignIDJAGWithResource(t, h.Issuer, clientID, "alice@testcorp.com", "tools/echo tools/query", rs.URI)
	tr := h.JWTBearerExchangeWithResource(clientID, clientSecret, assertion, "tools/echo tools/query", rs.URI)

	if tr.AccessToken == "" {
		t.Fatal("expected access token, got empty")
	}
	if tr.TokenType != "Bearer" {
		t.Errorf("token_type = %q, want Bearer", tr.TokenType)
	}
	if tr.Scope == "" {
		t.Error("expected scope in response")
	}

	// Verify access token works at resource server.
	status, _ := e2e.NewMCPClient(t, h, rs, clientID, "http://localhost:9999/callback").
		CallTool("/tools/echo", tr.AccessToken, `"hello from XAA"`)
	if status != http.StatusOK {
		t.Errorf("resource server call status = %d, want 200", status)
	}

	// Verify introspection.
	ir := h.IntrospectToken(tr.AccessToken, clientID, clientSecret)
	if !ir.Active {
		t.Fatal("token should be active")
	}
	if ir.ClientID != clientID {
		t.Errorf("introspection client_id = %q, want %q", ir.ClientID, clientID)
	}
}

// TestXAA_PolicyDenied tests that an ID-JAG is rejected when no matching policy exists.
func TestXAA_PolicyDenied(t *testing.T) {
	h, _ := e2e.SetupE2E(t, e2e.HarnessConfig{
		EnableXAA: true,
	}, []string{"tools/echo"})

	mockIdP := e2e.NewMockIdP(t)

	// Register IdP but create NO policy.
	h.RegisterTrustedIDP(input.RegisterIDPRequest{
		Name:    "NoPolicyIdP",
		Issuer:  mockIdP.Issuer,
		JWKSUri: mockIdP.Issuer + "/.well-known/jwks.json",
	})

	clientID, clientSecret := h.RegisterConfidentialClient(
		[]string{"urn:ietf:params:oauth:grant-type:jwt-bearer"},
		"tools/echo",
	)

	assertion := mockIdP.SignIDJAG(t, h.Issuer, clientID, "bob@testcorp.com", "tools/echo")

	oe := h.JWTBearerExchangeExpectError(clientID, clientSecret, assertion, "tools/echo")
	if oe.Error != "access_denied" {
		t.Errorf("error = %q, want access_denied", oe.Error)
	}
	if oe.StatusCode != http.StatusForbidden {
		t.Errorf("status = %d, want 403", oe.StatusCode)
	}
}

// TestXAA_ReplayPrevention tests that the same ID-JAG cannot be used twice.
func TestXAA_ReplayPrevention(t *testing.T) {
	h, _ := e2e.SetupE2E(t, e2e.HarnessConfig{
		EnableXAA: true,
	}, []string{"tools/echo"})

	mockIdP := e2e.NewMockIdP(t)

	idpID := h.RegisterTrustedIDP(input.RegisterIDPRequest{
		Name:    "ReplayIdP",
		Issuer:  mockIdP.Issuer,
		JWKSUri: mockIdP.Issuer + "/.well-known/jwks.json",
	})
	h.CreateXAAPolicy(input.CreatePolicyRequest{
		Name:  "Allow All",
		IDPID: idpID,
	})

	clientID, clientSecret := h.RegisterConfidentialClient(
		[]string{"urn:ietf:params:oauth:grant-type:jwt-bearer"},
		"tools/echo",
	)

	// Use the same assertion twice.
	assertion := mockIdP.SignIDJAG(t, h.Issuer, clientID, "alice@testcorp.com", "tools/echo")

	// First use — should succeed.
	tr := h.JWTBearerExchange(clientID, clientSecret, assertion, "tools/echo")
	if tr.AccessToken == "" {
		t.Fatal("first exchange should succeed")
	}

	// Second use — should fail with replay.
	oe := h.JWTBearerExchangeExpectError(clientID, clientSecret, assertion, "tools/echo")
	if oe.Error != "invalid_grant" {
		t.Errorf("replay error = %q, want invalid_grant", oe.Error)
	}
}

// TestXAA_UntrustedIdP tests that an ID-JAG from an unregistered issuer is rejected.
func TestXAA_UntrustedIdP(t *testing.T) {
	h, _ := e2e.SetupE2E(t, e2e.HarnessConfig{
		EnableXAA: true,
	}, []string{"tools/echo"})

	// Create a mock IdP but do NOT register it.
	untrustedIdP := e2e.NewMockIdP(t)

	clientID, clientSecret := h.RegisterConfidentialClient(
		[]string{"urn:ietf:params:oauth:grant-type:jwt-bearer"},
		"tools/echo",
	)

	assertion := untrustedIdP.SignIDJAG(t, h.Issuer, clientID, "eve@evil.com", "tools/echo")

	oe := h.JWTBearerExchangeExpectError(clientID, clientSecret, assertion, "tools/echo")
	if oe.Error != "invalid_grant" {
		t.Errorf("error = %q, want invalid_grant", oe.Error)
	}
}

// TestXAA_PolicyScopeRestriction pins the XAA policy scope-bound contract
// under the post-3bf1963 fail-closed semantics:
//   - A request whose scope is a subset of the policy max succeeds and
//     emits a token scoped to exactly the request.
//   - A request that exceeds the policy max does NOT silently narrow;
//     the policy is skipped and (with no other matching policy) the
//     exchange is denied with access_denied. Pre-3bf1963 the policy
//     silently intersected and emitted a narrowed token, hiding the
//     operator's misconfiguration. Mirrors the MED 4 fail-closed correction
//     in client_credentials and jwt_bearer.
func TestXAA_PolicyScopeRestriction(t *testing.T) {
	h, _ := e2e.SetupE2E(t, e2e.HarnessConfig{
		EnableXAA: true,
	}, []string{"tools/echo", "tools/admin"})

	mockIdP := e2e.NewMockIdP(t)

	idpID := h.RegisterTrustedIDP(input.RegisterIDPRequest{
		Name:    "ScopeIdP",
		Issuer:  mockIdP.Issuer,
		JWKSUri: mockIdP.Issuer + "/.well-known/jwks.json",
	})

	// Policy only allows "tools/echo" — not "tools/admin".
	h.CreateXAAPolicy(input.CreatePolicyRequest{
		Name:   "Echo Only",
		IDPID:  idpID,
		Scopes: []string{"tools/echo"},
	})

	clientID, clientSecret := h.RegisterConfidentialClient(
		[]string{"urn:ietf:params:oauth:grant-type:jwt-bearer"},
		"tools/echo tools/admin",
	)

	// Case 1: request within the policy bound (tools/echo only) succeeds
	// and emits a token scoped to exactly the request.
	allowedAssertion := mockIdP.SignIDJAG(t, h.Issuer, clientID, "alice@testcorp.com", "tools/echo")
	tr := h.JWTBearerExchange(clientID, clientSecret, allowedAssertion, "tools/echo")
	if tr.Scope != "tools/echo" {
		t.Errorf("in-bound request: scope = %q, want %q", tr.Scope, "tools/echo")
	}

	// Case 2: request beyond the policy bound (tools/echo + tools/admin)
	// is denied — the policy is skipped (not silently intersected), and
	// with no other policy the exchange returns access_denied.
	overbroadAssertion := mockIdP.SignIDJAG(t, h.Issuer, clientID, "alice@testcorp.com", "tools/echo tools/admin")
	oe := h.JWTBearerExchangeExpectError(clientID, clientSecret, overbroadAssertion, "tools/echo tools/admin")
	if oe.Error != "access_denied" {
		t.Errorf("overbroad request: error = %q, want access_denied (fail-closed per 3bf1963)", oe.Error)
	}
}

// TestXAA_SubjectMapping_Strict tests that strict mode denies unmapped subjects.
func TestXAA_SubjectMapping_Strict(t *testing.T) {
	h, _ := e2e.SetupE2E(t, e2e.HarnessConfig{
		EnableXAA:      true,
		XAASubjectMode: "strict",
	}, []string{"tools/echo"})

	mockIdP := e2e.NewMockIdP(t)

	idpID := h.RegisterTrustedIDP(input.RegisterIDPRequest{
		Name:    "StrictIdP",
		Issuer:  mockIdP.Issuer,
		JWKSUri: mockIdP.Issuer + "/.well-known/jwks.json",
	})
	h.CreateXAAPolicy(input.CreatePolicyRequest{
		Name:  "Allow All",
		IDPID: idpID,
	})

	clientID, clientSecret := h.RegisterConfidentialClient(
		[]string{"urn:ietf:params:oauth:grant-type:jwt-bearer"},
		"tools/echo",
	)

	// No subject mapping exists → strict mode should deny.
	assertion := mockIdP.SignIDJAG(t, h.Issuer, clientID, "unmapped@testcorp.com", "tools/echo")
	oe := h.JWTBearerExchangeExpectError(clientID, clientSecret, assertion, "tools/echo")
	if oe.Error != "access_denied" {
		t.Errorf("error = %q, want access_denied", oe.Error)
	}
}

// TestXAA_SubjectMapping_ExplicitMap tests that an explicit subject mapping provides a local user.
func TestXAA_SubjectMapping_ExplicitMap(t *testing.T) {
	h, _ := e2e.SetupE2E(t, e2e.HarnessConfig{
		EnableXAA:      true,
		XAASubjectMode: "strict",
	}, []string{"tools/echo"})

	mockIdP := e2e.NewMockIdP(t)

	idpID := h.RegisterTrustedIDP(input.RegisterIDPRequest{
		Name:    "MappedIdP",
		Issuer:  mockIdP.Issuer,
		JWKSUri: mockIdP.Issuer + "/.well-known/jwks.json",
	})
	h.CreateXAAPolicy(input.CreatePolicyRequest{
		Name:  "Allow All",
		IDPID: idpID,
	})

	// Create explicit subject mapping.
	h.CreateSubjectMapping(input.CreateMappingRequest{
		IDPID:       idpID,
		IDPSubject:  "mapped@testcorp.com",
		LocalUserID: "local-alice-123",
	})

	clientID, clientSecret := h.RegisterConfidentialClient(
		[]string{"urn:ietf:params:oauth:grant-type:jwt-bearer"},
		"tools/echo",
	)

	assertion := mockIdP.SignIDJAG(t, h.Issuer, clientID, "mapped@testcorp.com", "tools/echo")
	tr := h.JWTBearerExchange(clientID, clientSecret, assertion, "tools/echo")

	if tr.AccessToken == "" {
		t.Fatal("expected access token")
	}

	// Verify the subject in the token claims is the local user.
	claims := parseJWTClaims(t, tr.AccessToken)
	sub, _ := claims["sub"].(string)
	if sub != "local-alice-123" {
		t.Errorf("sub = %q, want %q", sub, "local-alice-123")
	}
}

// TestXAA_Revocation tests that XAA-issued tokens can be revoked.
func TestXAA_Revocation(t *testing.T) {
	h, _ := e2e.SetupE2E(t, e2e.HarnessConfig{
		EnableXAA: true,
	}, []string{"tools/echo"})

	mockIdP := e2e.NewMockIdP(t)

	idpID := h.RegisterTrustedIDP(input.RegisterIDPRequest{
		Name:    "RevokeIdP",
		Issuer:  mockIdP.Issuer,
		JWKSUri: mockIdP.Issuer + "/.well-known/jwks.json",
	})
	h.CreateXAAPolicy(input.CreatePolicyRequest{
		Name:  "Allow All",
		IDPID: idpID,
	})

	clientID, clientSecret := h.RegisterConfidentialClient(
		[]string{"urn:ietf:params:oauth:grant-type:jwt-bearer"},
		"tools/echo",
	)

	assertion := mockIdP.SignIDJAG(t, h.Issuer, clientID, "alice@testcorp.com", "tools/echo")
	tr := h.JWTBearerExchange(clientID, clientSecret, assertion, "tools/echo")

	// Token should be active.
	ir := h.IntrospectToken(tr.AccessToken, clientID, clientSecret)
	if !ir.Active {
		t.Fatal("token should be active before revocation")
	}

	// Revoke.
	status := h.RevokeToken(tr.AccessToken, clientID, clientSecret)
	if status != http.StatusOK {
		t.Errorf("revoke status = %d, want 200", status)
	}

	// Token should be inactive after revocation.
	ir = h.IntrospectToken(tr.AccessToken, clientID, clientSecret)
	if ir.Active {
		t.Error("token should be inactive after revocation")
	}
}

// TestXAA_DiscoveryGrantType verifies that jwt-bearer appears in AS metadata.
func TestXAA_DiscoveryGrantType(t *testing.T) {
	h, _ := e2e.SetupE2E(t, e2e.HarnessConfig{
		EnableXAA: true,
	}, []string{"tools/echo"})

	client := e2e.NewMCPClient(t, h, nil, "", "")
	meta := client.DiscoverASMetadata(h.Issuer)

	found := false
	for _, gt := range meta.GrantTypesSupported {
		if gt == "urn:ietf:params:oauth:grant-type:jwt-bearer" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("AS metadata should include jwt-bearer grant type, got: %v", meta.GrantTypesSupported)
	}
}

// TestXAA_DPoP tests XAA + DPoP proof-of-possession.
func TestXAA_DPoP(t *testing.T) {
	h, _ := e2e.SetupE2E(t, e2e.HarnessConfig{
		EnableXAA:  true,
		EnableDPoP: true,
	}, []string{"tools/echo"})

	mockIdP := e2e.NewMockIdP(t)

	idpID := h.RegisterTrustedIDP(input.RegisterIDPRequest{
		Name:    "DPoPIdP",
		Issuer:  mockIdP.Issuer,
		JWKSUri: mockIdP.Issuer + "/.well-known/jwks.json",
	})
	h.CreateXAAPolicy(input.CreatePolicyRequest{
		Name:  "Allow All",
		IDPID: idpID,
	})

	clientID, clientSecret := h.RegisterConfidentialClient(
		[]string{"urn:ietf:params:oauth:grant-type:jwt-bearer"},
		"tools/echo",
	)

	// Generate ES256 key pair for DPoP.
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate DPoP key: %v", err)
	}
	dpopSigner, err := crypto.NewDPoPSigner(privKey, jose.ES256)
	if err != nil {
		t.Fatalf("create DPoP signer: %v", err)
	}

	assertion := mockIdP.SignIDJAG(t, h.Issuer, clientID, "alice@testcorp.com", "tools/echo")

	// Create DPoP proof.
	jti := crypto.GenerateRandomString(16)
	dpopProof, err := crypto.CreateDPoPProof(dpopSigner, jti, "POST", h.Issuer+"/oauth/token", time.Now(), "", "")
	if err != nil {
		t.Fatalf("create DPoP proof: %v", err)
	}

	tr := xaaDPoPExchange(t, h.Issuer, clientID, clientSecret, assertion, "tools/echo", dpopProof)
	if tr.AccessToken == "" {
		t.Fatal("expected access token with DPoP")
	}
	if tr.TokenType != "DPoP" {
		t.Errorf("token_type = %q, want DPoP", tr.TokenType)
	}

	// Verify cnf.jkt claim in token.
	claims := parseJWTClaims(t, tr.AccessToken)
	cnf, ok := claims["cnf"].(map[string]interface{})
	if !ok {
		t.Fatal("expected cnf claim in DPoP-bound token")
	}
	if _, ok := cnf["jkt"].(string); !ok {
		t.Fatal("expected cnf.jkt string in DPoP-bound token")
	}
}

// --- XAA helpers ---

// xaaDPoPExchange performs a jwt-bearer token exchange with a DPoP proof header.
func xaaDPoPExchange(t *testing.T, issuer, clientID, clientSecret, assertion, scope, dpopProof string) *e2e.TokenResponse {
	t.Helper()

	form := url.Values{
		"grant_type":    {"urn:ietf:params:oauth:grant-type:jwt-bearer"},
		"assertion":     {assertion},
		"client_id":     {clientID},
		"client_secret": {clientSecret},
	}
	if scope != "" {
		form.Set("scope", scope)
	}

	req, err := http.NewRequest("POST", issuer+"/oauth/token", strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatalf("create token request: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("DPoP", dpopProof)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("token request: %v", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("jwt-bearer+DPoP exchange: status %d, body: %s", resp.StatusCode, body)
	}

	var tr e2e.TokenResponse
	if err := json.Unmarshal(body, &tr); err != nil {
		t.Fatalf("decode token response: %v", err)
	}
	return &tr
}
