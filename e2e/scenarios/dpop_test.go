//go:build e2e

package scenarios

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"

	"github.com/authplane/authserver/api/shared"
	"github.com/authplane/authserver/e2e"
	"github.com/authplane/authserver/internal/crypto"
	"github.com/authplane/authserver/internal/observability"
)

// remoteJWKSProvider fetches JWKS from a remote auth server for test resource servers.
type remoteJWKSProvider struct {
	jwksURL string
}

func (p *remoteJWKSProvider) BuildJWKS(ctx context.Context) (*jose.JSONWebKeySet, error) {
	resp, err := http.Get(p.jwksURL)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var jwks jose.JSONWebKeySet
	if err := json.NewDecoder(resp.Body).Decode(&jwks); err != nil {
		return nil, err
	}
	return &jwks, nil
}

// inMemoryProofStore is the resource-server-side replay store for DPoP proofs
// in e2e tests. Each scenario constructs its own (no cross-test state).
type inMemoryProofStore struct {
	mu   sync.Mutex
	seen map[string]time.Time
}

func newInMemoryProofStore() *inMemoryProofStore {
	return &inMemoryProofStore{seen: map[string]time.Time{}}
}

func (s *inMemoryProofStore) ConsumeJTI(_ context.Context, jti string, expiry time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.seen[jti]; ok {
		return errInMemoryProofReplay
	}
	s.seen[jti] = expiry
	return nil
}

var errInMemoryProofReplay = errors.New("dpop: jti already consumed")

// newDPoPResourceServer creates a test resource server with DPoP-aware JWT
// validation, mirroring the behavior of a production resource server.
//
// audience is the resource URI the token's `aud` claim must contain. The
// httptest.Server URL (where requests actually hit) is independent of the
// resource URI — a real resource server's external identity and its routable
// network endpoint are separate concerns. The DPoP proof's htu still has to
// match the actual request URL; that check is orthogonal to audience.
func newDPoPResourceServer(t *testing.T, issuer, audience string) *httptest.Server {
	t.Helper()

	jwksProv := &remoteJWKSProvider{jwksURL: issuer + "/.well-known/jwks.json"}
	obs := observability.NewNoop()
	jwtMW := shared.NewResourceJWTMiddleware(
		jwksProv,
		issuer,
		audience,
		newInMemoryProofStore(),
		shared.DPoPJWTConfig{ProofLifetime: 60 * time.Second},
		obs.WithComponent("test-rs"),
	)

	mux := http.NewServeMux()
	mux.Handle("POST /tools/echo", jwtMW.Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"ok":true}`))
	})))

	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

// dpopExchange performs a client_credentials token exchange with an optional DPoP proof.
// Returns the HTTP response status code, response body, and DPoP-Nonce header value.
//
// resource is optional — when non-empty, the resulting token's `aud` is bound
// to that URI (RFC 8707). Pass the rs.URI so a resource-server middleware with
// WithAudience(rs.URI) accepts the token. When empty, aud defaults to the
// issuer URL (AS-internal token, not addressable to any resource).
func dpopExchange(t *testing.T, issuer, clientID, clientSecret, scope, resource, dpopProof string) (int, []byte, string) {
	t.Helper()

	form := url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {clientID},
		"client_secret": {clientSecret},
	}
	if scope != "" {
		form.Set("scope", scope)
	}
	if resource != "" {
		form.Set("resource", resource)
	}

	req, err := http.NewRequest("POST", issuer+"/oauth/token", strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatalf("create token request: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if dpopProof != "" {
		req.Header.Set("DPoP", dpopProof)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("token request: %v", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, body, resp.Header.Get("DPoP-Nonce")
}

// TestDPoP_BoundTokenIssuedAndAccepted verifies the complete DPoP flow:
// 1. Client sends DPoP proof with client_credentials exchange → gets DPoP-bound access token
// 2. Token type is "DPoP" and DPoP-Nonce header is present in response
// 3. Introspection confirms cnf.jkt binding and token_type=DPoP
// 4. DPoP-aware resource server accepts the token with valid proof
func TestDPoP_BoundTokenIssuedAndAccepted(t *testing.T) {
	h, servers := e2e.SetupE2E(t, e2e.HarnessConfig{
		EnableClientCredentials: true,
		EnableDPoP:              true,
	}, []string{"tools/echo"})
	rs := servers[0]

	h.RegisterScope(rs.URI, "tools/echo", "Echo tool")

	clientID, clientSecret := h.RegisterConfidentialClient(
		[]string{"client_credentials"},
		"tools/echo",
	)

	// Generate ES256 key pair for DPoP.
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	signer, err := crypto.NewDPoPSigner(privKey, jose.ES256)
	if err != nil {
		t.Fatalf("create DPoP signer: %v", err)
	}

	// 1. Create DPoP proof and exchange client_credentials.
	jti := crypto.GenerateRandomString(16)
	proof, err := crypto.CreateDPoPProof(signer, jti, "POST", h.Issuer+"/oauth/token", time.Now(), "", "")
	if err != nil {
		t.Fatalf("create DPoP proof: %v", err)
	}

	status, body, dpopNonce := dpopExchange(t, h.Issuer, clientID, clientSecret, "tools/echo", rs.URI, proof)
	if status != http.StatusOK {
		t.Fatalf("exchange: expected 200, got %d, body: %s", status, string(body))
	}

	var tr e2e.TokenResponse
	if err := json.Unmarshal(body, &tr); err != nil {
		t.Fatalf("decode token: %v", err)
	}

	// Verify token_type is DPoP (not Bearer).
	if tr.TokenType != "DPoP" {
		t.Errorf("token_type: got %q, want DPoP", tr.TokenType)
	}

	// Verify DPoP-Nonce header is present (middleware injects it on every response).
	if dpopNonce == "" {
		t.Error("expected DPoP-Nonce header in response")
	}

	// 2. Introspect — verify cnf.jkt is present and token_type=DPoP.
	ir := h.IntrospectToken(tr.AccessToken, clientID, clientSecret)
	if !ir.Active {
		t.Fatal("expected active=true")
	}
	if ir.TokenType != "DPoP" {
		t.Errorf("introspect token_type: got %q, want DPoP", ir.TokenType)
	}
	if ir.Cnf == nil {
		t.Fatal("expected cnf in introspection response")
	}
	jktVal, ok := ir.Cnf["jkt"].(string)
	if !ok || jktVal == "" {
		t.Errorf("expected cnf.jkt to be a non-empty string, got %v", ir.Cnf["jkt"])
	}

	// Verify JKT matches our key pair.
	pubJWK := jose.JSONWebKey{Key: &privKey.PublicKey}
	expectedJKT, err := crypto.ComputeJKT(pubJWK)
	if err != nil {
		t.Fatalf("compute JKT: %v", err)
	}
	if jktVal != expectedJKT {
		t.Errorf("cnf.jkt: got %q, want %q", jktVal, expectedJKT)
	}

	// 3. DPoP-aware resource server accepts the token with valid proof.
	// audience is rs.URI — the resource identifier the AS minted the token for.
	// rs.URI is independent of rsSrv.URL (the rs's network endpoint); the
	// middleware checks aud against the configured resource identity, while
	// DPoP htu checks against the actual request URL.
	rsSrv := newDPoPResourceServer(t, h.Issuer, rs.URI)

	rsJTI := crypto.GenerateRandomString(16)
	rsATH := crypto.ComputeATH(tr.AccessToken)
	rsProof, err := crypto.CreateDPoPProof(signer, rsJTI, "POST", rsSrv.URL+"/tools/echo", time.Now(), "", rsATH)
	if err != nil {
		t.Fatalf("create RS DPoP proof: %v", err)
	}

	rsReq, _ := http.NewRequest("POST", rsSrv.URL+"/tools/echo", strings.NewReader(`{"msg":"hello"}`))
	rsReq.Header.Set("Authorization", "DPoP "+tr.AccessToken)
	rsReq.Header.Set("DPoP", rsProof)
	rsReq.Header.Set("Content-Type", "application/json")

	rsResp, err := http.DefaultClient.Do(rsReq)
	if err != nil {
		t.Fatalf("resource request: %v", err)
	}
	rsBody, _ := io.ReadAll(rsResp.Body)
	rsResp.Body.Close()

	if rsResp.StatusCode != http.StatusOK {
		t.Errorf("resource request: expected 200, got %d, body: %s", rsResp.StatusCode, string(rsBody))
	}
}

// TestDPoP_ReplayedJTI_Rejected verifies that replaying a DPoP proof JTI
// is rejected by the token endpoint (RFC 9449 §11.1 replay protection).
func TestDPoP_ReplayedJTI_Rejected(t *testing.T) {
	h, _ := e2e.SetupE2E(t, e2e.HarnessConfig{
		EnableClientCredentials: true,
		EnableDPoP:              true,
	}, []string{"tools/echo"})

	clientID, clientSecret := h.RegisterConfidentialClient(
		[]string{"client_credentials"},
		"tools/echo",
	)

	privKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	signer, _ := crypto.NewDPoPSigner(privKey, jose.ES256)

	// Use the same JTI for both proofs.
	jti := crypto.GenerateRandomString(16)

	// First request — should succeed.
	proof1, _ := crypto.CreateDPoPProof(signer, jti, "POST", h.Issuer+"/oauth/token", time.Now(), "", "")
	status1, _, _ := dpopExchange(t, h.Issuer, clientID, clientSecret, "tools/echo", "", proof1)
	if status1 != http.StatusOK {
		t.Fatalf("first exchange: expected 200, got %d", status1)
	}

	// Second request with same JTI — should be rejected.
	proof2, _ := crypto.CreateDPoPProof(signer, jti, "POST", h.Issuer+"/oauth/token", time.Now(), "", "")
	status2, body2, _ := dpopExchange(t, h.Issuer, clientID, clientSecret, "tools/echo", "", proof2)
	if status2 == http.StatusOK {
		t.Fatal("second exchange with same JTI should have been rejected")
	}

	var oe e2e.OAuthError
	if err := json.Unmarshal(body2, &oe); err != nil {
		t.Fatalf("decode error: %v", err)
	}
	if oe.Error != "invalid_dpop_proof" {
		t.Errorf("error: got %q, want invalid_dpop_proof", oe.Error)
	}
}

// TestDPoP_WrongHTM_Rejected verifies that a DPoP proof with an incorrect HTTP
// method (htm) is rejected by the token endpoint.
func TestDPoP_WrongHTM_Rejected(t *testing.T) {
	h, _ := e2e.SetupE2E(t, e2e.HarnessConfig{
		EnableClientCredentials: true,
		EnableDPoP:              true,
	}, []string{"tools/echo"})

	clientID, clientSecret := h.RegisterConfidentialClient(
		[]string{"client_credentials"},
		"tools/echo",
	)

	privKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	signer, _ := crypto.NewDPoPSigner(privKey, jose.ES256)

	// Proof says GET but we POST to the token endpoint.
	jti := crypto.GenerateRandomString(16)
	proof, _ := crypto.CreateDPoPProof(signer, jti, "GET", h.Issuer+"/oauth/token", time.Now(), "", "")

	status, body, _ := dpopExchange(t, h.Issuer, clientID, clientSecret, "tools/echo", "", proof)
	if status == http.StatusOK {
		t.Fatal("expected rejection for wrong HTM")
	}

	var oe e2e.OAuthError
	if err := json.Unmarshal(body, &oe); err != nil {
		t.Fatalf("decode error: %v", err)
	}
	if oe.Error != "invalid_dpop_proof" {
		t.Errorf("error: got %q, want invalid_dpop_proof", oe.Error)
	}
}

// TestDPoP_MissingProofOnBoundToken_Rejected verifies that a DPoP-bound access
// token is rejected by a resource server when no DPoP proof is provided.
// Per RFC 9449 §7.1, DPoP-bound tokens MUST use the DPoP authorization scheme
// with a valid proof; Bearer scheme is rejected.
func TestDPoP_MissingProofOnBoundToken_Rejected(t *testing.T) {
	h, servers := e2e.SetupE2E(t, e2e.HarnessConfig{
		EnableClientCredentials: true,
		EnableDPoP:              true,
	}, []string{"tools/echo"})
	rs := servers[0]
	h.RegisterScope(rs.URI, "tools/echo", "Echo tool")

	clientID, clientSecret := h.RegisterConfidentialClient(
		[]string{"client_credentials"},
		"tools/echo",
	)

	// Get a DPoP-bound token.
	privKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	signer, _ := crypto.NewDPoPSigner(privKey, jose.ES256)

	jti := crypto.GenerateRandomString(16)
	proof, _ := crypto.CreateDPoPProof(signer, jti, "POST", h.Issuer+"/oauth/token", time.Now(), "", "")

	status, body, _ := dpopExchange(t, h.Issuer, clientID, clientSecret, "tools/echo", rs.URI, proof)
	if status != http.StatusOK {
		t.Fatalf("exchange: expected 200, got %d, body: %s", status, string(body))
	}

	var tr e2e.TokenResponse
	if err := json.Unmarshal(body, &tr); err != nil {
		t.Fatalf("decode token: %v", err)
	}
	if tr.TokenType != "DPoP" {
		t.Fatalf("expected DPoP token, got %q", tr.TokenType)
	}

	// Create a DPoP-aware resource server. Audience = rs.URI (the resource
	// identifier the AS minted the token for); rsSrv.URL is the routable
	// endpoint, independent of audience.
	rsSrv := newDPoPResourceServer(t, h.Issuer, rs.URI)

	// Try with Bearer scheme (no DPoP proof) → should be rejected.
	rsReq, _ := http.NewRequest("POST", rsSrv.URL+"/tools/echo", strings.NewReader(`{}`))
	rsReq.Header.Set("Authorization", "Bearer "+tr.AccessToken)
	rsReq.Header.Set("Content-Type", "application/json")

	rsResp, err := http.DefaultClient.Do(rsReq)
	if err != nil {
		t.Fatalf("resource request: %v", err)
	}
	rsResp.Body.Close()

	if rsResp.StatusCode != http.StatusUnauthorized {
		t.Errorf("expected 401 for DPoP-bound token without proof, got %d", rsResp.StatusCode)
	}

	// Also try with DPoP scheme but no DPoP header → should be rejected.
	rsReq2, _ := http.NewRequest("POST", rsSrv.URL+"/tools/echo", strings.NewReader(`{}`))
	rsReq2.Header.Set("Authorization", "DPoP "+tr.AccessToken)
	rsReq2.Header.Set("Content-Type", "application/json")
	// No DPoP header set.

	rsResp2, err := http.DefaultClient.Do(rsReq2)
	if err != nil {
		t.Fatalf("resource request 2: %v", err)
	}
	rsResp2.Body.Close()

	if rsResp2.StatusCode != http.StatusUnauthorized {
		t.Errorf("expected 401 for DPoP scheme without proof header, got %d", rsResp2.StatusCode)
	}
}

// TestDPoP_NonDPoPClientUnaffected verifies that clients not using DPoP
// continue to get standard Bearer tokens even when DPoP is enabled server-wide.
func TestDPoP_NonDPoPClientUnaffected(t *testing.T) {
	h, servers := e2e.SetupE2E(t, e2e.HarnessConfig{
		EnableClientCredentials: true,
		EnableDPoP:              true,
	}, []string{"tools/echo"})
	rs := servers[0]

	h.RegisterScope(rs.URI, "tools/echo", "Echo tool")

	clientID, clientSecret := h.RegisterConfidentialClient(
		[]string{"client_credentials"},
		"tools/echo",
	)

	// No DPoP header — standard Bearer flow.
	tr := h.ClientCredentialsExchange(clientID, clientSecret, "tools/echo", "")
	if tr.TokenType != "Bearer" {
		t.Errorf("token_type: got %q, want Bearer", tr.TokenType)
	}

	// Introspect should show Bearer, no cnf.
	ir := h.IntrospectToken(tr.AccessToken, clientID, clientSecret)
	if !ir.Active {
		t.Fatal("expected active=true")
	}
	if ir.TokenType != "Bearer" {
		t.Errorf("introspect token_type: got %q, want Bearer", ir.TokenType)
	}
	if ir.Cnf != nil {
		t.Errorf("expected no cnf for non-DPoP token, got %v", ir.Cnf)
	}
}
