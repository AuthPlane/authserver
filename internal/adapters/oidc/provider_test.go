//go:build integration

package oidc_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	josejwt "github.com/go-jose/go-jose/v4/jwt"

	"github.com/authplane/authserver/internal/adapters/oidc"
	"github.com/authplane/authserver/internal/observability"
)

// testIDP is a mock upstream OIDC IdP for testing.
type testIDP struct {
	server          *httptest.Server
	key             *ecdsa.PrivateKey
	kid             string
	issuer          string
	clientID        string
	tokenHandler    http.HandlerFunc // custom token handler (nil = default)
	userinfoHandler http.HandlerFunc // custom userinfo handler (nil = default)
	scopesSupported []string         // scopes_supported in discovery
}

func newTestIDP(t *testing.T) *testIDP {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	idp := &testIDP{
		key:      key,
		kid:      "test-kid-1",
		clientID: "test-client",
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /.well-known/openid-configuration", idp.handleDiscovery)
	mux.HandleFunc("GET /jwks", idp.handleJWKS)
	mux.HandleFunc("POST /token", func(w http.ResponseWriter, r *http.Request) {
		if idp.tokenHandler != nil {
			idp.tokenHandler(w, r)
			return
		}
		idp.defaultTokenHandler(w, r)
	})
	mux.HandleFunc("GET /userinfo", func(w http.ResponseWriter, r *http.Request) {
		if idp.userinfoHandler != nil {
			idp.userinfoHandler(w, r)
			return
		}
		idp.defaultUserinfoHandler(w, r)
	})

	idp.server = httptest.NewServer(mux)
	idp.issuer = idp.server.URL
	return idp
}

func (idp *testIDP) close() {
	idp.server.Close()
}

func (idp *testIDP) handleDiscovery(w http.ResponseWriter, _ *http.Request) {
	doc := map[string]interface{}{
		"issuer":                 idp.issuer,
		"authorization_endpoint": idp.issuer + "/authorize",
		"token_endpoint":         idp.issuer + "/token",
		"jwks_uri":               idp.issuer + "/jwks",
		"userinfo_endpoint":      idp.issuer + "/userinfo",
	}
	if len(idp.scopesSupported) > 0 {
		doc["scopes_supported"] = idp.scopesSupported
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(doc)
}

func (idp *testIDP) handleJWKS(w http.ResponseWriter, _ *http.Request) {
	jwk := jose.JSONWebKey{
		Key:       idp.key.Public(),
		KeyID:     idp.kid,
		Algorithm: string(jose.ES256),
		Use:       "sig",
	}
	jwks := jose.JSONWebKeySet{Keys: []jose.JSONWebKey{jwk}}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(jwks)
}

func (idp *testIDP) defaultTokenHandler(w http.ResponseWriter, _ *http.Request) {
	idp.writeTokenResponse(w, nil)
}

func (idp *testIDP) defaultUserinfoHandler(w http.ResponseWriter, _ *http.Request) {
	resp := map[string]interface{}{
		"sub":   "upstream-user-123",
		"email": "user@example.com",
		"name":  "Test User",
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

func (idp *testIDP) writeTokenResponse(w http.ResponseWriter, overrideClaims map[string]interface{}) {
	claims := map[string]interface{}{
		"iss":   idp.issuer,
		"sub":   "upstream-user-123",
		"aud":   idp.clientID,
		"exp":   time.Now().Add(time.Hour).Unix(),
		"iat":   time.Now().Unix(),
		"nonce": "test-nonce",
		"email": "user@example.com",
	}
	for k, v := range overrideClaims {
		claims[k] = v
	}
	idToken := idp.signClaims(claims)
	resp := map[string]string{"id_token": idToken, "access_token": "test-access-token"}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

func (idp *testIDP) signClaims(claims map[string]interface{}) string {
	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.ES256, Key: idp.key},
		(&jose.SignerOptions{}).WithType("JWT").WithHeader(jose.HeaderKey("kid"), idp.kid),
	)
	if err != nil {
		panic(err)
	}
	payload, _ := json.Marshal(claims)
	jws, err := signer.Sign(payload)
	if err != nil {
		panic(err)
	}
	s, _ := jws.CompactSerialize()
	return s
}

func obs() *observability.Provider {
	return observability.NewNoop()
}

func testClient() oidc.Option {
	return oidc.WithHTTPClient(&http.Client{Timeout: 10 * time.Second})
}

// --- Tests: Discovery (18.1-18.3) ---

func TestDiscovery_Success(t *testing.T) {
	idp := newTestIDP(t)
	defer idp.close()

	p, err := oidc.New(context.Background(), idp.issuer, "test-client", "test-secret", nil, false, "", obs(), testClient())
	if err != nil {
		t.Fatalf("expected success, got: %v", err)
	}

	url := p.AuthorizationURL("state123", "nonce123", "", "http://localhost/callback")
	if url == "" {
		t.Fatal("AuthorizationURL returned empty")
	}
}

func TestDiscovery_InvalidIssuer(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		doc := map[string]string{
			"issuer":                 "https://wrong-issuer.example.com",
			"authorization_endpoint": "https://wrong-issuer.example.com/authorize",
			"token_endpoint":         "https://wrong-issuer.example.com/token",
			"jwks_uri":               "https://wrong-issuer.example.com/jwks",
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(doc)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	_, err := oidc.New(context.Background(), srv.URL, "client", "secret", nil, false, "", obs(), testClient())
	if err == nil {
		t.Fatal("expected error for issuer mismatch")
	}
}

func TestDiscovery_MissingFields(t *testing.T) {
	tests := []struct {
		name string
		doc  map[string]string
	}{
		{"missing authorization_endpoint", map[string]string{
			"issuer": "ISSUER", "token_endpoint": "ISSUER/token", "jwks_uri": "ISSUER/jwks",
		}},
		{"missing token_endpoint", map[string]string{
			"issuer": "ISSUER", "authorization_endpoint": "ISSUER/auth", "jwks_uri": "ISSUER/jwks",
		}},
		{"missing jwks_uri", map[string]string{
			"issuer": "ISSUER", "authorization_endpoint": "ISSUER/auth", "token_endpoint": "ISSUER/token",
		}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var srvURL string
			mux := http.NewServeMux()
			mux.HandleFunc("GET /.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
				doc := make(map[string]string, len(tt.doc))
				for k, v := range tt.doc {
					if v == "ISSUER" {
						doc[k] = srvURL
					} else if len(v) > 6 && v[:6] == "ISSUER" {
						doc[k] = srvURL + v[6:]
					} else {
						doc[k] = v
					}
				}
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(doc)
			})
			srv := httptest.NewServer(mux)
			srvURL = srv.URL
			defer srv.Close()

			_, err := oidc.New(context.Background(), srv.URL, "client", "secret", nil, false, "", obs(), testClient())
			if err == nil {
				t.Fatal("expected error for missing field")
			}
		})
	}
}

// --- Tests: JWKS (18.5) ---

func TestJWKSCache_HitAndMiss(t *testing.T) {
	idp := newTestIDP(t)
	defer idp.close()

	p, err := oidc.New(context.Background(), idp.issuer, "test-client", "test-secret", nil, false, "", obs(), testClient())
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	// Rotate to a new key (different kid) on the IDP side.
	newKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	newKid := "test-kid-2"
	idp.key = newKey
	idp.kid = newKid
	// Now the JWKS endpoint serves the new key.
	// The provider's cache still has the old key.

	// Set token handler to sign with the new key.
	idp.tokenHandler = func(w http.ResponseWriter, r *http.Request) {
		idp.writeTokenResponse(w, nil)
	}

	// ExchangeCode should trigger a JWKS re-fetch (kid miss) and succeed.
	result, err := p.ExchangeCode(context.Background(), "auth-code", "test-nonce", "", "http://localhost/callback")
	if err != nil {
		t.Fatalf("ExchangeCode after key rotation: %v", err)
	}
	if result.Subject != "upstream-user-123" {
		t.Errorf("Subject = %q, want upstream-user-123", result.Subject)
	}
}

// --- Tests: ID Token Validation (18.7-18.13) ---

func TestIDToken_ValidSignature(t *testing.T) {
	idp := newTestIDP(t)
	defer idp.close()

	p, err := oidc.New(context.Background(), idp.issuer, "test-client", "test-secret", nil, false, "", obs(), testClient())
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	result, err := p.ExchangeCode(context.Background(), "auth-code", "test-nonce", "", "http://localhost/callback")
	if err != nil {
		t.Fatalf("ExchangeCode: %v", err)
	}
	if result.Subject != "upstream-user-123" {
		t.Errorf("Subject = %q", result.Subject)
	}
	if result.Email != "user@example.com" {
		t.Errorf("Email = %q", result.Email)
	}
	if result.Issuer != idp.issuer {
		t.Errorf("Issuer = %q", result.Issuer)
	}
}

func TestIDToken_InvalidSignature(t *testing.T) {
	idp := newTestIDP(t)
	defer idp.close()

	otherKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	// Override token handler to sign with a different key.
	idp.tokenHandler = func(w http.ResponseWriter, _ *http.Request) {
		signer, _ := jose.NewSigner(
			jose.SigningKey{Algorithm: jose.ES256, Key: otherKey},
			(&jose.SignerOptions{}).WithType("JWT").WithHeader(jose.HeaderKey("kid"), idp.kid),
		)
		claims, _ := json.Marshal(map[string]interface{}{
			"iss": idp.issuer, "sub": "user", "aud": "test-client",
			"exp": time.Now().Add(time.Hour).Unix(), "nonce": "test-nonce",
		})
		jws, _ := signer.Sign(claims)
		s, _ := jws.CompactSerialize()
		resp := map[string]string{"id_token": s}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}

	p, err := oidc.New(context.Background(), idp.issuer, "test-client", "test-secret", nil, false, "", obs(), testClient())
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	_, err = p.ExchangeCode(context.Background(), "code", "test-nonce", "", "http://localhost/callback")
	if err == nil {
		t.Fatal("expected error for invalid signature")
	}
}

func TestIDToken_NonceMismatch(t *testing.T) {
	idp := newTestIDP(t)
	defer idp.close()

	p, err := oidc.New(context.Background(), idp.issuer, "test-client", "test-secret", nil, false, "", obs(), testClient())
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	// The token has nonce="test-nonce" but we pass "wrong-nonce".
	_, err = p.ExchangeCode(context.Background(), "code", "wrong-nonce", "", "http://localhost/callback")
	if err == nil {
		t.Fatal("expected error for nonce mismatch")
	}
}

func TestIDToken_AudMismatch(t *testing.T) {
	idp := newTestIDP(t)
	defer idp.close()

	idp.tokenHandler = func(w http.ResponseWriter, _ *http.Request) {
		idp.writeTokenResponse(w, map[string]interface{}{
			"aud": "wrong-client-id",
		})
	}

	p, err := oidc.New(context.Background(), idp.issuer, "test-client", "test-secret", nil, false, "", obs(), testClient())
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	_, err = p.ExchangeCode(context.Background(), "code", "test-nonce", "", "http://localhost/callback")
	if err == nil {
		t.Fatal("expected error for audience mismatch")
	}
}

func TestIDToken_Expired(t *testing.T) {
	idp := newTestIDP(t)
	defer idp.close()

	idp.tokenHandler = func(w http.ResponseWriter, _ *http.Request) {
		idp.writeTokenResponse(w, map[string]interface{}{
			"exp": time.Now().Add(-time.Hour).Unix(),
		})
	}

	p, err := oidc.New(context.Background(), idp.issuer, "test-client", "test-secret", nil, false, "", obs(), testClient())
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	_, err = p.ExchangeCode(context.Background(), "code", "test-nonce", "", "http://localhost/callback")
	if err == nil {
		t.Fatal("expected error for expired token")
	}
}

func TestIDToken_IssMismatch(t *testing.T) {
	idp := newTestIDP(t)
	defer idp.close()

	idp.tokenHandler = func(w http.ResponseWriter, _ *http.Request) {
		idp.writeTokenResponse(w, map[string]interface{}{
			"iss": "https://wrong-issuer.example.com",
		})
	}

	p, err := oidc.New(context.Background(), idp.issuer, "test-client", "test-secret", nil, false, "", obs(), testClient())
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	_, err = p.ExchangeCode(context.Background(), "code", "test-nonce", "", "http://localhost/callback")
	if err == nil {
		t.Fatal("expected error for issuer mismatch")
	}
}

func TestIDToken_AlgNone(t *testing.T) {
	idp := newTestIDP(t)
	defer idp.close()

	idp.tokenHandler = func(w http.ResponseWriter, _ *http.Request) {
		// Craft an unsigned JWT (alg=none) manually.
		claims := josejwt.Claims{
			Issuer:   idp.issuer,
			Subject:  "user",
			Audience: josejwt.Audience{idp.clientID},
			Expiry:   josejwt.NewNumericDate(time.Now().Add(time.Hour)),
		}
		header := `{"alg":"none","typ":"JWT"}`
		payload, _ := json.Marshal(claims)
		b64 := base64.RawURLEncoding.EncodeToString
		unsignedToken := fmt.Sprintf("%s.%s.", b64([]byte(header)), b64(payload))
		resp := map[string]string{"id_token": unsignedToken}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}

	p, err := oidc.New(context.Background(), idp.issuer, "test-client", "test-secret", nil, false, "", obs(), testClient())
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	_, err = p.ExchangeCode(context.Background(), "code", "test-nonce", "", "http://localhost/callback")
	if err == nil {
		t.Fatal("expected error for alg=none token")
	}
}

func TestAuthorizationURL_ContainsRequiredParams(t *testing.T) {
	idp := newTestIDP(t)
	defer idp.close()

	p, err := oidc.New(context.Background(), idp.issuer, "test-client", "test-secret", []string{"openid", "email"}, false, "", obs(), testClient())
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	u := p.AuthorizationURL("state-abc", "nonce-xyz", "", "http://localhost/callback")
	for _, want := range []string{
		"response_type=code",
		"client_id=test-client",
		"state=state-abc",
		"nonce=nonce-xyz",
		"redirect_uri=",
		"scope=openid+email",
	} {
		if !stringContains(u, want) {
			t.Errorf("URL missing %q:\n  %s", want, u)
		}
	}
}

// --- New Tests: PKCE ---

func TestAuthorizationURL_IncludesPKCE(t *testing.T) {
	idp := newTestIDP(t)
	defer idp.close()

	p, err := oidc.New(context.Background(), idp.issuer, "test-client", "test-secret", nil, false, "", obs(), testClient())
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	u := p.AuthorizationURL("state-abc", "nonce-xyz", "test-challenge-value", "http://localhost/callback")
	if !stringContains(u, "code_challenge=test-challenge-value") {
		t.Errorf("URL missing code_challenge:\n  %s", u)
	}
	if !stringContains(u, "code_challenge_method=S256") {
		t.Errorf("URL missing code_challenge_method=S256:\n  %s", u)
	}
}

func TestExchangeCode_SendsCodeVerifier(t *testing.T) {
	idp := newTestIDP(t)
	defer idp.close()

	var receivedVerifier string
	idp.tokenHandler = func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()
		receivedVerifier = r.FormValue("code_verifier")
		idp.writeTokenResponse(w, nil)
	}

	p, err := oidc.New(context.Background(), idp.issuer, "test-client", "test-secret", nil, false, "", obs(), testClient())
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	_, err = p.ExchangeCode(context.Background(), "test-code", "test-nonce", "my-test-verifier", "http://localhost/callback")
	if err != nil {
		t.Fatalf("ExchangeCode: %v", err)
	}
	if receivedVerifier != "my-test-verifier" {
		t.Errorf("code_verifier = %q, want my-test-verifier", receivedVerifier)
	}
}

// --- New Tests: Dex connector_id ---

func TestDexConnectorID_AppendsParam(t *testing.T) {
	idp := newTestIDP(t)
	defer idp.close()

	p, err := oidc.New(context.Background(), idp.issuer, "test-client", "test-secret", nil, false, "github-connector", obs(), testClient())
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	u := p.AuthorizationURL("state", "nonce", "", "http://localhost/callback")
	if !stringContains(u, "connector_id=github-connector") {
		t.Errorf("URL missing connector_id:\n  %s", u)
	}
}

// --- New Tests: Groups scope ---

func TestGroupsScope_AutoIncluded(t *testing.T) {
	idp := newTestIDP(t)
	idp.scopesSupported = []string{"openid", "email", "profile", "groups"}
	defer idp.close()

	p, err := oidc.New(context.Background(), idp.issuer, "test-client", "test-secret",
		[]string{"openid", "email"}, true, "", obs(), testClient())
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	u := p.AuthorizationURL("state", "nonce", "", "http://localhost/callback")
	if !stringContains(u, "groups") {
		t.Errorf("URL should include groups scope when includeGroupsScope=true and upstream supports it:\n  %s", u)
	}
}

func TestGroupsScope_OptOut(t *testing.T) {
	idp := newTestIDP(t)
	idp.scopesSupported = []string{"openid", "email", "profile", "groups"}
	defer idp.close()

	p, err := oidc.New(context.Background(), idp.issuer, "test-client", "test-secret",
		[]string{"openid", "email"}, false, "", obs(), testClient())
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	u := p.AuthorizationURL("state", "nonce", "", "http://localhost/callback")
	if stringContains(u, "groups") {
		t.Errorf("URL should NOT include groups scope when includeGroupsScope=false:\n  %s", u)
	}
}

func TestGroupsScope_NotIncludedWhenUpstreamDoesNotSupport(t *testing.T) {
	idp := newTestIDP(t)
	idp.scopesSupported = []string{"openid", "email", "profile"}
	defer idp.close()

	p, err := oidc.New(context.Background(), idp.issuer, "test-client", "test-secret",
		[]string{"openid", "email"}, true, "", obs(), testClient())
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	u := p.AuthorizationURL("state", "nonce", "", "http://localhost/callback")
	if stringContains(u, "groups") {
		t.Errorf("URL should NOT include groups when upstream doesn't support it:\n  %s", u)
	}
}

// --- New Tests: GetUserInfo ---

func TestGetUserInfo_Success(t *testing.T) {
	idp := newTestIDP(t)
	defer idp.close()

	p, err := oidc.New(context.Background(), idp.issuer, "test-client", "test-secret", nil, false, "", obs(), testClient())
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	info, err := p.GetUserInfo(context.Background(), "test-access-token")
	if err != nil {
		t.Fatalf("GetUserInfo: %v", err)
	}
	if info == nil {
		t.Fatal("GetUserInfo returned nil")
	}
	if info.Subject != "upstream-user-123" {
		t.Errorf("Subject = %q, want upstream-user-123", info.Subject)
	}
	if info.Email != "user@example.com" {
		t.Errorf("Email = %q, want user@example.com", info.Email)
	}
	if info.Name != "Test User" {
		t.Errorf("Name = %q, want Test User", info.Name)
	}
}

func TestGetUserInfo_NoEndpoint(t *testing.T) {
	// Create an IDP without userinfo_endpoint in discovery.
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	mux := http.NewServeMux()
	var srvURL string
	mux.HandleFunc("GET /.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		doc := map[string]string{
			"issuer":                 srvURL,
			"authorization_endpoint": srvURL + "/authorize",
			"token_endpoint":         srvURL + "/token",
			"jwks_uri":               srvURL + "/jwks",
			// No userinfo_endpoint
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(doc)
	})
	mux.HandleFunc("GET /jwks", func(w http.ResponseWriter, _ *http.Request) {
		jwk := jose.JSONWebKey{Key: key.Public(), KeyID: "k1", Algorithm: string(jose.ES256), Use: "sig"}
		jwks := jose.JSONWebKeySet{Keys: []jose.JSONWebKey{jwk}}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(jwks)
	})
	srv := httptest.NewServer(mux)
	srvURL = srv.URL
	defer srv.Close()

	p, err := oidc.New(context.Background(), srvURL, "test-client", "test-secret", nil, false, "", obs(), testClient())
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	info, err := p.GetUserInfo(context.Background(), "test-access-token")
	if err != nil {
		t.Fatalf("GetUserInfo: %v", err)
	}
	if info != nil {
		t.Error("GetUserInfo should return nil when no userinfo_endpoint")
	}
}

// --- New Tests: No redirects (SSRF) ---

func TestSSRF_NoRedirects(t *testing.T) {
	// Server that redirects discovery to another location.
	mux := http.NewServeMux()
	mux.HandleFunc("GET /.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "https://evil.example.com/.well-known/openid-configuration", http.StatusFound)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	// Use a client that blocks redirects (like the production one).
	noRedirectClient := &http.Client{
		Timeout: 10 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	_, err := oidc.New(context.Background(), srv.URL, "client", "secret", nil, false, "",
		obs(), oidc.WithHTTPClient(noRedirectClient))
	if err == nil {
		t.Fatal("expected error when discovery redirects")
	}
}

// --- New Tests: Name and Groups in ID token claims ---

func TestIDToken_NameAndGroups(t *testing.T) {
	idp := newTestIDP(t)
	defer idp.close()

	idp.tokenHandler = func(w http.ResponseWriter, _ *http.Request) {
		idp.writeTokenResponse(w, map[string]interface{}{
			"name":   "Alice Smith",
			"groups": []string{"engineering", "admin"},
		})
	}

	p, err := oidc.New(context.Background(), idp.issuer, "test-client", "test-secret", nil, false, "", obs(), testClient())
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	result, err := p.ExchangeCode(context.Background(), "code", "test-nonce", "", "http://localhost/callback")
	if err != nil {
		t.Fatalf("ExchangeCode: %v", err)
	}
	if result.Name != "Alice Smith" {
		t.Errorf("Name = %q, want Alice Smith", result.Name)
	}
	if len(result.Groups) != 2 || result.Groups[0] != "engineering" {
		t.Errorf("Groups = %v, want [engineering admin]", result.Groups)
	}
}

func stringContains(s, sub string) bool {
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
