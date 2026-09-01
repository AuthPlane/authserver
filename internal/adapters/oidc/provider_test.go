//go:build integration

package oidc_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	josejwt "github.com/go-jose/go-jose/v4/jwt"

	"github.com/authplane/authserver/internal/adapters/oidc"
	"github.com/authplane/authserver/internal/domain"
	"github.com/authplane/authserver/internal/observability"
	"github.com/authplane/authserver/internal/ports/output"
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

	// rotateAfterFirstJWKS, when set, makes the JWKS endpoint serve oldKey on
	// its first request and key (the rotated key) on every subsequent request.
	// Other tests leave it false and always get the current key.
	rotateAfterFirstJWKS bool
	oldKey               *ecdsa.PrivateKey
	oldKid               string
	failJWKSAfterFirst   bool         // when set, the JWKS endpoint 500s on its 2nd+ request
	jwksRequests         atomic.Int32 // number of JWKS requests served
	discoveryRequests    atomic.Int32 // number of discovery requests served
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
	idp.discoveryRequests.Add(1)
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
	n := idp.jwksRequests.Add(1)
	if idp.failJWKSAfterFirst && n >= 2 {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	pub, kid := idp.key.Public(), idp.kid
	// On the first request, optionally serve the OLD key set so that a token
	// signed with the rotated kid forces a re-fetch within a single call.
	if idp.rotateAfterFirstJWKS && n == 1 {
		pub, kid = idp.oldKey.Public(), idp.oldKid
	}
	jwk := jose.JSONWebKey{
		Key:       pub,
		KeyID:     kid,
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

// stubConfig is a test output.OIDCConfigProvider returning a fixed config (or err).
type stubConfig struct {
	cfg output.OIDCConfig
	err error
}

func (s stubConfig) Config(context.Context) (output.OIDCConfig, error) {
	return s.cfg, s.err
}

// staticConfig builds an output.OIDCConfigProvider for tests.
// The secret is carried as inline plaintext bytes (ClientSecret []byte);
// resolution to plaintext happens JIT in exchangeCode via fakeSecretResolver.
func staticConfig(issuer, clientID, secret, redirect string, scopes []string, groups bool, connector string) output.OIDCConfigProvider {
	return stubConfig{cfg: output.OIDCConfig{
		Issuer:             issuer,
		ClientID:           clientID,
		ClientSecret:       []byte(secret), // raw bytes, resolved JIT by secretResolver
		RedirectURI:        redirect,
		Scopes:             scopes,
		IncludeGroupsScope: groups,
		ConnectorID:        connector,
	}}
}

// fakeSecretResolver is a test SecretResolver that returns the Data as-is
// (treating it as already-plaintext), mirroring ConfigSecretBackend behaviour
// when no encryptor is configured (the OSS OIDC inline-secret path).
type fakeSecretResolver struct{}

func (fakeSecretResolver) Resolve(_ context.Context, src output.SecretSource) (string, error) {
	// For the Data path (OIDC inline): return bytes as-is.
	if len(src.Data) > 0 {
		return string(src.Data), nil
	}
	return "", nil
}

// testResolver returns a fakeSecretResolver suitable for integration tests.
func testResolver() output.SecretResolver { return fakeSecretResolver{} }

// --- Tests: Discovery (18.1-18.3) ---

func TestDiscovery_Success(t *testing.T) {
	idp := newTestIDP(t)
	defer idp.close()

	p := oidc.New(staticConfig(idp.issuer, "test-client", "test-secret", "http://localhost/callback", nil, false, ""), testResolver(), obs(), testClient())

	url, err := p.AuthorizationURL(context.Background(), "state123", "nonce123", "")
	if err != nil {
		t.Fatalf("AuthorizationURL: %v", err)
	}
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

	p := oidc.New(staticConfig(srv.URL, "client", "secret", "http://localhost/callback", nil, false, ""), testResolver(), obs(), testClient())
	if _, err := p.AuthorizationURL(context.Background(), "s", "n", ""); err == nil {
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

			p := oidc.New(staticConfig(srv.URL, "client", "secret", "http://localhost/callback", nil, false, ""), testResolver(), obs(), testClient())
			if _, err := p.AuthorizationURL(context.Background(), "s", "n", ""); err == nil {
				t.Fatal("expected error for missing field")
			}
		})
	}
}

// --- Tests: JWKS (18.5) ---

func TestJWKS_KidMissRefetch(t *testing.T) {
	idp := newTestIDP(t)
	defer idp.close()

	// Set up a key rotation that happens within a single ExchangeCode:
	//   - oldKey/oldKid: what the JWKS endpoint serves on its FIRST request.
	//   - key/kid (the rotated key): what it serves on every later request, and
	//     what the ID token is signed with.
	// This forces the within-call flow: initial resolveJWKS returns the old key
	// set, getKeys misses on the rotated kid, and the kid-miss branch re-fetches
	// via resolveJWKS, which now serves the new key set and hits.
	idp.oldKey = idp.key
	idp.oldKid = idp.kid
	newKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	idp.key = newKey
	idp.kid = "test-kid-2"
	idp.rotateAfterFirstJWKS = true

	// Sign the ID token with the new (rotated) key.
	idp.tokenHandler = func(w http.ResponseWriter, _ *http.Request) {
		idp.writeTokenResponse(w, nil)
	}

	p := oidc.New(staticConfig(idp.issuer, "test-client", "test-secret", "http://localhost/callback", nil, false, ""), testResolver(), obs(), testClient())

	// ExchangeCode should trigger a JWKS re-fetch (kid miss) and succeed.
	result, err := p.ExchangeCode(context.Background(), "auth-code", "test-nonce", "")
	if err != nil {
		t.Fatalf("ExchangeCode after key rotation: %v", err)
	}
	if result.Subject != "upstream-user-123" {
		t.Errorf("Subject = %q, want upstream-user-123", result.Subject)
	}
	// The miss path must have been taken: the JWKS endpoint was hit at least
	// twice (initial old-key fetch + re-fetch serving the rotated key).
	if got := idp.jwksRequests.Load(); got < 2 {
		t.Errorf("JWKS endpoint hit %d time(s), want >= 2 (kid-miss re-fetch not taken)", got)
	}
}

// --- Tests: ID Token Validation (18.7-18.13) ---

func TestIDToken_ValidSignature(t *testing.T) {
	idp := newTestIDP(t)
	defer idp.close()

	p := oidc.New(staticConfig(idp.issuer, "test-client", "test-secret", "http://localhost/callback", nil, false, ""), testResolver(), obs(), testClient())

	result, err := p.ExchangeCode(context.Background(), "auth-code", "test-nonce", "")
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

	p := oidc.New(staticConfig(idp.issuer, "test-client", "test-secret", "http://localhost/callback", nil, false, ""), testResolver(), obs(), testClient())

	_, err := p.ExchangeCode(context.Background(), "code", "test-nonce", "")
	if err == nil {
		t.Fatal("expected error for invalid signature")
	}
}

func TestIDToken_NonceMismatch(t *testing.T) {
	idp := newTestIDP(t)
	defer idp.close()

	p := oidc.New(staticConfig(idp.issuer, "test-client", "test-secret", "http://localhost/callback", nil, false, ""), testResolver(), obs(), testClient())

	// The token has nonce="test-nonce" but we pass "wrong-nonce".
	_, err := p.ExchangeCode(context.Background(), "code", "wrong-nonce", "")
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

	p := oidc.New(staticConfig(idp.issuer, "test-client", "test-secret", "http://localhost/callback", nil, false, ""), testResolver(), obs(), testClient())

	_, err := p.ExchangeCode(context.Background(), "code", "test-nonce", "")
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

	p := oidc.New(staticConfig(idp.issuer, "test-client", "test-secret", "http://localhost/callback", nil, false, ""), testResolver(), obs(), testClient())

	_, err := p.ExchangeCode(context.Background(), "code", "test-nonce", "")
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

	p := oidc.New(staticConfig(idp.issuer, "test-client", "test-secret", "http://localhost/callback", nil, false, ""), testResolver(), obs(), testClient())

	_, err := p.ExchangeCode(context.Background(), "code", "test-nonce", "")
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

	p := oidc.New(staticConfig(idp.issuer, "test-client", "test-secret", "http://localhost/callback", nil, false, ""), testResolver(), obs(), testClient())

	_, err := p.ExchangeCode(context.Background(), "code", "test-nonce", "")
	if err == nil {
		t.Fatal("expected error for alg=none token")
	}
}

func TestAuthorizationURL_ContainsRequiredParams(t *testing.T) {
	idp := newTestIDP(t)
	defer idp.close()

	p := oidc.New(staticConfig(idp.issuer, "test-client", "test-secret", "http://localhost/callback", []string{"openid", "email"}, false, ""), testResolver(), obs(), testClient())

	u, err := p.AuthorizationURL(context.Background(), "state-abc", "nonce-xyz", "")
	if err != nil {
		t.Fatalf("AuthorizationURL: %v", err)
	}
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

	p := oidc.New(staticConfig(idp.issuer, "test-client", "test-secret", "http://localhost/callback", nil, false, ""), testResolver(), obs(), testClient())

	u, err := p.AuthorizationURL(context.Background(), "state-abc", "nonce-xyz", "test-challenge-value")
	if err != nil {
		t.Fatalf("AuthorizationURL: %v", err)
	}
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

	p := oidc.New(staticConfig(idp.issuer, "test-client", "test-secret", "http://localhost/callback", nil, false, ""), testResolver(), obs(), testClient())

	_, err := p.ExchangeCode(context.Background(), "test-code", "test-nonce", "my-test-verifier")
	if err != nil {
		t.Fatalf("ExchangeCode: %v", err)
	}
	if receivedVerifier != "my-test-verifier" {
		t.Errorf("code_verifier = %q, want my-test-verifier", receivedVerifier)
	}
}

// emptySecretResolver always resolves to an empty secret, modelling an env var
// that is present but blank.
type emptySecretResolver struct{}

func (emptySecretResolver) Resolve(_ context.Context, _ output.SecretSource) (string, error) {
	return "", nil
}

// TestExchangeCode_EmptyResolvedSecret_FailsClosed verifies exchangeCode aborts
// before the token POST when the resolved client secret is empty, rather than
// sending SetBasicAuth(clientID, "") — mirroring the broker adapters' guard.
func TestExchangeCode_EmptyResolvedSecret_FailsClosed(t *testing.T) {
	idp := newTestIDP(t)
	defer idp.close()

	tokenCalled := false
	idp.tokenHandler = func(w http.ResponseWriter, _ *http.Request) {
		tokenCalled = true
		idp.writeTokenResponse(w, nil)
	}

	p := oidc.New(staticConfig(idp.issuer, "test-client", "secret", "http://localhost/callback", nil, false, ""), emptySecretResolver{}, obs(), testClient())

	if _, err := p.ExchangeCode(context.Background(), "code", "test-nonce", ""); err == nil {
		t.Fatal("expected error when resolved client secret is empty")
	}
	if tokenCalled {
		t.Error("token endpoint must not be called when the secret resolves empty (fail-closed)")
	}
}

// --- New Tests: Dex connector_id ---

func TestDexConnectorID_AppendsParam(t *testing.T) {
	idp := newTestIDP(t)
	defer idp.close()

	p := oidc.New(staticConfig(idp.issuer, "test-client", "test-secret", "http://localhost/callback", nil, false, "github-connector"), testResolver(), obs(), testClient())

	u, err := p.AuthorizationURL(context.Background(), "state", "nonce", "")
	if err != nil {
		t.Fatalf("AuthorizationURL: %v", err)
	}
	if !stringContains(u, "connector_id=github-connector") {
		t.Errorf("URL missing connector_id:\n  %s", u)
	}
}

// --- New Tests: Groups scope ---

func TestGroupsScope_AutoIncluded(t *testing.T) {
	idp := newTestIDP(t)
	idp.scopesSupported = []string{"openid", "email", "profile", "groups"}
	defer idp.close()

	p := oidc.New(staticConfig(idp.issuer, "test-client", "test-secret", "http://localhost/callback",
		[]string{"openid", "email"}, true, ""), testResolver(), obs(), testClient())

	u, err := p.AuthorizationURL(context.Background(), "state", "nonce", "")
	if err != nil {
		t.Fatalf("AuthorizationURL: %v", err)
	}
	if !stringContains(u, "groups") {
		t.Errorf("URL should include groups scope when includeGroupsScope=true and upstream supports it:\n  %s", u)
	}
}

func TestGroupsScope_OptOut(t *testing.T) {
	idp := newTestIDP(t)
	idp.scopesSupported = []string{"openid", "email", "profile", "groups"}
	defer idp.close()

	p := oidc.New(staticConfig(idp.issuer, "test-client", "test-secret", "http://localhost/callback",
		[]string{"openid", "email"}, false, ""), testResolver(), obs(), testClient())

	u, err := p.AuthorizationURL(context.Background(), "state", "nonce", "")
	if err != nil {
		t.Fatalf("AuthorizationURL: %v", err)
	}
	if stringContains(u, "groups") {
		t.Errorf("URL should NOT include groups scope when includeGroupsScope=false:\n  %s", u)
	}
}

func TestGroupsScope_NotIncludedWhenUpstreamDoesNotSupport(t *testing.T) {
	idp := newTestIDP(t)
	idp.scopesSupported = []string{"openid", "email", "profile"}
	defer idp.close()

	p := oidc.New(staticConfig(idp.issuer, "test-client", "test-secret", "http://localhost/callback",
		[]string{"openid", "email"}, true, ""), testResolver(), obs(), testClient())

	u, err := p.AuthorizationURL(context.Background(), "state", "nonce", "")
	if err != nil {
		t.Fatalf("AuthorizationURL: %v", err)
	}
	if stringContains(u, "groups") {
		t.Errorf("URL should NOT include groups when upstream doesn't support it:\n  %s", u)
	}
}

// --- New Tests: GetUserInfo ---

func TestGetUserInfo_Success(t *testing.T) {
	idp := newTestIDP(t)
	defer idp.close()

	p := oidc.New(staticConfig(idp.issuer, "test-client", "test-secret", "http://localhost/callback", nil, false, ""), testResolver(), obs(), testClient())

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

	p := oidc.New(staticConfig(srvURL, "test-client", "test-secret", "http://localhost/callback", nil, false, ""), testResolver(), obs(), testClient())

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

	p := oidc.New(staticConfig(srv.URL, "client", "secret", "http://localhost/callback", nil, false, ""),
		testResolver(), obs(), oidc.WithHTTPClient(noRedirectClient))
	if _, err := p.AuthorizationURL(context.Background(), "s", "n", ""); err == nil {
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

	p := oidc.New(staticConfig(idp.issuer, "test-client", "test-secret", "http://localhost/callback", nil, false, ""), testResolver(), obs(), testClient())

	result, err := p.ExchangeCode(context.Background(), "code", "test-nonce", "")
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

func TestProvider_ConfigError_Propagates(t *testing.T) {
	p := oidc.New(stubConfig{err: errTestConfig}, testResolver(), obs())
	if _, err := p.AuthorizationURL(context.Background(), "s", "n", ""); err == nil {
		t.Fatal("AuthorizationURL: expected config error")
	}
	if _, err := p.ExchangeCode(context.Background(), "code", "nonce", "verifier"); err == nil {
		t.Fatal("ExchangeCode: expected config error")
	}
	if _, err := p.GetUserInfo(context.Background(), "token"); err == nil {
		t.Fatal("GetUserInfo: expected config error")
	}
}

var errTestConfig = errors.New("config boom")

func stringContains(s, sub string) bool {
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

// --- Tests: discovery/JWKS caching ---

func TestDiscovery_Cached(t *testing.T) {
	idp := newTestIDP(t)
	defer idp.close()
	p := oidc.New(staticConfig(idp.issuer, "test-client", "test-secret", "http://localhost/callback", nil, false, ""), testResolver(), obs(), testClient())

	for i := 0; i < 3; i++ {
		if _, err := p.AuthorizationURL(context.Background(), "s", "n", ""); err != nil {
			t.Fatalf("AuthorizationURL[%d]: %v", i, err)
		}
	}
	if got := idp.discoveryRequests.Load(); got != 1 {
		t.Errorf("discovery endpoint hit %d time(s) across 3 calls, want 1 (should be cached)", got)
	}
}

func TestValidate_WarmsCacheAndValidates(t *testing.T) {
	idp := newTestIDP(t)
	defer idp.close()
	p := oidc.New(staticConfig(idp.issuer, "test-client", "test-secret", "http://localhost/callback", nil, false, ""), testResolver(), obs(), testClient())

	if err := p.Validate(context.Background()); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if got := idp.discoveryRequests.Load(); got != 1 {
		t.Errorf("Validate should fetch discovery once, got %d", got)
	}
	// Validate warmed the cache → a subsequent call does not refetch.
	if _, err := p.AuthorizationURL(context.Background(), "s", "n", ""); err != nil {
		t.Fatalf("AuthorizationURL: %v", err)
	}
	if got := idp.discoveryRequests.Load(); got != 1 {
		t.Errorf("Validate should have warmed the cache; discovery hit %d times, want 1", got)
	}
}

func TestValidate_FailsOnUnreachableDiscovery(t *testing.T) {
	idp := newTestIDP(t)
	defer idp.close()
	// Issuer whose discovery endpoint 404s → Validate must fail (boot fail-fast).
	p := oidc.New(staticConfig(idp.issuer+"/nope", "c", "s", "http://localhost/callback", nil, false, ""), testResolver(), obs(), testClient())
	if err := p.Validate(context.Background()); err == nil {
		t.Fatal("Validate: expected error for unreachable discovery endpoint")
	}
}

// recordingJWKSCache is a test oidc.Cache that delegates to fetch but counts
// Loads, to prove WithJWKSCache wires an alternate cache into the Provider.
type recordingJWKSCache struct{ loads atomic.Int32 }

func (c *recordingJWKSCache) Load(_ context.Context, _ string, fetch func() (*jose.JSONWebKeySet, error)) (*jose.JSONWebKeySet, error) {
	c.loads.Add(1)
	return fetch()
}
func (c *recordingJWKSCache) Fresh(context.Context, string) (*jose.JSONWebKeySet, bool) {
	return nil, false
}
func (c *recordingJWKSCache) Peek(context.Context, string) (*jose.JSONWebKeySet, bool) {
	return nil, false
}
func (c *recordingJWKSCache) Store(context.Context, string, *jose.JSONWebKeySet) {}

func TestWithJWKSCache_InjectsAlternateCache(t *testing.T) {
	idp := newTestIDP(t)
	defer idp.close()

	custom := &recordingJWKSCache{}
	p := oidc.New(
		staticConfig(idp.issuer, "test-client", "test-secret", "http://localhost/callback", nil, false, ""),
		testResolver(), obs(), testClient(), oidc.WithJWKSCache(custom),
	)

	if _, err := p.ExchangeCode(context.Background(), "auth-code", "test-nonce", ""); err != nil {
		t.Fatalf("ExchangeCode: %v", err)
	}
	if got := custom.loads.Load(); got == 0 {
		t.Error("WithJWKSCache: the injected cache was not consulted")
	}
}

func TestExchangeCode_InfraError_IsUnavailable(t *testing.T) {
	// Config resolution failing is an infrastructure error → tagged with
	// domain.ErrOIDCUnavailable so the handler maps it to 500, not 401.
	p := oidc.New(stubConfig{err: errors.New("config source down")}, testResolver(), obs())
	if _, err := p.ExchangeCode(context.Background(), "code", "nonce", ""); !errors.Is(err, domain.ErrOIDCUnavailable) {
		t.Fatalf("ExchangeCode on config error: want errors.Is(domain.ErrOIDCUnavailable), got %v", err)
	}

	// Discovery failing (unreachable issuer) is likewise infra.
	idp := newTestIDP(t)
	defer idp.close()
	p2 := oidc.New(staticConfig(idp.issuer+"/nope", "c", "s", "http://localhost/callback", nil, false, ""), testResolver(), obs(), testClient())
	if _, err := p2.ExchangeCode(context.Background(), "code", "nonce", ""); !errors.Is(err, domain.ErrOIDCUnavailable) {
		t.Fatalf("ExchangeCode on discovery error: want errors.Is(domain.ErrOIDCUnavailable), got %v", err)
	}
}

func TestExchangeCode_JWKSRefreshFails_IsUnavailable(t *testing.T) {
	idp := newTestIDP(t)
	defer idp.close()

	// First JWKS request serves an unrelated key so the token's kid misses; the
	// kid-miss refresh (2nd request) then fails with 500. The resulting error
	// must be tagged domain.ErrOIDCUnavailable (infra), so the callback → 500.
	otherKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	idp.oldKey = otherKey
	idp.oldKid = "unrelated-kid"
	idp.rotateAfterFirstJWKS = true
	idp.failJWKSAfterFirst = true

	idp.tokenHandler = func(w http.ResponseWriter, _ *http.Request) {
		idp.writeTokenResponse(w, nil) // signed with idp.key / idp.kid
	}

	p := oidc.New(staticConfig(idp.issuer, "test-client", "test-secret", "http://localhost/callback", nil, false, ""), testResolver(), obs(), testClient())
	if _, err := p.ExchangeCode(context.Background(), "auth-code", "test-nonce", ""); !errors.Is(err, domain.ErrOIDCUnavailable) {
		t.Fatalf("ExchangeCode with failing JWKS refresh: want errors.Is(domain.ErrOIDCUnavailable), got %v", err)
	}
}

func TestExchangeCode_TokenEndpoint5xx_IsUnavailable(t *testing.T) {
	idp := newTestIDP(t)
	defer idp.close()
	// Token endpoint returns 503 (IdP overloaded/down) — infra, not bad creds.
	idp.tokenHandler = func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}
	p := oidc.New(staticConfig(idp.issuer, "test-client", "test-secret", "http://localhost/callback", nil, false, ""), testResolver(), obs(), testClient())
	if _, err := p.ExchangeCode(context.Background(), "code", "test-nonce", ""); !errors.Is(err, domain.ErrOIDCUnavailable) {
		t.Fatalf("token endpoint 503: want errors.Is(domain.ErrOIDCUnavailable), got %v", err)
	}
}

func TestExchangeCode_TokenEndpoint4xx_IsNotUnavailable(t *testing.T) {
	idp := newTestIDP(t)
	defer idp.close()
	// Token endpoint returns 400 (invalid_grant) — a genuine credential failure
	// that must stay a 401, i.e. NOT tagged ErrOIDCUnavailable.
	idp.tokenHandler = func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
	}
	p := oidc.New(staticConfig(idp.issuer, "test-client", "test-secret", "http://localhost/callback", nil, false, ""), testResolver(), obs(), testClient())
	_, err := p.ExchangeCode(context.Background(), "code", "test-nonce", "")
	if err == nil {
		t.Fatal("token endpoint 400: expected error")
	}
	if errors.Is(err, domain.ErrOIDCUnavailable) {
		t.Fatalf("token endpoint 400 is a credential failure, must NOT be tagged unavailable: %v", err)
	}
}
