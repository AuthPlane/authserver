//go:build integration

package public_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"

	apipublic "github.com/authplane/authserver/api/public"
	"github.com/authplane/authserver/internal/adapters/keyfile"
	"github.com/authplane/authserver/internal/crypto"
	"github.com/authplane/authserver/internal/domain/client"
	"github.com/authplane/authserver/internal/domain/user"
	"github.com/authplane/authserver/internal/services"
	"github.com/authplane/authserver/testdata"
)

// introspectTestEnv holds the test environment for introspection HTTP tests.
type introspectTestEnv struct {
	ts       *httptest.Server
	kp       *crypto.KeyPair
	clientID string
}

func newIntrospectTestServer(t *testing.T) *introspectTestEnv {
	t.Helper()

	stores := testdata.SetupTestStores(t)
	obs := testObs()

	// Key store + JWKS service.
	dir := t.TempDir()
	ks, err := keyfile.New(dir, obs)
	if err != nil {
		t.Fatalf("keyfile: %v", err)
	}
	jwksSvc := services.NewJWKSService(ks, nil, "ES256", obs)

	// Get signing key and build a key pair for signing test tokens.
	sk, err := jwksSvc.GetSigningKey(t.Context())
	if err != nil {
		t.Fatalf("get signing key: %v", err)
	}
	kp := &crypto.KeyPair{
		PrivateKey: sk.PrivateKey,
		PublicKey:  sk.PublicKey,
		Algorithm:  jose.SignatureAlgorithm(sk.Algorithm),
		KeyID:      sk.KeyID,
	}

	// Create a test client (confidential).
	secretHash, err := crypto.HashBcrypt("test-secret")
	if err != nil {
		t.Fatalf("hash bcrypt: %v", err)
	}
	c := &client.Client{
		ID:           "introspect-http-client",
		SecretHash:   secretHash,
		RedirectURIs: []string{"http://localhost/callback"},
		Status:       client.StatusActive,
		IssuedAt:     time.Now(),
	}
	if err := stores.Client.Create(t.Context(), c); err != nil {
		t.Fatalf("create client: %v", err)
	}

	// Create the user referenced by test tokens (subject "user-1").
	testUser := &user.User{
		ID:       "user-1",
		Email:    "user1@example.com",
		Status:   user.StatusActive,
		Role:     user.RoleUser,
		Provider: user.ProviderLocal,
	}
	if err := stores.User.Create(t.Context(), testUser); err != nil {
		t.Fatalf("create user: %v", err)
	}

	// Create introspection service.
	introspectSvc := services.NewIntrospectionService(
		jwksSvc, stores.Revocation, stores.MachineToken, stores.Client, stores.User,
		staticIssuerForTest("https://auth.example.com"), obs, nil,
	)

	srv := apipublic.NewServer(context.Background(), testServerCfg(), apipublic.Deps{
		CORSConfigProvider:    testCORS(),
		URLs:                  testURLBuilder(),
		SessionSecretProvider: testSessionSecret(),
		SessionConfigProvider: testSessionConfig(),
		JWKS:                  jwksSvc,
		Introspect:            introspectSvc,
		IssuerProvider:        staticIssuerForTest("https://auth.example.com"),
		SessionCookie:         apipublic.SessionCookie{Name: "authserver_session"},
	}, obs)

	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)

	return &introspectTestEnv{
		ts:       ts,
		kp:       kp,
		clientID: c.ID,
	}
}

func signIntrospectToken(t *testing.T, kp *crypto.KeyPair, claims crypto.AccessTokenClaims) string {
	t.Helper()
	token, err := crypto.SignAccessToken(kp, claims)
	if err != nil {
		t.Fatalf("sign access token: %v", err)
	}
	return token
}

func validIntrospectClaims() crypto.AccessTokenClaims {
	now := time.Now().UTC()
	return crypto.AccessTokenClaims{
		Issuer:   "https://auth.example.com",
		Subject:  "user-1",
		Audience: []string{"https://resource.example.com"},
		ClientID: "introspect-http-client",
		Scope:    "tools/read tools/write",
		JTI:      crypto.GenerateRandomString(16),
		IssuedAt: now.Unix(),
		Expiry:   now.Add(15 * time.Minute).Unix(),
	}
}

// --- POST /oauth/introspect ---

func TestIntrospectHTTP_ValidToken_ReturnsActive(t *testing.T) {
	env := newIntrospectTestServer(t)

	claims := validIntrospectClaims()
	token := signIntrospectToken(t, env.kp, claims)

	body := strings.NewReader("token=" + token)
	req, _ := http.NewRequest("POST", env.ts.URL+"/oauth/introspect", body)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(env.clientID+":test-secret")))

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("introspect: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status: got %d, want 200", resp.StatusCode)
	}

	var result map[string]any
	json.NewDecoder(resp.Body).Decode(&result)

	if result["active"] != true {
		t.Fatal("expected active=true")
	}
	if result["sub"] != "user-1" {
		t.Errorf("sub = %v, want user-1", result["sub"])
	}
	if result["client_id"] != "introspect-http-client" {
		t.Errorf("client_id = %v, want introspect-http-client", result["client_id"])
	}
	if result["scope"] != "tools/read tools/write" {
		t.Errorf("scope = %v, want 'tools/read tools/write'", result["scope"])
	}
	if result["token_type"] != "Bearer" {
		t.Errorf("token_type = %v, want Bearer", result["token_type"])
	}
	if result["iss"] != "https://auth.example.com" {
		t.Errorf("iss = %v, want https://auth.example.com", result["iss"])
	}
}

func TestIntrospectHTTP_MissingToken_BadRequest(t *testing.T) {
	env := newIntrospectTestServer(t)

	body := strings.NewReader("")
	req, _ := http.NewRequest("POST", env.ts.URL+"/oauth/introspect", body)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(env.clientID+":test-secret")))

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("introspect: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status: got %d, want 400", resp.StatusCode)
	}
}

func TestIntrospectHTTP_InvalidClientAuth_Unauthorized(t *testing.T) {
	env := newIntrospectTestServer(t)

	claims := validIntrospectClaims()
	token := signIntrospectToken(t, env.kp, claims)

	body := strings.NewReader("token=" + token)
	req, _ := http.NewRequest("POST", env.ts.URL+"/oauth/introspect", body)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(env.clientID+":wrong-secret")))

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("introspect: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status: got %d, want 401", resp.StatusCode)
	}
}

func TestIntrospectHTTP_ExpiredToken_Inactive(t *testing.T) {
	env := newIntrospectTestServer(t)

	claims := validIntrospectClaims()
	claims.Expiry = time.Now().Add(-1 * time.Hour).Unix()
	token := signIntrospectToken(t, env.kp, claims)

	body := strings.NewReader("token=" + token)
	req, _ := http.NewRequest("POST", env.ts.URL+"/oauth/introspect", body)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(env.clientID+":test-secret")))

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("introspect: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status: got %d, want 200", resp.StatusCode)
	}

	var result map[string]any
	json.NewDecoder(resp.Body).Decode(&result)

	if result["active"] != false {
		t.Fatal("expected active=false for expired token")
	}
}

func TestIntrospectHTTP_GarbageToken_Inactive(t *testing.T) {
	env := newIntrospectTestServer(t)

	body := strings.NewReader("token=this-is-not-a-jwt")
	req, _ := http.NewRequest("POST", env.ts.URL+"/oauth/introspect", body)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(env.clientID+":test-secret")))

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("introspect: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status: got %d, want 200", resp.StatusCode)
	}

	var result map[string]any
	json.NewDecoder(resp.Body).Decode(&result)

	if result["active"] != false {
		t.Fatal("expected active=false for garbage token")
	}
}
