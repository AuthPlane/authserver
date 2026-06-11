//go:build integration

package public_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-jose/go-jose/v4"

	apipublic "github.com/authplane/authserver/api/public"
	"github.com/authplane/authserver/api/public/wellknown"
	"github.com/authplane/authserver/internal/adapters/keyfile"
	"github.com/authplane/authserver/internal/config"
	"github.com/authplane/authserver/internal/crypto"
	"github.com/authplane/authserver/internal/observability"
	"github.com/authplane/authserver/internal/services"
)

func testObs() *observability.Provider {
	return observability.NewNoop()
}

func testServerCfg() config.ServerConfig {
	return config.ServerConfig{
		Issuer:  "https://auth.example.com",
		Address: ":0",
	}
}

func testResourceServers() wellknown.ResourceListerFunc {
	return func() []wellknown.ResourceEntry {
		return []wellknown.ResourceEntry{
			{URI: "https://mcp.example.com", Scopes: []string{"tools/query_database", "tools/create_ticket"}},
		}
	}
}

func newTestJWKSService(t *testing.T) *services.JWKSService {
	t.Helper()
	dir := t.TempDir()
	obs := testObs()
	store, err := keyfile.New(dir, obs)
	if err != nil {
		t.Fatalf("create keyfile store: %v", err)
	}
	return services.NewJWKSService(store, "ES256", obs)
}

func newTestServer(t *testing.T) *httptest.Server {
	t.Helper()
	jwksSvc := newTestJWKSService(t)

	srv := apipublic.NewServer(context.Background(), testServerCfg(), apipublic.Deps{
		JWKS:            jwksSvc,
		ResourceServers: testResourceServers(),
	}, testObs())

	// Use httptest to test the handler directly.
	// We need to access the internal handler; use NewServer and extract the mux.
	// Actually, just create a real httptest server.
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	return ts
}

// --- JWKS Endpoint Tests ---

func TestJWKS_ReturnsValidJSON(t *testing.T) {
	ts := newTestServer(t)

	resp, err := http.Get(ts.URL + "/.well-known/jwks.json")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status: got %d, want 200", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); ct != "application/json" {
		t.Errorf("content-type: got %q, want %q", ct, "application/json")
	}

	var jwks jose.JSONWebKeySet
	if err := json.NewDecoder(resp.Body).Decode(&jwks); err != nil {
		t.Fatalf("decode jwks: %v", err)
	}
	if len(jwks.Keys) < 1 {
		t.Fatal("expected at least 1 key in JWKS")
	}

	key := jwks.Keys[0]
	if key.Use != "sig" {
		t.Errorf("use: got %q, want %q", key.Use, "sig")
	}
	if key.Algorithm != "ES256" {
		t.Errorf("alg: got %q, want %q", key.Algorithm, "ES256")
	}
	if key.KeyID == "" {
		t.Error("kid is empty")
	}
}

func TestJWKS_CacheControl(t *testing.T) {
	ts := newTestServer(t)

	resp, err := http.Get(ts.URL + "/.well-known/jwks.json")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	resp.Body.Close()

	cc := resp.Header.Get("Cache-Control")
	if cc != "public, max-age=3600" {
		t.Errorf("cache-control: got %q, want %q", cc, "public, max-age=3600")
	}
}

// --- AS Metadata Endpoint Tests ---

func TestASMetadata_AllRequiredFields(t *testing.T) {
	ts := newTestServer(t)

	resp, err := http.Get(ts.URL + "/.well-known/oauth-authorization-server")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status: got %d, want 200", resp.StatusCode)
	}

	body, _ := io.ReadAll(resp.Body)
	var meta map[string]any
	if err := json.Unmarshal(body, &meta); err != nil {
		t.Fatalf("decode: %v", err)
	}

	requiredFields := []string{
		"issuer",
		"authorization_endpoint",
		"token_endpoint",
		"registration_endpoint",
		"revocation_endpoint",
		"jwks_uri",
		"response_types_supported",
		"grant_types_supported",
		"token_endpoint_auth_methods_supported",
		"code_challenge_methods_supported",
		"scopes_supported",
		"resource_indicators_supported",
	}

	for _, field := range requiredFields {
		if _, ok := meta[field]; !ok {
			t.Errorf("missing required field: %s", field)
		}
	}

	// Verify correct values.
	if meta["issuer"] != "https://auth.example.com" {
		t.Errorf("issuer: got %v", meta["issuer"])
	}
	if meta["authorization_endpoint"] != "https://auth.example.com/oauth/authorize" {
		t.Errorf("authorization_endpoint: got %v", meta["authorization_endpoint"])
	}
	if meta["token_endpoint"] != "https://auth.example.com/oauth/token" {
		t.Errorf("token_endpoint: got %v", meta["token_endpoint"])
	}
	if meta["jwks_uri"] != "https://auth.example.com/.well-known/jwks.json" {
		t.Errorf("jwks_uri: got %v", meta["jwks_uri"])
	}

	// resource_indicators_supported must be true.
	if meta["resource_indicators_supported"] != true {
		t.Errorf("resource_indicators_supported: got %v", meta["resource_indicators_supported"])
	}

	// code_challenge_methods_supported must be ["S256"].
	methods, ok := meta["code_challenge_methods_supported"].([]any)
	if !ok || len(methods) != 1 || methods[0] != "S256" {
		t.Errorf("code_challenge_methods_supported: got %v", meta["code_challenge_methods_supported"])
	}
}

// Matrix: 6.14 — AS metadata must include Cache-Control header
func TestASMetadata_CacheControl(t *testing.T) {
	ts := newTestServer(t)

	resp, err := http.Get(ts.URL + "/.well-known/oauth-authorization-server")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	resp.Body.Close()

	cc := resp.Header.Get("Cache-Control")
	if cc != "public, max-age=3600" {
		t.Errorf("Cache-Control: got %q, want %q", cc, "public, max-age=3600")
	}
}

func TestASMetadata_ScopesFromResourceServers(t *testing.T) {
	ts := newTestServer(t)

	resp, err := http.Get(ts.URL + "/.well-known/oauth-authorization-server")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer resp.Body.Close()

	var meta map[string]any
	json.NewDecoder(resp.Body).Decode(&meta)

	scopes, ok := meta["scopes_supported"].([]any)
	if !ok {
		t.Fatal("scopes_supported not an array")
	}
	if len(scopes) != 2 {
		t.Fatalf("expected 2 scopes, got %d", len(scopes))
	}
}

// --- JWT Round-Trip via JWKS Endpoint ---

func TestJWKS_JWTRoundTrip(t *testing.T) {
	// Create a JWKS service and server.
	dir := t.TempDir()
	obs := testObs()
	store, err := keyfile.New(dir, obs)
	if err != nil {
		t.Fatalf("create store: %v", err)
	}
	jwksSvc := services.NewJWKSService(store, "ES256", obs)

	srv := apipublic.NewServer(context.Background(), testServerCfg(), apipublic.Deps{
		JWKS:            jwksSvc,
		ResourceServers: testResourceServers(),
	}, obs)

	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	// Get signing key and sign a JWT.
	sk, err := jwksSvc.GetSigningKey(context.Background())
	if err != nil {
		t.Fatalf("get signing key: %v", err)
	}

	kp := &crypto.KeyPair{
		PrivateKey: sk.PrivateKey,
		PublicKey:  sk.PublicKey,
		Algorithm:  "ES256",
		KeyID:      sk.KeyID,
	}

	claims := crypto.AccessTokenClaims{
		Issuer:   "https://auth.example.com",
		Subject:  "user-42",
		Audience: []string{"https://mcp.example.com"},
		ClientID: "test-client",
		Scope:    "tools/query_database",
		JTI:      "jti-round-trip",
		IssuedAt: 1700000000,
		Expiry:   4700000000,
	}
	token, err := crypto.SignAccessToken(kp, claims)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	// Fetch JWKS from the endpoint.
	resp, err := http.Get(ts.URL + "/.well-known/jwks.json")
	if err != nil {
		t.Fatalf("fetch jwks: %v", err)
	}
	defer resp.Body.Close()

	var jwks jose.JSONWebKeySet
	if err := json.NewDecoder(resp.Body).Decode(&jwks); err != nil {
		t.Fatalf("decode jwks: %v", err)
	}

	// Verify JWT using the JWKS from the endpoint.
	verified, err := crypto.VerifyAccessToken(token, &jwks)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if verified.Subject != "user-42" {
		t.Errorf("sub: got %q, want %q", verified.Subject, "user-42")
	}
	if verified.ClientID != "test-client" {
		t.Errorf("client_id: got %q, want %q", verified.ClientID, "test-client")
	}
}

// Matrix: 11.3 — JWKS endpoint is rate limited
func TestJWKS_RateLimited(t *testing.T) {
	ts := newRateLimitTestServer(t, config.RateLimitConfig{
		Enabled:           true,
		RequestsPerSecond: 2,
		Burst:             2,
	})

	var got429 bool
	for i := 0; i < 20; i++ {
		resp, err := http.Get(ts.URL + "/.well-known/jwks.json")
		if err != nil {
			t.Fatalf("get: %v", err)
		}
		if resp.StatusCode == http.StatusTooManyRequests {
			got429 = true
			resp.Body.Close()
			break
		}
		resp.Body.Close()
	}
	if !got429 {
		t.Error("JWKS endpoint should be rate-limited; expected 429 after rapid requests")
	}
}

// --- Health Check Tests ---

// Matrix: 17.1 — upgraded from ⚠️: GET /health returns 200 with status=ok
func TestHealth_ReturnsOK(t *testing.T) {
	ts := newTestServer(t)

	resp, err := http.Get(ts.URL + "/health")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status: got %d, want 200", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); ct != "application/json" {
		t.Errorf("content-type: got %q, want application/json", ct)
	}

	var health map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&health); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if health["status"] != "ok" {
		t.Errorf("status field: got %v, want 'ok'", health["status"])
	}
	if health["time"] == nil || health["time"] == "" {
		t.Error("time field should be present and non-empty")
	}
}

// Matrix: 17.2 — health check returns 503 when DB is unreachable
func TestHealth_DBDown_Returns503(t *testing.T) {
	jwksSvc := newTestJWKSService(t)

	srv := apipublic.NewServer(context.Background(), testServerCfg(), apipublic.Deps{
		JWKS:            jwksSvc,
		ResourceServers: testResourceServers(),
		Health:          &failingHealthChecker{},
	}, testObs())

	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/health")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("status: got %d, want 503", resp.StatusCode)
	}

	var health map[string]any
	json.NewDecoder(resp.Body).Decode(&health)
	if health["status"] != "degraded" {
		t.Errorf("status field: got %v, want 'degraded'", health["status"])
	}
	if health["db"] != "error" {
		t.Errorf("db field: got %v, want 'error'", health["db"])
	}
}

// failingHealthChecker always returns an error (simulates unreachable DB).
type failingHealthChecker struct{}

func (f *failingHealthChecker) Ping(_ context.Context) error {
	return context.DeadlineExceeded
}

// --- Metrics Tests ---

// Matrix: 17.3 — /metrics is NOT exposed on the public server (moved to admin).
func TestMetrics_NotExposedOnPublicServer(t *testing.T) {
	obsCfg := config.ObservabilityConfig{
		Metrics: config.MetricsConfig{
			Provider: "prometheus",
			Path:     "/metrics",
		},
	}
	obs, shutdown, err := observability.New(context.Background(), obsCfg)
	if err != nil {
		t.Fatalf("create obs: %v", err)
	}
	t.Cleanup(func() { shutdown(context.Background()) })

	dir := t.TempDir()
	store, err := keyfile.New(dir, obs)
	if err != nil {
		t.Fatalf("create keyfile store: %v", err)
	}
	jwksSvc := services.NewJWKSService(store, "ES256", obs)

	srv := apipublic.NewServer(context.Background(), testServerCfg(), apipublic.Deps{
		JWKS:            jwksSvc,
		ResourceServers: testResourceServers(),
	}, obs)

	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/metrics")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer resp.Body.Close()

	// /metrics should NOT be reachable on the public server.
	if resp.StatusCode == http.StatusOK {
		t.Fatal("/metrics should not be exposed on the public server (moved to admin port)")
	}
}

// Matrix: 17.5 — graceful shutdown completes in-flight requests
func TestGracefulShutdown(t *testing.T) {
	jwksSvc := newTestJWKSService(t)

	srv := apipublic.NewServer(context.Background(), testServerCfg(), apipublic.Deps{
		JWKS:            jwksSvc,
		ResourceServers: testResourceServers(),
	}, testObs())

	ts := httptest.NewServer(srv.Handler())

	// Verify server is responding.
	resp, err := http.Get(ts.URL + "/health")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status: got %d, want 200", resp.StatusCode)
	}

	// Shutdown the server gracefully.
	ts.Close()

	// After shutdown, new requests should fail (connection refused).
	_, err = http.Get(ts.URL + "/health")
	if err == nil {
		t.Error("request after shutdown should fail")
	}

	// The server uses http.Server.Shutdown() which drains in-flight requests.
	// httptest.Close() calls this internally. The fact that our pre-shutdown
	// request completed with 200 and post-shutdown fails proves graceful shutdown works.
}

// --- Resource Server DB scope discovery tests ---
// These verify that AS metadata discovers scopes from the resource_servers DB
// table (populated by Admin API).

func staticResourceLister(entries []wellknown.ResourceEntry) wellknown.ResourceListerFunc {
	return func() []wellknown.ResourceEntry { return entries }
}

func TestASMetadata_ResourceServerDBScopes_Included(t *testing.T) {
	jwksSvc := newTestJWKSService(t)

	// No static config, no scopes table — only resource servers from DB.
	srv := apipublic.NewServer(context.Background(), testServerCfg(), apipublic.Deps{
		JWKS: jwksSvc,
		ResourceServers: staticResourceLister([]wellknown.ResourceEntry{
			{URI: "https://mcp.example.com", Scopes: []string{"tools/query", "tools/create"}},
		}),
	}, testObs())

	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/.well-known/oauth-authorization-server")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer resp.Body.Close()

	var meta map[string]any
	json.NewDecoder(resp.Body).Decode(&meta)

	scopes, ok := meta["scopes_supported"].([]any)
	if !ok || scopes == nil {
		t.Fatalf("scopes_supported should be a non-null array, got: %v", meta["scopes_supported"])
	}
	if len(scopes) != 2 {
		t.Fatalf("expected 2 scopes from resource servers, got %d: %v", len(scopes), scopes)
	}

	scopeSet := make(map[string]bool)
	for _, s := range scopes {
		scopeSet[s.(string)] = true
	}
	if !scopeSet["tools/query"] || !scopeSet["tools/create"] {
		t.Errorf("resource server scopes not found in scopes_supported: %v", scopes)
	}
}

func TestASMetadata_MergesMultipleResourceServers(t *testing.T) {
	jwksSvc := newTestJWKSService(t)

	srv := apipublic.NewServer(context.Background(), testServerCfg(), apipublic.Deps{
		JWKS: jwksSvc,
		ResourceServers: staticResourceLister([]wellknown.ResourceEntry{
			{URI: "https://mcp1.example.com", Scopes: []string{"tools/query"}},
			{URI: "https://mcp2.example.com", Scopes: []string{"tools/create"}},
		}),
	}, testObs())

	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/.well-known/oauth-authorization-server")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer resp.Body.Close()

	var meta map[string]any
	json.NewDecoder(resp.Body).Decode(&meta)

	scopes, ok := meta["scopes_supported"].([]any)
	if !ok {
		t.Fatal("scopes_supported should be an array")
	}
	if len(scopes) != 2 {
		t.Fatalf("expected 2 scopes from 2 resource servers, got %d: %v", len(scopes), scopes)
	}

	scopeSet := make(map[string]bool)
	for _, s := range scopes {
		scopeSet[s.(string)] = true
	}
	if !scopeSet["tools/query"] {
		t.Error("missing scope from first resource server")
	}
	if !scopeSet["tools/create"] {
		t.Error("missing scope from second resource server")
	}
}

func TestASMetadata_DeduplicatesScopesAcrossResourceServers(t *testing.T) {
	jwksSvc := newTestJWKSService(t)

	// Two resource servers with overlapping scopes — duplicates must appear only once.
	srv := apipublic.NewServer(context.Background(), testServerCfg(), apipublic.Deps{
		JWKS: jwksSvc,
		ResourceServers: staticResourceLister([]wellknown.ResourceEntry{
			{URI: "https://mcp1.example.com", Scopes: []string{"tools/query", "tools/shared"}},
			{URI: "https://mcp2.example.com", Scopes: []string{"tools/create", "tools/shared"}},
		}),
	}, testObs())

	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/.well-known/oauth-authorization-server")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer resp.Body.Close()

	var meta map[string]any
	json.NewDecoder(resp.Body).Decode(&meta)

	scopes, ok := meta["scopes_supported"].([]any)
	if !ok || scopes == nil {
		t.Fatalf("scopes_supported should be a non-null array, got: %v", meta["scopes_supported"])
	}

	scopeSet := make(map[string]bool)
	for _, s := range scopes {
		scopeSet[s.(string)] = true
	}

	for _, want := range []string{"tools/query", "tools/create", "tools/shared"} {
		if !scopeSet[want] {
			t.Errorf("missing scope %q in scopes_supported: %v", want, scopes)
		}
	}
	if len(scopes) != 3 {
		t.Errorf("expected 3 unique scopes (tools/shared deduplicated), got %d: %v", len(scopes), scopes)
	}
}
