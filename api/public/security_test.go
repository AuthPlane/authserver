//go:build integration

package public_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	apipublic "github.com/authplane/authserver/api/public"
	"github.com/authplane/authserver/internal/config"
)

// --- Section 18: Security Hardening ---

// Matrix: 18.1 — Security headers present on all responses
func TestSecurityHeaders_PresentOnAllResponses(t *testing.T) {
	jwksSvc := newTestJWKSService(t)
	obs := testObs()

	srv := apipublic.NewServer(context.Background(), testServerCfg(), apipublic.Deps{
		JWKS:            jwksSvc,
		ResourceServers: testResourceServers(),
	}, obs)

	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)

	paths := []string{
		"/.well-known/oauth-authorization-server",
		"/.well-known/jwks.json",
		"/health",
	}

	for _, path := range paths {
		t.Run(path, func(t *testing.T) {
			resp, err := http.Get(ts.URL + path)
			if err != nil {
				t.Fatalf("get %s: %v", path, err)
			}
			resp.Body.Close()

			if v := resp.Header.Get("X-Content-Type-Options"); v != "nosniff" {
				t.Errorf("X-Content-Type-Options: got %q, want %q", v, "nosniff")
			}
			if v := resp.Header.Get("X-Frame-Options"); v != "DENY" {
				t.Errorf("X-Frame-Options: got %q, want %q", v, "DENY")
			}
			if v := resp.Header.Get("Referrer-Policy"); v != "no-referrer" {
				t.Errorf("Referrer-Policy: got %q, want %q", v, "no-referrer")
			}
			csp := resp.Header.Get("Content-Security-Policy")
			if !strings.Contains(csp, "default-src 'none'") {
				t.Errorf("CSP: got %q, want it to contain default-src 'none'", csp)
			}
		})
	}
}

// Matrix: 18.2 — HSTS header present when secure mode enabled
func TestSecurityHeaders_HSTS_WhenSecure(t *testing.T) {
	jwksSvc := newTestJWKSService(t)
	obs := testObs()

	srv := apipublic.NewServer(context.Background(), testServerCfg(), apipublic.Deps{
		JWKS:            jwksSvc,
		ResourceServers: testResourceServers(),
		SessionCfg: config.SessionConfig{
			Secure: true,
		},
	}, obs)

	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)

	resp, err := http.Get(ts.URL + "/health")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	resp.Body.Close()

	hsts := resp.Header.Get("Strict-Transport-Security")
	if !strings.Contains(hsts, "max-age=") {
		t.Errorf("HSTS header missing or wrong: got %q", hsts)
	}
}

// Matrix: 18.3 — CORS allows configured origins on token endpoint
func TestCORS_AllowedOrigin_TokenEndpoint(t *testing.T) {
	jwksSvc := newTestJWKSService(t)
	obs := testObs()

	cfg := testServerCfg()
	cfg.AllowedOrigins = []string{"https://app.example.com"}
	srv := apipublic.NewServer(context.Background(), cfg, apipublic.Deps{
		JWKS:            jwksSvc,
		ResourceServers: testResourceServers(),
	}, obs)

	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)

	req, _ := http.NewRequest("OPTIONS", ts.URL+"/oauth/token", nil)
	req.Header.Set("Origin", "https://app.example.com")
	req.Header.Set("Access-Control-Request-Method", "POST")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("options: %v", err)
	}
	resp.Body.Close()

	if resp.StatusCode != http.StatusNoContent {
		t.Errorf("preflight status: got %d, want 204", resp.StatusCode)
	}
	if v := resp.Header.Get("Access-Control-Allow-Origin"); v != "https://app.example.com" {
		t.Errorf("ACAO: got %q, want %q", v, "https://app.example.com")
	}
	if v := resp.Header.Get("Access-Control-Allow-Methods"); !strings.Contains(v, "POST") {
		t.Errorf("ACAM: got %q, want POST included", v)
	}
}

// Matrix: 18.4 — CORS rejects unknown origins
func TestCORS_UnknownOrigin_NoHeaders(t *testing.T) {
	jwksSvc := newTestJWKSService(t)
	obs := testObs()

	cfg := testServerCfg()
	cfg.AllowedOrigins = []string{"https://app.example.com"}
	srv := apipublic.NewServer(context.Background(), cfg, apipublic.Deps{
		JWKS:            jwksSvc,
		ResourceServers: testResourceServers(),
	}, obs)

	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)

	req, _ := http.NewRequest("OPTIONS", ts.URL+"/oauth/token", nil)
	req.Header.Set("Origin", "https://evil.example.com")
	req.Header.Set("Access-Control-Request-Method", "POST")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("options: %v", err)
	}
	resp.Body.Close()

	if v := resp.Header.Get("Access-Control-Allow-Origin"); v != "" {
		t.Errorf("ACAO should be empty for unknown origin, got %q", v)
	}
}

// Matrix: 18.5 — CORS not applied to login/consent (same-origin only)
func TestCORS_NotOnLoginConsent(t *testing.T) {
	jwksSvc := newTestJWKSService(t)
	obs := testObs()

	cfg := testServerCfg()
	cfg.AllowedOrigins = []string{"*"}
	srv := apipublic.NewServer(context.Background(), cfg, apipublic.Deps{
		JWKS:            jwksSvc,
		ResourceServers: testResourceServers(),
	}, obs)

	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)

	for _, path := range []string{"/login", "/consent"} {
		t.Run(path, func(t *testing.T) {
			req, _ := http.NewRequest("GET", ts.URL+path, nil)
			req.Header.Set("Origin", "https://evil.example.com")

			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatalf("get %s: %v", path, err)
			}
			resp.Body.Close()

			if v := resp.Header.Get("Access-Control-Allow-Origin"); v != "" {
				t.Errorf("%s should not have CORS headers, got ACAO=%q", path, v)
			}
		})
	}
}

// Matrix: 18.9 — Request body size limit on DCR endpoint
func TestRegister_OversizedBody_Rejected(t *testing.T) {
	ts := newDCRTestServer(t, "open", nil)

	bigBody := strings.Repeat("x", 2*1024*1024) // 2MB > 1MB limit
	resp, err := http.Post(ts.URL+"/oauth/register", "application/json", strings.NewReader(bigBody))
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("oversized body should return 400, got %d", resp.StatusCode)
	}
}

// Matrix: 18.10 — Cache-Control: no-store on HTML pages
func TestSecurityHeaders_CacheControl_HTMLPages(t *testing.T) {
	env := newOAuthTestServer(t)

	resp, err := http.Get(env.ts.URL + "/login?session_id=fake")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	resp.Body.Close()

	if v := resp.Header.Get("Cache-Control"); v != "no-store" {
		t.Errorf("Cache-Control on login page: got %q, want %q", v, "no-store")
	}
}

// Matrix: 18.3 — CORS Vary header for non-wildcard origin
func TestCORS_VaryHeader_NonWildcard(t *testing.T) {
	jwksSvc := newTestJWKSService(t)
	obs := testObs()

	cfg := testServerCfg()
	cfg.AllowedOrigins = []string{"https://app.example.com"}
	srv := apipublic.NewServer(context.Background(), cfg, apipublic.Deps{
		JWKS:            jwksSvc,
		ResourceServers: testResourceServers(),
		SessionCfg: config.SessionConfig{
			CookieName: "authserver_session",
			MaxAge:     24 * time.Hour,
			Secret:     "test-secret-32-bytes-long-enough",
			SameSite:   "lax",
		},
	}, obs)

	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)

	// Actual request (not preflight) with Origin.
	req, _ := http.NewRequest("GET", ts.URL+"/.well-known/oauth-authorization-server", nil)
	req.Header.Set("Origin", "https://app.example.com")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	resp.Body.Close()

	// Non-wildcard origins should set Vary: Origin for caching correctness.
	if v := resp.Header.Get("Vary"); !strings.Contains(v, "Origin") {
		t.Errorf("Vary header should contain Origin for non-wildcard CORS, got %q", v)
	}
}

// TestCORS_PreflightAllPublicEndpoints is the  Track 3 (Browser
// & CORS contract) cadence anchor per the operator-test plan
// §4 Track 3: every public endpoint that browser-originated MCP
// clients hit MUST handle the OPTIONS preflight correctly. The
// existing TestCORS_AllowedOrigin_TokenEndpoint covers /oauth/token;
// this expands the gate to the rest of the operator-shaped surface
// (introspection, revocation, AS metadata, JWKS).
//
// Browser-originated MCP clients (MCP Inspector, Claude Desktop,
// Claude Code in browser) call these endpoints across origins —
// failing preflight is invisible server-side and breaks every
// browser flow silently. surfaced this exact pattern.
func TestCORS_PreflightAllPublicEndpoints(t *testing.T) {
	jwksSvc := newTestJWKSService(t)
	obs := testObs()

	const browserOrigin = "https://app.example.com"
	cfg := testServerCfg()
	cfg.AllowedOrigins = []string{browserOrigin}
	srv := apipublic.NewServer(context.Background(), cfg, apipublic.Deps{
		JWKS:            jwksSvc,
		ResourceServers: testResourceServers(),
	}, obs)

	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)

	cases := []struct {
		path   string
		method string // value of Access-Control-Request-Method
	}{
		// Discovery endpoints — fetched at startup by every browser-
		// resident MCP client (RFC 8414 / RFC 9728).
		{"/.well-known/oauth-authorization-server", "GET"},
		{"/.well-known/oauth-protected-resource", "GET"},
		{"/.well-known/jwks.json", "GET"},

		// Token endpoints — hit during the auth-code → JWT exchange
		// + on every refresh / introspection / revoke.
		{"/oauth/token", "POST"},
		{"/oauth/introspect", "POST"},
		{"/oauth/revoke", "POST"},
	}

	for _, tc := range cases {
		t.Run(tc.path, func(t *testing.T) {
			req, _ := http.NewRequest("OPTIONS", ts.URL+tc.path, nil)
			req.Header.Set("Origin", browserOrigin)
			req.Header.Set("Access-Control-Request-Method", tc.method)

			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatalf("OPTIONS %s: %v", tc.path, err)
			}
			resp.Body.Close()

			// Preflight must return 204 No Content (the canonical CORS
			// preflight response — see Fetch standard §3.7).
			if resp.StatusCode != http.StatusNoContent {
				t.Errorf("OPTIONS %s: status %d, want 204", tc.path, resp.StatusCode)
			}
			// Response must echo the configured origin (NOT "*" since
			// the deployment configures a non-wildcard origin list).
			if got := resp.Header.Get("Access-Control-Allow-Origin"); got != browserOrigin {
				t.Errorf("OPTIONS %s: Access-Control-Allow-Origin = %q, want %q",
					tc.path, got, browserOrigin)
			}
			// Methods header must include the requested method.
			if v := resp.Header.Get("Access-Control-Allow-Methods"); !strings.Contains(v, tc.method) {
				t.Errorf("OPTIONS %s: Access-Control-Allow-Methods = %q, want %s included",
					tc.path, v, tc.method)
			}
		})
	}
}
