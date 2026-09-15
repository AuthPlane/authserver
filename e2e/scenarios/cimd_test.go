//go:build e2e

package scenarios

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync/atomic"
	"testing"

	"github.com/authplane/authserver/e2e"
	"github.com/authplane/authserver/internal/ports/output"
)

// TestE2E_CIMD_FullAuthFlow exercises the complete CIMD-based authorization flow:
// URL-based client_id → CIMD fetch → login → consent → code → token.
func TestE2E_CIMD_FullAuthFlow(t *testing.T) {
	scopes := []string{"tools/echo"}
	h, servers := e2e.SetupE2E(t, e2e.HarnessConfig{}, scopes)
	rs := servers[0]

	h.CreateUser("alice@example.com", "password123")
	h.RegisterScope(rs.URI, "tools/echo", "Echo tool")

	// Start a CIMD server that serves client metadata.
	redirectURI := "http://localhost:9999/callback"
	cimdServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		doc := output.CIMDDocument{
			ClientID:     "http://" + r.Host + r.URL.Path,
			ClientName:   "CIMD E2E Client",
			RedirectURIs: []string{redirectURI},
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(doc)
	}))
	defer cimdServer.Close()

	clientID := cimdServer.URL + "/client.json" // URL-based client_id

	// Create MCP client with URL-based client_id.
	client := e2e.NewMCPClient(t, h, rs, clientID, redirectURI)

	// Full flow: login → authorize → consent → token.
	tokens := client.FullFlow("alice@example.com", "password123", "tools/echo", false)
	if tokens.AccessToken == "" {
		t.Fatal("expected access token from CIMD auth flow")
	}
	if tokens.TokenType != "Bearer" {
		t.Errorf("expected Bearer token type, got %q", tokens.TokenType)
	}

	// Verify the access token works on the resource server.
	status, _ := client.CallTool("/tools/echo", tokens.AccessToken, `"cimd hello"`)
	if status != http.StatusOK {
		t.Fatalf("echo tool: expected 200, got %d", status)
	}
}

// TestE2E_CIMD_FetchFailure verifies that authorize with a URL client_id where
// the CIMD server is unreachable returns an HTTP error (no redirect).
func TestE2E_CIMD_FetchFailure(t *testing.T) {
	scopes := []string{"tools/echo"}
	h, _ := e2e.SetupE2E(t, e2e.HarnessConfig{}, scopes)

	// CIMD server that always fails.
	cimdServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer cimdServer.Close()

	httpClient := h.NewClient()
	authURL := h.Issuer + "/oauth/authorize?" + url.Values{
		"client_id":             {cimdServer.URL + "/client.json"},
		"redirect_uri":          {"http://localhost:9999/callback"},
		"response_type":         {"code"},
		"scope":                 {"tools/echo"},
		"state":                 {"test-state"},
		"code_challenge":        {"E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"},
		"code_challenge_method": {"S256"},
	}.Encode()

	resp, err := httpClient.Get(authURL)
	if err != nil {
		t.Fatalf("GET authorize: %v", err)
	}
	resp.Body.Close()

	// When client_id is invalid, server returns 400 (can't redirect to unknown client).
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("expected 400 for failed CIMD fetch, got %d", resp.StatusCode)
	}
}

// TestE2E_CIMD_WrongRedirectURI verifies that a CIMD-registered client rejects
// authorize requests with a redirect_uri not in the CIMD document.
func TestE2E_CIMD_WrongRedirectURI(t *testing.T) {
	scopes := []string{"tools/echo"}
	h, _ := e2e.SetupE2E(t, e2e.HarnessConfig{}, scopes)

	cimdServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		doc := output.CIMDDocument{
			ClientID:     "http://" + r.Host + r.URL.Path,
			ClientName:   "CIMD Redirect Test",
			RedirectURIs: []string{"https://legit.example.com/callback"},
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(doc)
	}))
	defer cimdServer.Close()

	httpClient := h.NewClient()
	authURL := h.Issuer + "/oauth/authorize?" + url.Values{
		"client_id":             {cimdServer.URL + "/client.json"},
		"redirect_uri":          {"https://evil.example.com/steal"}, // Not in CIMD document
		"response_type":         {"code"},
		"scope":                 {"tools/echo"},
		"state":                 {"test-state"},
		"code_challenge":        {"E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"},
		"code_challenge_method": {"S256"},
	}.Encode()

	resp, err := httpClient.Get(authURL)
	if err != nil {
		t.Fatalf("GET authorize: %v", err)
	}
	resp.Body.Close()

	// When redirect_uri doesn't match, server returns 400 (can't redirect to untrusted URI).
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("expected 400 for mismatched redirect_uri, got %d", resp.StatusCode)
	}
}

// TestE2E_CIMD_SuspendedClient verifies that after an admin suspends a CIMD-registered
// client, subsequent authorize requests are rejected.
func TestE2E_CIMD_SuspendedClient(t *testing.T) {
	scopes := []string{"tools/echo"}
	h, servers := e2e.SetupE2E(t, e2e.HarnessConfig{}, scopes)
	rs := servers[0]

	h.CreateUser("alice@example.com", "password123")
	h.RegisterScope(rs.URI, "tools/echo", "Echo tool")

	redirectURI := "http://localhost:9999/callback"
	cimdServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		doc := output.CIMDDocument{
			ClientID:     "http://" + r.Host + r.URL.Path,
			ClientName:   "CIMD Suspend Test",
			RedirectURIs: []string{redirectURI},
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(doc)
	}))
	defer cimdServer.Close()

	clientID := cimdServer.URL + "/client.json"
	client := e2e.NewMCPClient(t, h, rs, clientID, redirectURI)

	// First flow — succeeds, client gets auto-registered.
	tokens := client.FullFlow("alice@example.com", "password123", "tools/echo", false)
	if tokens.AccessToken == "" {
		t.Fatal("expected access token from first CIMD flow")
	}

	// Suspend the client via admin API.
	err := h.AdminSvc.SuspendClient(t.Context(), clientID)
	if err != nil {
		t.Fatalf("suspend client: %v", err)
	}

	// Second attempt — should fail because client is suspended.
	// Suspended client returns 403 (not a redirect, since the client is known but blocked).
	httpClient2 := h.NewClient()
	authURL := h.Issuer + "/oauth/authorize?" + url.Values{
		"client_id":             {clientID},
		"redirect_uri":          {redirectURI},
		"response_type":         {"code"},
		"scope":                 {"tools/echo"},
		"state":                 {"test-state-2"},
		"code_challenge":        {"E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"},
		"code_challenge_method": {"S256"},
	}.Encode()

	resp, err := httpClient2.Get(authURL)
	if err != nil {
		t.Fatalf("GET authorize: %v", err)
	}
	resp.Body.Close()

	if resp.StatusCode == http.StatusSeeOther {
		loc := resp.Header.Get("Location")
		locURL, _ := url.Parse(loc)
		if code := locURL.Query().Get("code"); code != "" {
			t.Fatal("expected no auth code for suspended CIMD client")
		}
		// Redirect to error page is acceptable.
	} else if resp.StatusCode != http.StatusForbidden && resp.StatusCode != http.StatusBadRequest {
		t.Errorf("expected 403 or 400 for suspended client, got %d", resp.StatusCode)
	}
}

// TestE2E_CIMD_UnauthenticatedFetchAmplification pins the end-to-end shape of
// the amplification the CIMD path used to allow.
//
// GET /oauth/authorize takes no session, and resolving a URL-shaped client_id
// fetches that URL, so an unauthenticated request makes the server issue an
// outbound HTTP request to a host the caller names. Nothing on the failure path
// was cached, so every repeat produced another outbound request — measured at
// the adapter before the fix: 50 inbound, 50 outbound.
//
// The client here carries no session cookie and no credentials of any kind:
// that is the point.
func TestE2E_CIMD_UnauthenticatedFetchAmplification(t *testing.T) {
	scopes := []string{"tools/echo"}
	h, _ := e2e.SetupE2E(t, e2e.HarnessConfig{}, scopes)

	var outbound atomic.Int64
	cimdServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		outbound.Add(1)
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer cimdServer.Close()

	httpClient := h.NewClient()
	authURL := h.Issuer + "/oauth/authorize?" + url.Values{
		"client_id":             {cimdServer.URL + "/client.json"},
		"redirect_uri":          {"http://localhost:9999/callback"},
		"response_type":         {"code"},
		"scope":                 {"tools/echo"},
		"state":                 {"test-state"},
		"code_challenge":        {"E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"},
		"code_challenge_method": {"S256"},
	}.Encode()

	const inbound = 20
	for i := 0; i < inbound; i++ {
		resp, err := httpClient.Get(authURL)
		if err != nil {
			t.Fatalf("GET authorize %d: %v", i, err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("request %d: expected 400 for failed CIMD fetch, got %d", i, resp.StatusCode)
		}
	}

	if got := outbound.Load(); got != 1 {
		t.Errorf("%d unauthenticated authorize requests produced %d outbound CIMD fetches, want 1", inbound, got)
	}
}
