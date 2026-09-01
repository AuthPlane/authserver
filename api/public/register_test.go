//go:build integration

package public_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	apipublic "github.com/authplane/authserver/api/public"
	"github.com/authplane/authserver/internal/config"
	"github.com/authplane/authserver/internal/crypto"
	"github.com/authplane/authserver/internal/ports/input"
	"github.com/authplane/authserver/internal/services"
	"github.com/authplane/authserver/testdata"
)

func newDCRTestServer(t *testing.T, mode string, approvedRedirects []string) *httptest.Server {
	t.Helper()

	stores := testdata.SetupTestStores(t)
	obs := testObs()

	dcrMode := staticDCRModeForTest{
		Mode:              mode,
		ApprovedRedirects: approvedRedirects,
	}

	dcrSvc := services.NewDCRService(stores.Client, dcrMode, obs.WithComponent("dcr"), nil)
	jwksSvc := newTestJWKSService(t)

	srv := apipublic.NewServer(context.Background(), testServerCfg(), apipublic.Deps{
		CORSConfigProvider:    testCORS(),
		URLs:                  testURLBuilder(),
		SessionSecretProvider: testSessionSecret(),
		SessionConfigProvider: testSessionConfig(),
		JWKS:                  jwksSvc,
		IssuerProvider:        staticIssuerForTest("https://auth.example.com"),
		DCR:                   dcrSvc,
	}, obs)

	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	return ts
}

func postJSON(url string, body any) (*http.Response, error) {
	data, _ := json.Marshal(body)
	return http.Post(url, "application/json", bytes.NewReader(data))
}

// --- DCR HTTP Tests ---

func TestRegister_PublicClient(t *testing.T) {
	ts := newDCRTestServer(t, "open", nil)

	resp, err := postJSON(ts.URL+"/oauth/register", input.RegisterClientRequest{
		ClientName:   "Test Public",
		RedirectURIs: []string{"https://app.example.com/callback"},
	})
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("status: got %d, want 201", resp.StatusCode)
	}

	if ct := resp.Header.Get("Content-Type"); ct != "application/json" {
		t.Errorf("content-type: got %q", ct)
	}
	if cc := resp.Header.Get("Cache-Control"); cc != "no-store" {
		t.Errorf("cache-control: got %q, want %q", cc, "no-store")
	}

	var result input.RegisterClientResponse
	json.NewDecoder(resp.Body).Decode(&result)

	if result.ClientID == "" {
		t.Error("client_id is empty")
	}
	if result.ClientName != "Test Public" {
		t.Errorf("client_name: got %q", result.ClientName)
	}
	if result.ClientSecret != "" {
		t.Error("public client should not have secret")
	}
	if result.TokenEndpointAuthMethod != "none" {
		t.Errorf("auth method: got %q", result.TokenEndpointAuthMethod)
	}
	if result.ClientIDIssuedAt == 0 {
		t.Error("client_id_issued_at is zero")
	}
}

func TestRegister_ConfidentialClient(t *testing.T) {
	ts := newDCRTestServer(t, "open", nil)

	resp, err := postJSON(ts.URL+"/oauth/register", input.RegisterClientRequest{
		ClientName:              "Confidential App",
		RedirectURIs:            []string{"https://app.example.com/callback"},
		TokenEndpointAuthMethod: "client_secret_basic",
	})
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("status: got %d, want 201", resp.StatusCode)
	}

	var result input.RegisterClientResponse
	json.NewDecoder(resp.Body).Decode(&result)

	if result.ClientSecret == "" {
		t.Error("confidential client should have secret")
	}
	if result.ClientSecretExpiresAt == nil || *result.ClientSecretExpiresAt != 0 {
		t.Errorf("client_secret_expires_at: got %v, want ptr to 0", result.ClientSecretExpiresAt)
	}

	// Secret should not be a bcrypt hash (it's the plaintext).
	if err := crypto.CompareBcrypt(result.ClientSecret, "anything"); err == nil {
		t.Error("returned secret should be plaintext, not a hash")
	}
}

func TestRegister_AdminOnly_Returns403(t *testing.T) {
	ts := newDCRTestServer(t, "admin_only", nil)

	resp, err := postJSON(ts.URL+"/oauth/register", input.RegisterClientRequest{
		ClientName:   "Should Fail",
		RedirectURIs: []string{"https://app.example.com/callback"},
	})
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status: got %d, want 403", resp.StatusCode)
	}

	var errResp map[string]string
	json.NewDecoder(resp.Body).Decode(&errResp)
	if errResp["error"] == "" {
		t.Error("error field missing")
	}
}

func TestRegister_ApprovedRedirects_Rejected(t *testing.T) {
	ts := newDCRTestServer(t, "approved_redirects", []string{
		"https://app.example.com/callback",
	})

	resp, err := postJSON(ts.URL+"/oauth/register", input.RegisterClientRequest{
		ClientName:   "Bad Redirect",
		RedirectURIs: []string{"https://evil.example.com/callback"},
	})
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status: got %d, want 400", resp.StatusCode)
	}
}

func TestRegister_InvalidJSON(t *testing.T) {
	ts := newDCRTestServer(t, "open", nil)

	resp, err := http.Post(ts.URL+"/oauth/register", "application/json", bytes.NewReader([]byte("not json")))
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status: got %d, want 400", resp.StatusCode)
	}
}

func TestRegister_MissingName(t *testing.T) {
	ts := newDCRTestServer(t, "open", nil)

	resp, err := postJSON(ts.URL+"/oauth/register", input.RegisterClientRequest{
		RedirectURIs: []string{"https://app.example.com/callback"},
	})
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status: got %d, want 400", resp.StatusCode)
	}
}

// Matrix: 14.15 — DCR abuse protection: rate limiting prevents mass registration
func TestRegister_RateLimited(t *testing.T) {
	stores := testdata.SetupTestStores(t)
	obs := testObs()

	dcrMode := staticDCRModeForTest{
		Mode: "open",
	}
	dcrSvc := services.NewDCRService(stores.Client, dcrMode, obs.WithComponent("dcr"), nil)
	jwksSvc := newTestJWKSService(t)

	// Create server WITH rate limiting enabled (very low: 2 req/s, burst 2).
	srv := apipublic.NewServer(context.Background(), testServerCfg(), apipublic.Deps{
		CORSConfigProvider:    testCORS(),
		URLs:                  testURLBuilder(),
		SessionSecretProvider: testSessionSecret(),
		SessionConfigProvider: testSessionConfig(),
		JWKS:                  jwksSvc,
		IssuerProvider:        staticIssuerForTest("https://auth.example.com"),
		DCR:                   dcrSvc,
		RateLimitCfg: config.RateLimitConfig{
			Enabled:           true,
			RequestsPerSecond: 2,
			Burst:             2,
		},
	}, obs)

	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)

	// Send rapid registration requests. Rate limiter should reject some.
	var got429 bool
	for i := 0; i < 20; i++ {
		resp, err := postJSON(ts.URL+"/oauth/register", input.RegisterClientRequest{
			ClientName:   "Mass Reg " + crypto.GenerateRandomString(4),
			RedirectURIs: []string{"https://app.example.com/callback"},
		})
		if err != nil {
			t.Fatalf("register %d: %v", i, err)
		}
		if resp.StatusCode == http.StatusTooManyRequests {
			got429 = true
			// Verify Retry-After header.
			if ra := resp.Header.Get("Retry-After"); ra == "" {
				t.Error("429 on DCR should include Retry-After header")
			}
			resp.Body.Close()
			break
		}
		resp.Body.Close()
	}
	if !got429 {
		t.Error("DCR endpoint should be rate-limited; expected 429 after rapid registrations")
	}
}
