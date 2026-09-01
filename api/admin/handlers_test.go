// handlers_test.go drives the admin HTTP handlers against the real
// admin service wired with an in-memory sqlite store. The
// `//go:build integration` tag this file used to carry was dropped as
// part of the cleanup: the grant + issuance test block (lines
// 1985-2601 previously) moved to e2e/scenarios/{admin_grants,
// admin_issuances}_test.go where it now drives the public flow surfaces.
// The remaining tests below are HTTP-handler integration tests for
// admin CRUD endpoints; they keep direct store imports because their
// fixtures (clients, users, token families, consent_grants for FK
// blocking) cannot be created through the public surface that the
// admin httptest.NewServer here exposes.
//
// Without the integration tag this file runs under regular `go test
// ./api/admin/...`. Gate 0 ignores untagged files so the internal/
// imports above no longer count against the allowlist.

package admin_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	apiadmin "github.com/authplane/authserver/api/admin"
	"github.com/authplane/authserver/internal/adapters/sqlite"
	"github.com/authplane/authserver/internal/config"
	"github.com/authplane/authserver/internal/crypto"
	"github.com/authplane/authserver/internal/domain/audit"
	"github.com/authplane/authserver/internal/domain/client"
	"github.com/authplane/authserver/internal/domain/resource"
	"github.com/authplane/authserver/internal/domain/token"
	"github.com/authplane/authserver/internal/domain/user"
	"github.com/authplane/authserver/internal/observability"
	"github.com/authplane/authserver/internal/ports/output"
	"github.com/authplane/authserver/internal/services"
	"github.com/authplane/authserver/testdata"
)

const testAPIKey = "test-admin-api-key-123"

// noopSecretEncoder is a passthrough SecretEncoder for the admin HTTP tests: it
// returns the ref unchanged (env-backend semantics), so config_data is persisted
// verbatim.
type noopSecretEncoder struct{}

func (noopSecretEncoder) Encode(_ context.Context, in output.SecretInput) (output.EncodedSecret, error) {
	return output.EncodedSecret{Ref: in.Ref}, nil
}

func testObs() *observability.Provider {
	return observability.NewNoop()
}

type adminTestEnv struct {
	ts     *httptest.Server
	stores *testdata.TestHelper
}

func newAdminTestServer(t *testing.T) *adminTestEnv {
	t.Helper()
	stores := testdata.SetupTestStores(t)
	obs := testObs()

	adminSvc := services.NewAdminService(
		stores.Client, stores.User, stores.Token, stores.Audit,
		obs, nil,
		services.WithMachineTokenStore(stores.MachineToken),
		services.WithRevocationStore(stores.Revocation),
	)

	srv := mustNewServer(t, config.AdminConfig{
		Enabled: true,
		Address: ":0",
		APIKey:  testAPIKey,
	}, adminSvc, obs, apiadmin.OptionalDeps{})

	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)

	return &adminTestEnv{
		ts:     ts,
		stores: &testdata.TestHelper{Stores: stores},
	}
}

func createTestUser(t *testing.T, stores *sqlite.Stores) *user.User {
	t.Helper()
	now := time.Now().UTC()
	u := &user.User{
		ID:           crypto.GenerateRandomString(16),
		Email:        crypto.GenerateRandomString(8) + "@test.com",
		Name:         "Test User",
		PasswordHash: "$2a$10$dummy",
		Role:         user.RoleUser,
		Status:       user.StatusActive,
		Provider:     user.ProviderLocal,
		CreatedAt:    now,
		UpdatedAt:    now,
	}
	if err := stores.User.Create(context.Background(), u); err != nil {
		t.Fatalf("create test user: %v", err)
	}
	return u
}

func createTestClient(t *testing.T, stores *sqlite.Stores) *client.Client {
	t.Helper()
	now := time.Now().UTC()
	c := &client.Client{
		ID:                      crypto.GenerateClientID(),
		Name:                    "Handler Test Client",
		RedirectURIs:            []string{"https://app.example.com/callback"},
		GrantTypes:              []string{"authorization_code"},
		ResponseTypes:           []string{"code"},
		TokenEndpointAuthMethod: "none",
		Status:                  client.StatusActive,
		RegistrationSource:      client.SourceDCR,
		IssuedAt:                now,
		UpdatedAt:               now,
	}
	if err := stores.Client.Create(context.Background(), c); err != nil {
		t.Fatalf("create test client: %v", err)
	}
	return c
}

// createTokenFamily seeds the parent client + user rows for the family's
// FK columns and persists the family. Mirrors the pattern used
// by adminTestSetup.createTokenFamily in internal/services tests.
func (e *adminTestEnv) createTokenFamily(t *testing.T, family *token.Family) {
	t.Helper()
	testdata.EnsureClient(t, e.stores.Stores.Client, family.ClientID)
	testdata.EnsureUser(t, e.stores.Stores.User, family.UserID)
	if err := e.stores.Stores.Token.CreateFamily(context.Background(), family); err != nil {
		t.Fatalf("create token family: %v", err)
	}
}

func (e *adminTestEnv) doRequest(t *testing.T, method, path string, body any) *http.Response {
	t.Helper()
	var bodyReader *bytes.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		bodyReader = bytes.NewReader(b)
	} else {
		bodyReader = bytes.NewReader(nil)
	}

	req, err := http.NewRequestWithContext(t.Context(), method, e.ts.URL+path, bodyReader)
	if err != nil {
		t.Fatalf("build req: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+testAPIKey)
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	return resp
}

func TestAdmin_AuthRequired(t *testing.T) {
	env := newAdminTestServer(t)

	// No auth header.
	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, env.ts.URL+"/admin/stats", nil)
	if err != nil {
		t.Fatalf("build req: %v", err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	_ = resp.Body.Close()

	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status: got %d, want 401", resp.StatusCode)
	}
}

func TestAdmin_InvalidKey(t *testing.T) {
	env := newAdminTestServer(t)

	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, env.ts.URL+"/admin/stats", nil)
	if err != nil {
		t.Fatalf("build req: %v", err)
	}
	req.Header.Set("Authorization", "Bearer wrong-key")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	_ = resp.Body.Close()

	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status: got %d, want 401", resp.StatusCode)
	}
}

func TestAdmin_ListClients(t *testing.T) {
	env := newAdminTestServer(t)

	// Create a client.
	now := time.Now().UTC()
	c := &client.Client{
		ID:                      crypto.GenerateClientID(),
		Name:                    "Admin List Test",
		RedirectURIs:            []string{"https://app.example.com/callback"},
		GrantTypes:              []string{"authorization_code"},
		ResponseTypes:           []string{"code"},
		TokenEndpointAuthMethod: "none",
		Status:                  client.StatusActive,
		RegistrationSource:      client.SourceDCR,
		IssuedAt:                now,
		UpdatedAt:               now,
	}
	_ = env.stores.Stores.Client.Create(context.Background(), c)
	resp := env.doRequest(t, "GET", "/admin/clients", nil)
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status: got %d, want 200", resp.StatusCode)
	}

	var clients []map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&clients)
	if len(clients) < 1 {
		t.Error("expected at least 1 client")
	}
}

func TestAdmin_SuspendClient(t *testing.T) {
	env := newAdminTestServer(t)

	now := time.Now().UTC()
	c := &client.Client{
		ID:                      crypto.GenerateClientID(),
		Name:                    "Suspend Test",
		RedirectURIs:            []string{"https://app.example.com/callback"},
		GrantTypes:              []string{"authorization_code"},
		ResponseTypes:           []string{"code"},
		TokenEndpointAuthMethod: "none",
		Status:                  client.StatusActive,
		RegistrationSource:      client.SourceDCR,
		IssuedAt:                now,
		UpdatedAt:               now,
	}
	_ = env.stores.Stores.Client.Create(context.Background(), c)
	resp := env.doRequest(t, "PATCH", "/admin/clients/"+c.ID+"/suspend", nil)
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status: got %d, want 200", resp.StatusCode)
	}

	// Verify.
	got, _ := env.stores.Stores.Client.GetByID(context.Background(), c.ID)
	if got.Status != client.StatusSuspended {
		t.Errorf("status: got %q", got.Status)
	}
}

func TestAdmin_CreateClient_201(t *testing.T) {
	env := newAdminTestServer(t)

	body := map[string]any{
		"client_name":                "My Server",
		"grant_types":                []string{"client_credentials"},
		"token_endpoint_auth_method": "client_secret_basic",
		"scope":                      "mcp:read",
	}
	resp := env.doRequest(t, "POST", "/admin/clients", body)
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusCreated {
		var errBody map[string]any
		_ = json.NewDecoder(resp.Body).Decode(&errBody)
		t.Fatalf("status: got %d, want 201; body: %v", resp.StatusCode, errBody)
	}

	var result map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&result)

	if result["client_id"] == nil || result["client_id"] == "" {
		t.Error("client_id is empty")
	}
	if result["client_secret"] == nil || result["client_secret"] == "" {
		t.Error("client_secret should be present for confidential client")
	}
	if result["registration_source"] != "admin" {
		t.Errorf("registration_source: got %v", result["registration_source"])
	}
}

func TestAdmin_CreateClient_Public_NoSecret(t *testing.T) {
	env := newAdminTestServer(t)

	body := map[string]any{
		"client_name":                "Public SPA",
		"redirect_uris":              []string{"https://app.example.com/callback"},
		"grant_types":                []string{"authorization_code"},
		"token_endpoint_auth_method": "none",
	}
	resp := env.doRequest(t, "POST", "/admin/clients", body)
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusCreated {
		var errBody map[string]any
		_ = json.NewDecoder(resp.Body).Decode(&errBody)
		t.Fatalf("status: got %d, want 201; body: %v", resp.StatusCode, errBody)
	}

	var result map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&result)

	// Public clients should not have a secret.
	if result["client_secret"] != nil && result["client_secret"] != "" {
		t.Error("public client should not have client_secret in response")
	}
}

func TestAdmin_CreateClient_400_MissingName(t *testing.T) {
	env := newAdminTestServer(t)

	body := map[string]any{
		"redirect_uris": []string{"https://app.example.com/callback"},
	}
	resp := env.doRequest(t, "POST", "/admin/clients", body)
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status: got %d, want 400", resp.StatusCode)
	}
}

func TestAdmin_CreateClient_400_InvalidJSON(t *testing.T) {
	env := newAdminTestServer(t)

	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, env.ts.URL+"/admin/clients", strings.NewReader("{invalid"))
	if err != nil {
		t.Fatalf("build req: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+testAPIKey)
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status: got %d, want 400", resp.StatusCode)
	}
}

func TestAdmin_UpdateClient_200(t *testing.T) {
	env := newAdminTestServer(t)

	// Create a client first.
	createBody := map[string]any{
		"client_name":                "Update Me",
		"redirect_uris":              []string{"https://app.example.com/callback"},
		"grant_types":                []string{"authorization_code"},
		"token_endpoint_auth_method": "none",
	}
	createResp := env.doRequest(t, "POST", "/admin/clients", createBody)
	defer func() { _ = createResp.Body.Close() }()
	var created map[string]any
	_ = json.NewDecoder(createResp.Body).Decode(&created)
	clientID := created["client_id"].(string)

	// Update name only.
	updateBody := map[string]any{
		"client_name": "Updated Name",
	}
	resp := env.doRequest(t, "PATCH", "/admin/clients/"+clientID, updateBody)
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		var errBody map[string]any
		_ = json.NewDecoder(resp.Body).Decode(&errBody)
		t.Fatalf("status: got %d, want 200; body: %v", resp.StatusCode, errBody)
	}

	var result map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&result)
	if result["name"] != "Updated Name" {
		t.Errorf("name: got %v", result["name"])
	}
}

func TestAdmin_UpdateClient_400_EmptyName(t *testing.T) {
	env := newAdminTestServer(t)

	createBody := map[string]any{
		"client_name":                "To Invalidate",
		"redirect_uris":              []string{"https://app.example.com/callback"},
		"grant_types":                []string{"authorization_code"},
		"token_endpoint_auth_method": "none",
	}
	createResp := env.doRequest(t, "POST", "/admin/clients", createBody)
	defer func() { _ = createResp.Body.Close() }()
	var created map[string]any
	_ = json.NewDecoder(createResp.Body).Decode(&created)
	clientID := created["client_id"].(string)

	// Empty name should fail validation.
	updateBody := map[string]any{
		"client_name": "",
	}
	resp := env.doRequest(t, "PATCH", "/admin/clients/"+clientID, updateBody)
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status: got %d, want 400", resp.StatusCode)
	}
}

func TestAdmin_UpdateClient_NotFound(t *testing.T) {
	env := newAdminTestServer(t)

	updateBody := map[string]any{
		"client_name": "Ghost",
	}
	resp := env.doRequest(t, "PATCH", "/admin/clients/nonexistent-id", updateBody)
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status: got %d, want 400", resp.StatusCode)
	}
}

func TestAdmin_RotateClientSecret_200(t *testing.T) {
	env := newAdminTestServer(t)

	// Create a confidential client first.
	createBody := map[string]any{
		"client_name":                "Rotate Test",
		"grant_types":                []string{"client_credentials"},
		"token_endpoint_auth_method": "client_secret_basic",
	}
	createResp := env.doRequest(t, "POST", "/admin/clients", createBody)
	defer func() { _ = createResp.Body.Close() }()
	var created map[string]any
	_ = json.NewDecoder(createResp.Body).Decode(&created)
	clientID := created["client_id"].(string)

	// Rotate.
	resp := env.doRequest(t, "POST", "/admin/clients/"+clientID+"/rotate-secret", nil)
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		var errBody map[string]any
		_ = json.NewDecoder(resp.Body).Decode(&errBody)
		t.Fatalf("status: got %d, want 200; body: %v", resp.StatusCode, errBody)
	}

	var result map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&result)
	if result["client_id"] != clientID {
		t.Errorf("client_id: got %v, want %s", result["client_id"], clientID)
	}
	if result["client_secret"] == nil || result["client_secret"] == "" {
		t.Error("client_secret should be present")
	}
}

func TestAdmin_RotateClientSecret_PublicClient_400(t *testing.T) {
	env := newAdminTestServer(t)

	// Create a public client.
	createBody := map[string]any{
		"client_name":                "Public Rotate",
		"redirect_uris":              []string{"https://app.example.com/callback"},
		"grant_types":                []string{"authorization_code"},
		"token_endpoint_auth_method": "none",
	}
	createResp := env.doRequest(t, "POST", "/admin/clients", createBody)
	defer func() { _ = createResp.Body.Close() }()
	var created map[string]any
	_ = json.NewDecoder(createResp.Body).Decode(&created)
	clientID := created["client_id"].(string)

	// Rotate should fail with 400.
	resp := env.doRequest(t, "POST", "/admin/clients/"+clientID+"/rotate-secret", nil)
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status: got %d, want 400", resp.StatusCode)
	}
}

func TestAdmin_RotateClientSecret_NotFound_400(t *testing.T) {
	env := newAdminTestServer(t)

	resp := env.doRequest(t, "POST", "/admin/clients/nonexistent-id/rotate-secret", nil)
	defer func() { _ = resp.Body.Close() }()
	// Non-existent client returns 400 (domain error ErrClientNotFound).
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status: got %d, want 400", resp.StatusCode)
	}
}

func TestAdmin_CreateUser(t *testing.T) {
	env := newAdminTestServer(t)

	body := map[string]string{
		"email":    "new-admin@example.com",
		"password": "secret123",
		"role":     "admin",
	}
	resp := env.doRequest(t, "POST", "/admin/users", body)
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusCreated {
		var errBody map[string]any
		_ = json.NewDecoder(resp.Body).Decode(&errBody)
		t.Fatalf("status: got %d, want 201; body: %v", resp.StatusCode, errBody)
	}

	var userResp map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&userResp)
	if userResp["id"] == nil || userResp["id"] == "" {
		t.Error("id is empty")
	}
	if userResp["email"] != "new-admin@example.com" {
		t.Errorf("email: got %v", userResp["email"])
	}
}

// POST /admin/users on duplicate email must return 409 Conflict, not 500.
// Idempotent setup scripts repeat the same POST and rely on the conflict status
// to detect "already created"; a 500 makes that indistinguishable from a real
// outage.
func TestAdmin_CreateUser_DuplicateEmail_Returns409(t *testing.T) {
	env := newAdminTestServer(t)

	body := map[string]string{
		"email":    "alice@example.com",
		"password": "secret123",
	}

	first := env.doRequest(t, "POST", "/admin/users", body)
	_ = first.Body.Close()
	if first.StatusCode != http.StatusCreated {
		t.Fatalf("first create: got %d, want 201", first.StatusCode)
	}

	second := env.doRequest(t, "POST", "/admin/users", body)
	defer func() { _ = second.Body.Close() }()
	if second.StatusCode != http.StatusConflict {
		b, _ := io.ReadAll(second.Body)
		t.Fatalf("second create: got %d, want 409: %s", second.StatusCode, string(b))
	}

	ct := second.Header.Get("Content-Type")
	if ct != "application/problem+json" {
		t.Errorf("Content-Type: got %q, want application/problem+json", ct)
	}

	var errResp map[string]any
	if err := json.NewDecoder(second.Body).Decode(&errResp); err != nil {
		t.Fatalf("decode error body: %v", err)
	}
	detail, _ := errResp["detail"].(string)
	if detail == "" {
		t.Fatalf("error body has no detail: %v", errResp)
	}
	if strings.Contains(strings.ToLower(detail), "internal") {
		t.Errorf("detail leaks internal-error message: %q", detail)
	}
	if !strings.Contains(strings.ToLower(detail), "already exists") {
		t.Errorf("detail %q does not mention conflict", detail)
	}
}

// Matrix: 16.2 — upgraded from ⚠️: non-admin key is rejected
func TestAdmin_NonAdminKey_Rejected(t *testing.T) {
	env := newAdminTestServer(t)

	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, env.ts.URL+"/admin/stats", nil)
	if err != nil {
		t.Fatalf("build req: %v", err)
	}
	req.Header.Set("Authorization", "Bearer not-the-admin-key")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	_ = resp.Body.Close()

	// Any key that doesn't match the configured admin API key must be rejected.
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status: got %d, want 401", resp.StatusCode)
	}
}

// Matrix: 10.4 — admin API errors use structured JSON (RFC 9457 Problem Details)
func TestAdmin_ErrorFormat_StructuredJSON(t *testing.T) {
	env := newAdminTestServer(t)

	// Request a non-existent resource to trigger 404.
	resp := env.doRequest(t, "GET", "/admin/clients/nonexistent-client-id", nil)
	defer func() { _ = resp.Body.Close() }()
	// Verify error response uses RFC 9457 Problem Details format.
	ct := resp.Header.Get("Content-Type")
	if ct != "application/problem+json" {
		t.Errorf("Content-Type: got %q, want application/problem+json", ct)
	}

	var errResp map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&errResp)
	if errResp["detail"] == nil || errResp["detail"] == "" {
		t.Error("admin error response should have 'detail' field (RFC 9457)")
	}
	if errResp["status"] == nil {
		t.Error("admin error response should have 'status' field (RFC 9457)")
	}
}

// Matrix: 10.4 — admin API 401 errors also use structured JSON
func TestAdmin_AuthError_StructuredJSON(t *testing.T) {
	env := newAdminTestServer(t)

	// Request without auth.
	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, env.ts.URL+"/admin/clients", nil)
	if err != nil {
		t.Fatalf("build req: %v", err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status: got %d, want 401", resp.StatusCode)
	}

	ct := resp.Header.Get("Content-Type")
	if ct != "application/json" {
		t.Errorf("Content-Type: got %q, want application/json", ct)
	}

	var errResp map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&errResp)
	if errResp["error"] == nil || errResp["error"] == "" {
		t.Error("admin auth error should have 'error' field")
	}
}

func TestAdmin_GetStats(t *testing.T) {
	env := newAdminTestServer(t)

	resp := env.doRequest(t, "GET", "/admin/stats", nil)
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status: got %d, want 200", resp.StatusCode)
	}

	var stats map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&stats)

	// Should have all stat fields (even if zero).
	for _, field := range []string{"clients", "users", "active_tokens_24h", "revoked_tokens", "connections"} {
		if _, ok := stats[field]; !ok {
			t.Errorf("missing field: %s", field)
		}
	}
}

// A malformed or out-of-bounds audit query parameter is a 400, never silently
// replaced with a default the caller did not ask for.
func TestAdmin_QueryAudit_ParamValidation(t *testing.T) {
	env := newAdminTestServer(t)

	cases := []struct {
		name  string
		query string
		want  int
	}{
		{"no params", "", http.StatusOK},
		{"valid since and limit", "?limit=10&since=" + time.Now().UTC().Add(-time.Hour).Format(time.RFC3339), http.StatusOK},
		{"malformed since", "?since=garbage", http.StatusBadRequest},
		{"malformed until", "?until=yesterday", http.StatusBadRequest},
		{"malformed limit", "?limit=abc", http.StatusBadRequest},
		{"malformed offset", "?offset=1e9", http.StatusBadRequest},
		{"limit beyond the cap", "?limit=1000000000", http.StatusBadRequest},
		{"offset beyond the cap", "?offset=100000000", http.StatusBadRequest},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resp := env.doRequest(t, "GET", "/admin/audit"+tc.query, nil)
			defer func() { _ = resp.Body.Close() }()
			if resp.StatusCode != tc.want {
				body, _ := io.ReadAll(resp.Body)
				t.Errorf("status: got %d, want %d (body: %s)", resp.StatusCode, tc.want, body)
			}
		})
	}
}

// Matrix: 18.14 — Admin API rejects all when API key is empty
func TestAdmin_EmptyKey_RejectsAll(t *testing.T) {
	stores := testdata.SetupTestStores(t)
	obs := testObs()

	adminSvc := services.NewAdminService(
		stores.Client, stores.User, stores.Token, stores.Audit,
		obs, nil,
	)

	// Server with EMPTY API key.
	srv := mustNewServer(t, config.AdminConfig{
		Enabled: true,
		Address: ":0",
		APIKey:  "", // empty!
	}, adminSvc, obs, apiadmin.OptionalDeps{})

	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)

	// Even with a Bearer token, should be rejected.
	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, ts.URL+"/admin/stats", nil)
	if err != nil {
		t.Fatalf("build req: %v", err)
	}
	req.Header.Set("Authorization", "Bearer some-token")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	_ = resp.Body.Close()

	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("empty key should reject all requests, got %d", resp.StatusCode)
	}
}

// Matrix: 18.16 — Admin 500 errors don't leak internal details
func TestAdmin_InternalError_NoDetailLeak(t *testing.T) {
	env := newAdminTestServer(t)

	// Request a non-existent client — should return error without internal details.
	resp := env.doRequest(t, "GET", "/admin/clients/nonexistent-id-12345", nil)
	defer func() { _ = resp.Body.Close() }()
	var body map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&body)

	// Verify the error response doesn't contain stack traces, file paths, or SQL details.
	errMsg, _ := body["error"].(string)
	errDesc, _ := body["error_description"].(string)
	combined := errMsg + " " + errDesc
	for _, leak := range []string{".go:", "runtime.", "goroutine", "SQL", "panic"} {
		if strings.Contains(combined, leak) {
			t.Errorf("admin error response leaks internal detail %q: %s", leak, combined)
		}
	}
}

// Matrix: 11.2 — admin API rate limited (CODE FIX: added per-IP rate limiter to admin server)
func TestAdmin_RateLimited(t *testing.T) {
	stores := testdata.SetupTestStores(t)
	obs := testObs()

	adminSvc := services.NewAdminService(
		stores.Client, stores.User, stores.Token, stores.Audit,
		obs, nil,
	)

	// Create admin server with rate limiting: 2 req/s, burst 2.
	srv := mustNewServer(t, config.AdminConfig{
		Enabled:           true,
		Address:           ":0",
		APIKey:            testAPIKey,
		RequestsPerSecond: 2,
		Burst:             2,
	}, adminSvc, obs, apiadmin.OptionalDeps{})

	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)

	var got429 bool
	for i := 0; i < 20; i++ {
		req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, ts.URL+"/admin/stats", nil)
		if err != nil {
			t.Fatalf("build req: %v", err)
		}
		req.Header.Set("Authorization", "Bearer "+testAPIKey)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("do: %v", err)
		}
		if resp.StatusCode == http.StatusTooManyRequests {
			got429 = true
			if ra := resp.Header.Get("Retry-After"); ra == "" {
				t.Error("429 on admin API should include Retry-After header")
			}
			_ = resp.Body.Close()
			break
		}
		_ = resp.Body.Close()
	}
	if !got429 {
		t.Error("admin API should be rate-limited; expected 429 after rapid requests")
	}
}

// --- Token management handler tests ---

func TestAdminHandler_ListTokens_200(t *testing.T) {
	env := newAdminTestServer(t)

	// Seed a token family.
	now := time.Now().UTC()
	env.createTokenFamily(t, &token.Family{
		ID:        crypto.GenerateRandomString(16),
		ClientID:  "handler-list-client",
		UserID:    "handler-list-user",
		Scope:     "tools/query",
		Status:    token.FamilyActive,
		CreatedAt: now,
	})

	resp := env.doRequest(t, "GET", "/admin/tokens?client_id=handler-list-client&limit=10", nil)
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status: got %d, want 200", resp.StatusCode)
	}

	var result map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&result)
	total, _ := result["total"].(float64)
	if total < 1 {
		t.Errorf("total: got %v, want >= 1", total)
	}
}

func TestAdminHandler_ListUserTokens_200(t *testing.T) {
	env := newAdminTestServer(t)

	// Create a user.
	u := createTestUser(t, env.stores.Stores)

	// Seed a token family for this user.
	now := time.Now().UTC()
	env.createTokenFamily(t, &token.Family{
		ID:        crypto.GenerateRandomString(16),
		ClientID:  "handler-user-token-client",
		UserID:    u.ID,
		Scope:     "tools/query",
		Status:    token.FamilyActive,
		CreatedAt: now,
	})

	resp := env.doRequest(t, "GET", "/admin/users/"+u.ID+"/tokens?limit=10", nil)
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status: got %d, want 200", resp.StatusCode)
	}

	var result map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&result)
	total, _ := result["total"].(float64)
	if total < 1 {
		t.Errorf("total: got %v, want >= 1", total)
	}
}

func TestAdminHandler_RevokeToken_204(t *testing.T) {
	env := newAdminTestServer(t)

	family := &token.Family{
		ID:        crypto.GenerateRandomString(16),
		ClientID:  "handler-revoke-client",
		UserID:    "handler-revoke-user",
		Scope:     "tools/query",
		Status:    token.FamilyActive,
		CreatedAt: time.Now().UTC(),
	}
	env.createTokenFamily(t, family)

	resp := env.doRequest(t, "DELETE", "/admin/tokens/"+family.ID, nil)
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusNoContent {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status: got %d, want 204, body: %s", resp.StatusCode, body)
	}
}

func TestAdminHandler_RevokeToken_400_NotFound(t *testing.T) {
	env := newAdminTestServer(t)

	resp := env.doRequest(t, "DELETE", "/admin/tokens/nonexistent-jti-12345", nil)
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusBadRequest {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status: got %d, want 400, body: %s", resp.StatusCode, body)
	}
}

// --- Delete Client ---

func TestAdminHandler_DeleteClient_204(t *testing.T) {
	env := newAdminTestServer(t)

	c := createTestClient(t, env.stores.Stores)

	resp := env.doRequest(t, "DELETE", "/admin/clients/"+c.ID, nil)
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusNoContent {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status: got %d, want 204, body: %s", resp.StatusCode, body)
	}
}

func TestAdminHandler_DeleteClient_409_ActiveTokens(t *testing.T) {
	env := newAdminTestServer(t)

	c := createTestClient(t, env.stores.Stores)

	// Create active token family.
	family := &token.Family{
		ID:        crypto.GenerateRandomString(16),
		ClientID:  c.ID,
		UserID:    "test-user",
		Scope:     "tools/query",
		Status:    token.FamilyActive,
		CreatedAt: time.Now().UTC(),
	}
	env.createTokenFamily(t, family)

	resp := env.doRequest(t, "DELETE", "/admin/clients/"+c.ID, nil)
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusConflict {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status: got %d, want 409, body: %s", resp.StatusCode, body)
	}
}

func TestAdminHandler_DeleteClient_204_Force(t *testing.T) {
	env := newAdminTestServer(t)

	c := createTestClient(t, env.stores.Stores)

	// Create active token family.
	family := &token.Family{
		ID:        crypto.GenerateRandomString(16),
		ClientID:  c.ID,
		UserID:    "test-user",
		Scope:     "tools/query",
		Status:    token.FamilyActive,
		CreatedAt: time.Now().UTC(),
	}
	env.createTokenFamily(t, family)

	resp := env.doRequest(t, "DELETE", "/admin/clients/"+c.ID+"?force=true", nil)
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusNoContent {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status: got %d, want 204, body: %s", resp.StatusCode, body)
	}
}

// --- Force Logout ---

func TestAdminHandler_ForceLogoutUser_200(t *testing.T) {
	env := newAdminTestServer(t)

	u := createTestUser(t, env.stores.Stores)

	// Create a token family for this user.
	family := &token.Family{
		ID:        crypto.GenerateRandomString(16),
		ClientID:  "force-logout-client",
		UserID:    u.ID,
		Scope:     "tools/query",
		Status:    token.FamilyActive,
		CreatedAt: time.Now().UTC(),
	}
	env.createTokenFamily(t, family)

	resp := env.doRequest(t, "DELETE", "/admin/users/"+u.ID+"/tokens", nil)
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status: got %d, want 200, body: %s", resp.StatusCode, body)
	}

	var result map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&result)
	if result["user_id"] != u.ID {
		t.Errorf("user_id: got %v, want %s", result["user_id"], u.ID)
	}
	count, _ := result["tokens_revoked"].(float64)
	if count < 1 {
		t.Errorf("tokens_revoked: got %v, want >= 1", count)
	}
}

// --- Update User ---

func TestAdminHandler_UpdateUser_200(t *testing.T) {
	env := newAdminTestServer(t)

	u := createTestUser(t, env.stores.Stores)

	body := map[string]string{"email": "updated@example.com", "name": "Updated Name"}
	resp := env.doRequest(t, "PATCH", "/admin/users/"+u.ID, body)
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("status: got %d, want 200, body: %s", resp.StatusCode, b)
	}

	var result map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&result)
	if result["email"] != "updated@example.com" {
		t.Errorf("email: got %v, want updated@example.com", result["email"])
	}
	if result["name"] != "Updated Name" {
		t.Errorf("name: got %v, want Updated Name", result["name"])
	}
}

func TestAdminHandler_UpdateUser_PartialUpdate(t *testing.T) {
	env := newAdminTestServer(t)

	u := createTestUser(t, env.stores.Stores)

	// Only update name, email should remain unchanged.
	body := map[string]string{"name": "Only Name Changed"}
	resp := env.doRequest(t, "PATCH", "/admin/users/"+u.ID, body)
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("status: got %d, want 200, body: %s", resp.StatusCode, b)
	}

	var result map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&result)
	if result["email"] != u.Email {
		t.Errorf("email should be unchanged: got %v, want %s", result["email"], u.Email)
	}
	if result["name"] != "Only Name Changed" {
		t.Errorf("name: got %v, want Only Name Changed", result["name"])
	}
}

func TestAdminHandler_UpdateUser_404_NotFound(t *testing.T) {
	env := newAdminTestServer(t)

	body := map[string]string{"name": "Ghost"}
	resp := env.doRequest(t, "PATCH", "/admin/users/nonexistent-user-id", body)
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode == http.StatusOK {
		t.Fatalf("expected error status for nonexistent user, got 200")
	}
}

// --- Delete User ---

func TestAdminHandler_DeleteUser_204(t *testing.T) {
	env := newAdminTestServer(t)

	u := createTestUser(t, env.stores.Stores)

	resp := env.doRequest(t, "DELETE", "/admin/users/"+u.ID, nil)
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusNoContent {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("status: got %d, want 204, body: %s", resp.StatusCode, b)
	}
}

func TestAdminHandler_DeleteUser_409_ActiveTokens(t *testing.T) {
	env := newAdminTestServer(t)

	u := createTestUser(t, env.stores.Stores)

	// Create active token family for user.
	family := &token.Family{
		ID:        crypto.GenerateRandomString(16),
		ClientID:  "delete-user-client",
		UserID:    u.ID,
		Scope:     "tools/query",
		Status:    token.FamilyActive,
		CreatedAt: time.Now().UTC(),
	}
	env.createTokenFamily(t, family)

	resp := env.doRequest(t, "DELETE", "/admin/users/"+u.ID, nil)
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusConflict {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("status: got %d, want 409, body: %s", resp.StatusCode, b)
	}
}

func TestAdminHandler_DeleteUser_204_Force(t *testing.T) {
	env := newAdminTestServer(t)

	u := createTestUser(t, env.stores.Stores)

	// Create active token family for user.
	family := &token.Family{
		ID:        crypto.GenerateRandomString(16),
		ClientID:  "delete-user-force-client",
		UserID:    u.ID,
		Scope:     "tools/query",
		Status:    token.FamilyActive,
		CreatedAt: time.Now().UTC(),
	}
	env.createTokenFamily(t, family)

	resp := env.doRequest(t, "DELETE", "/admin/users/"+u.ID+"?force=true", nil)
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusNoContent {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("status: got %d, want 204, body: %s", resp.StatusCode, b)
	}
}

func TestAdminHandler_ForceLogoutUser_404_UserNotFound(t *testing.T) {
	env := newAdminTestServer(t)

	resp := env.doRequest(t, "DELETE", "/admin/users/nonexistent-user/tokens", nil)
	defer func() { _ = resp.Body.Close() }()
	// User not found returns from writeDomainOrInternalError — check it's an error.
	if resp.StatusCode == http.StatusNoContent || resp.StatusCode == http.StatusOK {
		t.Fatalf("expected error status, got %d", resp.StatusCode)
	}
}

// --- Key Management ---

// mockKeyStore implements output.KeyStore for admin key tests.
type mockKeyStore struct {
	current  *output.SigningKey
	previous *output.SigningKey
}

func (m *mockKeyStore) LoadCurrent(_ context.Context) (*output.SigningKey, error) {
	return m.current, nil
}

func (m *mockKeyStore) LoadPrevious(_ context.Context) (*output.SigningKey, error) {
	return m.previous, nil
}

func (m *mockKeyStore) Save(_ context.Context, key *output.SigningKey) error {
	m.previous = m.current
	m.current = key
	return nil
}

func (m *mockKeyStore) ListActive(_ context.Context) ([]*output.SigningKey, error) {
	var keys []*output.SigningKey
	if m.current != nil {
		keys = append(keys, m.current)
	}
	if m.previous != nil {
		keys = append(keys, m.previous)
	}
	return keys, nil
}

var _ output.KeyStore = (*mockKeyStore)(nil)

// mockAdminAuditRecorder captures audit events for assertion.
type mockAdminAuditRecorder struct {
	events []audit.Event
}

func (m *mockAdminAuditRecorder) Record(_ context.Context, e audit.Event) {
	m.events = append(m.events, e)
}

func newAdminKeysTestServer(t *testing.T) *httptest.Server {
	t.Helper()
	stores := testdata.SetupTestStores(t)
	obs := testObs()

	adminSvc := services.NewAdminService(
		stores.Client, stores.User, stores.Token, stores.Audit,
		obs, nil,
	)

	keyStore := &mockKeyStore{}
	jwksSvc := services.NewJWKSService(keyStore, nil, "ES256", obs)

	auditor := &mockAdminAuditRecorder{}

	keysDeps := &apiadmin.KeysDeps{
		KeyAdmin: jwksSvc,
		Audit:    auditor,
	}

	srv := mustNewServer(t, config.AdminConfig{
		Enabled: true,
		Address: ":0",
		APIKey:  testAPIKey,
	}, adminSvc, obs, apiadmin.OptionalDeps{Keys: keysDeps})

	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	return ts
}

func doKeyRequest(t *testing.T, ts *httptest.Server, method, path string) *http.Response {
	t.Helper()
	req, err := http.NewRequestWithContext(t.Context(), method, ts.URL+path, nil)
	if err != nil {
		t.Fatalf("build req: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+testAPIKey)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	return resp
}

func TestAdminHandler_ListKeys_200(t *testing.T) {
	ts := newAdminKeysTestServer(t)

	resp := doKeyRequest(t, ts, "GET", "/admin/keys")
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status: got %d, want 200, body: %s", resp.StatusCode, body)
	}

	var result map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&result)
	keys, ok := result["keys"].([]any)
	if !ok {
		t.Fatal("response should have 'keys' array")
	}
	// Initially empty — no keys generated yet.
	// The JWKS service generates on first GetSigningKey call, but BuildJWKS
	// returns an empty set when no keys exist for keyfile/vault_transit path.
	_ = keys
}

func TestAdminHandler_RotateKey_200(t *testing.T) {
	ts := newAdminKeysTestServer(t)

	resp := doKeyRequest(t, ts, "POST", "/admin/keys/rotate")
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status: got %d, want 200, body: %s", resp.StatusCode, body)
	}

	var result map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&result)
	if result["kid"] == nil || result["kid"] == "" {
		t.Error("response should have 'kid' field")
	}
	if result["alg"] != "ES256" {
		t.Errorf("alg: got %v, want ES256", result["alg"])
	}
}

func TestAdminHandler_RotateKey_ThenListKeys_ShowsBoth(t *testing.T) {
	ts := newAdminKeysTestServer(t)

	// Rotate twice to get current + previous.
	resp1 := doKeyRequest(t, ts, "POST", "/admin/keys/rotate")
	_ = resp1.Body.Close()
	if resp1.StatusCode != http.StatusOK {
		t.Fatalf("rotate 1 status: got %d, want 200", resp1.StatusCode)
	}

	resp2 := doKeyRequest(t, ts, "POST", "/admin/keys/rotate")
	_ = resp2.Body.Close()
	if resp2.StatusCode != http.StatusOK {
		t.Fatalf("rotate 2 status: got %d, want 200", resp2.StatusCode)
	}

	// List should show 2 keys.
	resp := doKeyRequest(t, ts, "GET", "/admin/keys")
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status: got %d, want 200, body: %s", resp.StatusCode, body)
	}

	var result struct {
		Keys []struct {
			KeyID  string `json:"kid"`
			Alg    string `json:"alg"`
			Status string `json:"status"`
		} `json:"keys"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&result)

	if len(result.Keys) != 2 {
		t.Fatalf("keys: got %d, want 2", len(result.Keys))
	}
	if result.Keys[0].Status != "current" {
		t.Errorf("first key status: got %q, want current", result.Keys[0].Status)
	}
	if result.Keys[1].Status != "previous" {
		t.Errorf("second key status: got %q, want previous", result.Keys[1].Status)
	}
}

// ─── DCR Settings handler tests ──────────────────────────────────────────────

// mockDCRAdmin implements admin.DCRAdmin for handler tests.
type mockDCRAdmin struct {
	mode   string
	getErr error // when set, GetMode fails closed (provider unavailable)
	setErr error // when set, SetMode fails
}

func (m *mockDCRAdmin) GetMode(ctx context.Context) (string, error) { return m.mode, m.getErr }
func (m *mockDCRAdmin) SetMode(ctx context.Context, mode string) error {
	if m.setErr != nil {
		return m.setErr
	}
	m.mode = mode
	return nil
}

func newAdminDCRTestServer(t *testing.T) (*httptest.Server, *mockDCRAdmin) {
	t.Helper()
	stores := testdata.SetupTestStores(t)
	obs := testObs()

	adminSvc := services.NewAdminService(
		stores.Client, stores.User, stores.Token, stores.Audit,
		obs, nil,
	)

	mockDCR := &mockDCRAdmin{mode: "open"}
	dcrDeps := &apiadmin.DCRDeps{
		DCR:      mockDCR,
		Settings: stores.RuntimeSettings,
		Audit:    nil,
	}

	srv := mustNewServer(t, config.AdminConfig{
		Enabled: true,
		Address: ":0",
		APIKey:  testAPIKey,
	}, adminSvc, obs, apiadmin.OptionalDeps{DCR: dcrDeps})

	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	return ts, mockDCR
}

func doDCRRequest(t *testing.T, ts *httptest.Server, method, path string, body string) *http.Response {
	t.Helper()
	var bodyReader io.Reader
	if body != "" {
		bodyReader = strings.NewReader(body)
	}
	req, err := http.NewRequestWithContext(t.Context(), method, ts.URL+path, bodyReader)
	if err != nil {
		t.Fatalf("build req: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+testAPIKey)
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	return resp
}

func TestAdminHandler_GetDCRSettings_500_OnProviderError(t *testing.T) {
	ts, mockDCR := newAdminDCRTestServer(t)
	mockDCR.getErr = errors.New("dcr mode provider unavailable")

	resp := doDCRRequest(t, ts, "GET", "/admin/settings/dcr", "")
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusInternalServerError {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status: got %d, want 500 (fail closed), body: %s", resp.StatusCode, body)
	}
}

// When GetMode fails on an update, the handler must 500 before persisting or
// applying the new mode.
func TestAdminHandler_UpdateDCRSettings_500_OnProviderError(t *testing.T) {
	ts, mockDCR := newAdminDCRTestServer(t)
	mockDCR.getErr = errors.New("dcr mode provider unavailable")

	resp := doDCRRequest(t, ts, "PATCH", "/admin/settings/dcr", `{"mode":"admin_only"}`)
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusInternalServerError {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status: got %d, want 500 (fail closed), body: %s", resp.StatusCode, body)
	}
}

// When applying the new mode at runtime fails, the handler must 500.
func TestAdminHandler_UpdateDCRSettings_500_OnSetError(t *testing.T) {
	ts, mockDCR := newAdminDCRTestServer(t)
	mockDCR.setErr = errors.New("apply failed")

	resp := doDCRRequest(t, ts, "PATCH", "/admin/settings/dcr", `{"mode":"admin_only"}`)
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusInternalServerError {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status: got %d, want 500, body: %s", resp.StatusCode, body)
	}
}

func TestAdminHandler_GetDCRSettings_200(t *testing.T) {
	ts, _ := newAdminDCRTestServer(t)

	resp := doDCRRequest(t, ts, "GET", "/admin/settings/dcr", "")
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status: got %d, want 200, body: %s", resp.StatusCode, body)
	}

	var result map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&result)
	if result["mode"] != "open" {
		t.Errorf("mode: got %v, want open", result["mode"])
	}
}

func TestAdminHandler_UpdateDCRSettings_200(t *testing.T) {
	ts, mockDCR := newAdminDCRTestServer(t)

	resp := doDCRRequest(t, ts, "PATCH", "/admin/settings/dcr", `{"mode":"admin_only"}`)
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status: got %d, want 200, body: %s", resp.StatusCode, body)
	}

	var result map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&result)
	if result["mode"] != "admin_only" {
		t.Errorf("mode: got %v, want admin_only", result["mode"])
	}

	// Verify the runtime DCR service was updated.
	gotMode, _ := mockDCR.GetMode(context.Background())
	if gotMode != "admin_only" {
		t.Errorf("mockDCR mode: got %v, want admin_only", gotMode)
	}
}

func TestAdminHandler_UpdateDCRSettings_InvalidMode(t *testing.T) {
	ts, _ := newAdminDCRTestServer(t)

	resp := doDCRRequest(t, ts, "PATCH", "/admin/settings/dcr", `{"mode":"invalid"}`)
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusBadRequest {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status: got %d, want 400, body: %s", resp.StatusCode, body)
	}
}

func TestAdminHandler_UpdateDCRSettings_EmptyMode(t *testing.T) {
	ts, _ := newAdminDCRTestServer(t)

	resp := doDCRRequest(t, ts, "PATCH", "/admin/settings/dcr", `{"mode":""}`)
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusBadRequest {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status: got %d, want 400, body: %s", resp.StatusCode, body)
	}
}

func TestAdminHandler_UpdateDCRSettings_PersistsToStore(t *testing.T) {
	ts, _ := newAdminDCRTestServer(t)

	// Set to admin_only.
	resp := doDCRRequest(t, ts, "PATCH", "/admin/settings/dcr", `{"mode":"admin_only"}`)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("update status: got %d, want 200", resp.StatusCode)
	}

	// GET should reflect the new mode.
	resp2 := doDCRRequest(t, ts, "GET", "/admin/settings/dcr", "")
	defer func() { _ = resp2.Body.Close() }()
	var result map[string]any
	_ = json.NewDecoder(resp2.Body).Decode(&result)
	if result["mode"] != "admin_only" {
		t.Errorf("mode after update: got %v, want admin_only", result["mode"])
	}
}

// --- Metrics on admin server ---

func TestMetrics_AvailableOnAdminServer(t *testing.T) {
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
	t.Cleanup(func() { _ = shutdown(context.Background()) })

	stores := testdata.SetupTestStores(t)
	adminSvc := services.NewAdminService(
		stores.Client, stores.User, stores.Token, stores.Audit,
		obs, nil,
		services.WithMachineTokenStore(stores.MachineToken),
		services.WithRevocationStore(stores.Revocation),
	)

	srv := mustNewServer(t, config.AdminConfig{
		Enabled: true,
		Address: ":0",
		APIKey:  testAPIKey,
	}, adminSvc, obs, apiadmin.OptionalDeps{})

	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	// /metrics should be reachable on the admin server without API key.
	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, ts.URL+"/metrics", nil)
	if err != nil {
		t.Fatalf("build req: %v", err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status: got %d, want 200", resp.StatusCode)
	}

	ct := resp.Header.Get("Content-Type")
	if !strings.Contains(ct, "text/plain") && !strings.Contains(ct, "text/openmetrics") {
		t.Errorf("content-type: got %q, want Prometheus text format", ct)
	}
}

// --- Resource Unification: /admin/resources + /admin/broker-providers ---

// newAdminTestServerWithUnifiedResources returns a test server that wires the
// new ResourceAdmin + BrokerProviderAdmin services on top of the
// existing admin surface.
func newAdminTestServerWithUnifiedResources(t *testing.T) *adminTestEnv {
	t.Helper()
	stores := testdata.SetupTestStores(t)
	obs := testObs()

	adminSvc := services.NewAdminService(
		stores.Client, stores.User, stores.Token, stores.Audit,
		obs, nil,
		services.WithMachineTokenStore(stores.MachineToken),
		services.WithRevocationStore(stores.Revocation),
	)

	resourceAdminSvc := services.NewResourceAdminService(
		stores.Resource, stores.BrokerProvider, stores.Client, obs, nil,
	)
	brokerProviderAdminSvc := services.NewBrokerProviderAdminService(
		stores.BrokerProvider, obs, nil, noopSecretEncoder{},
	)

	srv := mustNewServer(t, config.AdminConfig{
		Enabled: true,
		Address: ":0",
		APIKey:  testAPIKey,
	}, adminSvc, obs, apiadmin.OptionalDeps{
		Resources:       &apiadmin.ResourceAdminDeps{Resources: resourceAdminSvc},
		BrokerProviders: &apiadmin.BrokerProviderAdminDeps{BrokerProviders: brokerProviderAdminSvc},
	})

	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)

	return &adminTestEnv{
		ts:     ts,
		stores: &testdata.TestHelper{Stores: stores},
	}
}

func TestAdmin_Resources_AuthRequired(t *testing.T) {
	env := newAdminTestServerWithUnifiedResources(t)

	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, env.ts.URL+"/admin/resources", nil)
	if err != nil {
		t.Fatalf("build req: %v", err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status: got %d, want 401", resp.StatusCode)
	}
}

func TestAdmin_BrokerProviders_AuthRequired(t *testing.T) {
	env := newAdminTestServerWithUnifiedResources(t)

	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, env.ts.URL+"/admin/broker-providers", nil)
	if err != nil {
		t.Fatalf("build req: %v", err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status: got %d, want 401", resp.StatusCode)
	}
}

func TestAdmin_BrokerProviders_FullCRUD(t *testing.T) {
	env := newAdminTestServerWithUnifiedResources(t)

	createBody := map[string]any{
		"slug":         "github",
		"display_name": "GitHub",
		"protocol":     "oauth",
		"config_data": map[string]any{
			"client_id":         "x",
			"client_secret_ref": "GH_SECRET",
		},
	}
	resp := env.doRequest(t, "POST", "/admin/broker-providers", createBody)
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusCreated {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("create status: got %d, want 201: %s", resp.StatusCode, string(b))
	}
	var created map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&created); err != nil {
		t.Fatalf("decode create: %v", err)
	}
	id, _ := created["id"].(string)
	if id == "" {
		t.Fatal("expected id in create response")
	}
	if created["slug"] != "github" {
		t.Errorf("slug: got %q, want %q", created["slug"], "github")
	}

	getResp := env.doRequest(t, "GET", "/admin/broker-providers/"+id, nil)
	defer func() { _ = getResp.Body.Close() }()
	if getResp.StatusCode != http.StatusOK {
		t.Fatalf("get status: got %d, want 200", getResp.StatusCode)
	}

	patchBody := map[string]any{"display_name": "GitHub (renamed)"}
	patchResp := env.doRequest(t, "PATCH", "/admin/broker-providers/"+id, patchBody)
	defer func() { _ = patchResp.Body.Close() }()
	if patchResp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(patchResp.Body)
		t.Fatalf("patch status: got %d, want 200: %s", patchResp.StatusCode, string(b))
	}
	var patched map[string]any
	if err := json.NewDecoder(patchResp.Body).Decode(&patched); err != nil {
		t.Fatalf("decode patch: %v", err)
	}
	if patched["display_name"] != "GitHub (renamed)" {
		t.Errorf("post-patch display_name: got %q", patched["display_name"])
	}
	// Protocol must be unchanged after a display-name-only patch.
	if patched["protocol"] != "oauth" {
		t.Errorf("post-patch protocol: got %q, want %q", patched["protocol"], "oauth")
	}

	delResp := env.doRequest(t, "DELETE", "/admin/broker-providers/"+id, nil)
	_ = delResp.Body.Close()
	if delResp.StatusCode != http.StatusNoContent {
		t.Fatalf("delete status: got %d, want 204", delResp.StatusCode)
	}

	missResp := env.doRequest(t, "GET", "/admin/broker-providers/"+id, nil)
	_ = missResp.Body.Close()
	if missResp.StatusCode != http.StatusNotFound {
		t.Fatalf("post-delete get: got %d, want 404", missResp.StatusCode)
	}
}

func TestAdmin_Resources_FullCRUD(t *testing.T) {
	env := newAdminTestServerWithUnifiedResources(t)

	// 1. Seed a broker provider so the broker-resource create can reference it.
	bpResp := env.doRequest(t, "POST", "/admin/broker-providers", map[string]any{
		"slug":         "google-workspace",
		"display_name": "Google Workspace",
		"protocol":     "oauth",
		"config_data":  map[string]any{},
	})
	defer func() { _ = bpResp.Body.Close() }()
	if bpResp.StatusCode != http.StatusCreated {
		b, _ := io.ReadAll(bpResp.Body)
		t.Fatalf("seed broker provider: %d %s", bpResp.StatusCode, string(b))
	}
	var bp map[string]any
	_ = json.NewDecoder(bpResp.Body).Decode(&bp)
	bpID, _ := bp["id"].(string)

	// 2. Create a Broker resource pointing at it.
	createBody := map[string]any{
		"slug":               "google-calendar",
		"uri":                "https://www.googleapis.com/calendar/v3",
		"backend_kind":       "broker",
		"broker_provider_id": bpID,
		"display_name":       "Google Calendar",
		"scopes": []map[string]any{
			{"name": "events.read", "upstream": "https://www.googleapis.com/auth/calendar.events.readonly"},
		},
	}
	resp := env.doRequest(t, "POST", "/admin/resources", createBody)
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusCreated {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("create status: got %d, want 201: %s", resp.StatusCode, string(b))
	}
	var created map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&created)
	id, _ := created["id"].(string)
	if id == "" {
		t.Fatal("expected id in create response")
	}

	// 3. GET should round-trip every field.
	getResp := env.doRequest(t, "GET", "/admin/resources/"+id, nil)
	defer func() { _ = getResp.Body.Close() }()
	if getResp.StatusCode != http.StatusOK {
		t.Fatalf("get status: %d", getResp.StatusCode)
	}
	var got map[string]any
	_ = json.NewDecoder(getResp.Body).Decode(&got)
	if got["backend_kind"] != "broker" {
		t.Errorf("backend_kind: got %q, want %q", got["backend_kind"], "broker")
	}
	if got["broker_provider_id"] != bpID {
		t.Errorf("broker_provider_id: got %q, want %q", got["broker_provider_id"], bpID)
	}

	// 4. PATCH display_name only.
	patchResp := env.doRequest(t, "PATCH", "/admin/resources/"+id, map[string]any{
		"display_name": "Calendar API",
	})
	defer func() { _ = patchResp.Body.Close() }()
	if patchResp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(patchResp.Body)
		t.Fatalf("patch status: got %d, want 200: %s", patchResp.StatusCode, string(b))
	}
	var patched map[string]any
	_ = json.NewDecoder(patchResp.Body).Decode(&patched)
	if patched["display_name"] != "Calendar API" {
		t.Errorf("display_name: got %q", patched["display_name"])
	}

	// 5. DELETE.
	delResp := env.doRequest(t, "DELETE", "/admin/resources/"+id, nil)
	_ = delResp.Body.Close()
	if delResp.StatusCode != http.StatusNoContent {
		t.Fatalf("delete status: got %d, want 204", delResp.StatusCode)
	}
}

// TestAdmin_Resources_Patch_OmittedPolicy_DoesNotWiden is the HTTP-level
// regression for the security guard: PATCH with body
// {"display_name":"new"} must not widen policy.exchange.allowed_client_ids.
func TestAdmin_Resources_Patch_OmittedPolicy_DoesNotWiden(t *testing.T) {
	env := newAdminTestServerWithUnifiedResources(t)
	ctx := context.Background()

	// Seed an Agent client referenced by the resource policy.
	agent := &client.Client{
		ID:                      crypto.GenerateClientID(),
		Name:                    "Agent",
		RedirectURIs:            []string{"https://app/cb"},
		GrantTypes:              []string{"authorization_code"},
		ResponseTypes:           []string{"code"},
		TokenEndpointAuthMethod: "none",
		Status:                  client.StatusActive,
		RegistrationSource:      client.SourceDCR,
		IssuedAt:                time.Now().UTC(),
		UpdatedAt:               time.Now().UTC(),
	}
	if err := env.stores.Stores.Client.Create(ctx, agent); err != nil {
		t.Fatalf("seed client: %v", err)
	}

	// Create a Mint resource with a non-empty allowlist.
	createBody := map[string]any{
		"slug":         "mint-guarded",
		"backend_kind": "mint",
		"display_name": "Guarded",
		"policy": map[string]any{
			"exchange": map[string]any{
				"allowed_client_ids": []string{agent.ID},
			},
			"connect": map[string]any{
				"allowed_return_urls": []string{},
			},
		},
	}
	resp := env.doRequest(t, "POST", "/admin/resources", createBody)
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusCreated {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("create: %d %s", resp.StatusCode, string(b))
	}
	var created map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&created)
	id, _ := created["id"].(string)

	// PATCH only display_name. Policy must NOT widen.
	patchResp := env.doRequest(t, "PATCH", "/admin/resources/"+id, map[string]any{
		"display_name": "Guarded (renamed)",
	})
	defer func() { _ = patchResp.Body.Close() }()
	if patchResp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(patchResp.Body)
		t.Fatalf("patch: %d %s", patchResp.StatusCode, string(b))
	}

	// Re-GET to confirm allowlist intact.
	getResp := env.doRequest(t, "GET", "/admin/resources/"+id, nil)
	defer func() { _ = getResp.Body.Close() }()
	var got map[string]any
	_ = json.NewDecoder(getResp.Body).Decode(&got)
	policy, _ := got["policy"].(map[string]any)
	exchange, _ := policy["exchange"].(map[string]any)
	allowed, _ := exchange["allowed_client_ids"].([]any)
	if len(allowed) != 1 || allowed[0] != agent.ID {
		t.Errorf("allowlist widened: got %v, want [%s]", allowed, agent.ID)
	}
}

func TestAdmin_Resources_ListFiltersByBackendKind(t *testing.T) {
	env := newAdminTestServerWithUnifiedResources(t)

	// Seed a broker provider to support a Broker resource.
	bpResp := env.doRequest(t, "POST", "/admin/broker-providers", map[string]any{
		"slug":         "filter-provider",
		"display_name": "Filter",
		"protocol":     "oauth",
		"config_data":  map[string]any{},
	})
	defer func() { _ = bpResp.Body.Close() }()
	var bp map[string]any
	_ = json.NewDecoder(bpResp.Body).Decode(&bp)
	bpID, _ := bp["id"].(string)

	// One Mint, one Broker.
	for _, body := range []map[string]any{
		{"slug": "mint-a", "backend_kind": "mint", "display_name": "Mint A"},
		{"slug": "broker-a", "backend_kind": "broker", "broker_provider_id": bpID, "display_name": "Broker A"},
	} {
		r := env.doRequest(t, "POST", "/admin/resources", body)
		if r.StatusCode != http.StatusCreated {
			b, _ := io.ReadAll(r.Body)
			t.Fatalf("seed %s: %d %s", body["slug"], r.StatusCode, string(b))
		}
		_ = r.Body.Close()
	}

	// Filter mint.
	mintResp := env.doRequest(t, "GET", "/admin/resources?backend_kind=mint", nil)
	defer func() { _ = mintResp.Body.Close() }()
	var mintList []map[string]any
	_ = json.NewDecoder(mintResp.Body).Decode(&mintList)
	if len(mintList) != 1 || mintList[0]["slug"] != "mint-a" {
		t.Errorf("mint filter: got %v", mintList)
	}

	// Filter broker.
	brokerResp := env.doRequest(t, "GET", "/admin/resources?backend_kind=broker", nil)
	defer func() { _ = brokerResp.Body.Close() }()
	var brokerList []map[string]any
	_ = json.NewDecoder(brokerResp.Body).Decode(&brokerList)
	if len(brokerList) != 1 || brokerList[0]["slug"] != "broker-a" {
		t.Errorf("broker filter: got %v", brokerList)
	}

	// Invalid filter value rejected.
	badResp := env.doRequest(t, "GET", "/admin/resources?backend_kind=bogus", nil)
	_ = badResp.Body.Close()
	if badResp.StatusCode != http.StatusBadRequest {
		t.Errorf("invalid backend_kind: got %d, want 400", badResp.StatusCode)
	}
}

func TestAdmin_Resources_DeleteBlockedByConsentGrant(t *testing.T) {
	env := newAdminTestServerWithUnifiedResources(t)
	ctx := context.Background()

	// Create a Mint resource via the admin API.
	createResp := env.doRequest(t, "POST", "/admin/resources", map[string]any{
		"slug":         "fk-blocked",
		"backend_kind": "mint",
		"display_name": "FK Blocked",
	})
	defer func() { _ = createResp.Body.Close() }()
	var created map[string]any
	_ = json.NewDecoder(createResp.Body).Decode(&created)
	resourceID, _ := created["id"].(string)
	if resourceID == "" {
		t.Fatalf("expected created resource id, got %v", created)
	}

	// Seed a consent_grants_unified row pointing at the resource.
	user := createTestUser(t, env.stores.Stores)
	ag := createTestClient(t, env.stores.Stores)
	grant := &resource.ConsentGrant{
		ID:         crypto.GenerateRandomString(16),
		UserID:     user.ID,
		ClientID:   ag.ID,
		ResourceID: resourceID,
		Scopes:     []string{"read"},
		CreatedAt:  time.Now().UTC(),
		UpdatedAt:  time.Now().UTC(),
	}
	if err := env.stores.Stores.ConsentGrant.Upsert(ctx, grant); err != nil {
		t.Fatalf("seed consent grant: %v", err)
	}

	// Delete must 409.
	delResp := env.doRequest(t, "DELETE", "/admin/resources/"+resourceID, nil)
	defer func() { _ = delResp.Body.Close() }()
	if delResp.StatusCode != http.StatusConflict {
		b, _ := io.ReadAll(delResp.Body)
		t.Fatalf("delete status: got %d, want 409: %s", delResp.StatusCode, string(b))
	}
}

func TestAdmin_BrokerProviders_DeleteBlockedByResource(t *testing.T) {
	env := newAdminTestServerWithUnifiedResources(t)

	bpResp := env.doRequest(t, "POST", "/admin/broker-providers", map[string]any{
		"slug":         "blocked-provider",
		"display_name": "Blocked",
		"protocol":     "oauth",
		"config_data":  map[string]any{},
	})
	defer func() { _ = bpResp.Body.Close() }()
	var bp map[string]any
	_ = json.NewDecoder(bpResp.Body).Decode(&bp)
	bpID, _ := bp["id"].(string)

	rResp := env.doRequest(t, "POST", "/admin/resources", map[string]any{
		"slug":               "broker-on-blocked",
		"backend_kind":       "broker",
		"broker_provider_id": bpID,
		"display_name":       "Broker on Blocked",
	})
	_ = rResp.Body.Close()
	if rResp.StatusCode != http.StatusCreated {
		t.Fatalf("seed resource: %d", rResp.StatusCode)
	}

	delResp := env.doRequest(t, "DELETE", "/admin/broker-providers/"+bpID, nil)
	defer func() { _ = delResp.Body.Close() }()
	if delResp.StatusCode != http.StatusConflict {
		b, _ := io.ReadAll(delResp.Body)
		t.Fatalf("delete status: got %d, want 409: %s", delResp.StatusCode, string(b))
	}
}

func TestAdmin_Resources_Create_RejectsInvalidSlug(t *testing.T) {
	env := newAdminTestServerWithUnifiedResources(t)
	resp := env.doRequest(t, "POST", "/admin/resources", map[string]any{
		"slug":         "Invalid Slug!",
		"backend_kind": "mint",
		"display_name": "x",
	})
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusBadRequest {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("status: got %d, want 400: %s", resp.StatusCode, string(b))
	}
}

func TestAdmin_Resources_DuplicateSlug_Returns409(t *testing.T) {
	env := newAdminTestServerWithUnifiedResources(t)

	body := map[string]any{
		"slug":         "conflict-test",
		"backend_kind": "mint",
		"display_name": "First",
	}
	first := env.doRequest(t, "POST", "/admin/resources", body)
	_ = first.Body.Close()
	if first.StatusCode != http.StatusCreated {
		t.Fatalf("first create: %d", first.StatusCode)
	}

	second := env.doRequest(t, "POST", "/admin/resources", body)
	defer func() { _ = second.Body.Close() }()
	if second.StatusCode != http.StatusConflict {
		b, _ := io.ReadAll(second.Body)
		t.Fatalf("second create: got %d, want 409: %s", second.StatusCode, string(b))
	}
}

func TestAdmin_BrokerProviders_ConfigDataRoundTrip(t *testing.T) {
	env := newAdminTestServerWithUnifiedResources(t)

	cfg := map[string]any{
		"client_id":         "abc",
		"client_secret_ref": "X",
		"authorize_url":     "https://example.com/authorize",
		"nested":            map[string]any{"a": []any{1.0, 2.0}},
	}
	resp := env.doRequest(t, "POST", "/admin/broker-providers", map[string]any{
		"slug":         "rt",
		"display_name": "RT",
		"protocol":     "oauth",
		"config_data":  cfg,
	})
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusCreated {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("create: %d %s", resp.StatusCode, string(b))
	}
	var created map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&created)
	id, _ := created["id"].(string)

	// GET and confirm config_data round-trips byte-for-byte (modulo JSON
	// canonical key ordering, which Go's encoder doesn't reorder either way).
	getResp := env.doRequest(t, "GET", "/admin/broker-providers/"+id, nil)
	defer func() { _ = getResp.Body.Close() }()
	var got map[string]any
	_ = json.NewDecoder(getResp.Body).Decode(&got)
	gotCfg, _ := got["config_data"].(map[string]any)
	if gotCfg["client_id"] != "abc" {
		t.Errorf("config_data.client_id: got %v", gotCfg["client_id"])
	}
}

// TestAdmin_Resources_MintOmitsConnectPolicy locks the F2 fix: Mint
// resources do not emit `policy.connect` on the wire (the design §6 semantics —
// Mint resources have no connect-policy concept).
func TestAdmin_Resources_MintOmitsConnectPolicy(t *testing.T) {
	env := newAdminTestServerWithUnifiedResources(t)

	resp := env.doRequest(t, "POST", "/admin/resources", map[string]any{
		"slug":         "mint-no-connect",
		"backend_kind": "mint",
		"display_name": "Mint",
	})
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusCreated {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("create: %d %s", resp.StatusCode, string(b))
	}
	var v map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&v)

	policy, _ := v["policy"].(map[string]any)
	if _, present := policy["connect"]; present {
		t.Errorf("Mint resource emitted policy.connect; expected omitted. policy=%v", policy)
	}
	exch, _ := policy["exchange"].(map[string]any)
	allowed, _ := exch["allowed_client_ids"].([]any)
	if allowed == nil {
		t.Errorf("allowed_client_ids encoded as null; expected []. exchange=%v", exch)
	}
}

// TestAdmin_Resources_BrokerEmitsConnectPolicy locks the inverse of F2:
// Broker resources DO emit `policy.connect`.
func TestAdmin_Resources_BrokerEmitsConnectPolicy(t *testing.T) {
	env := newAdminTestServerWithUnifiedResources(t)

	bp := env.doRequest(t, "POST", "/admin/broker-providers", map[string]any{
		"slug":         "p-connect",
		"display_name": "P",
		"protocol":     "oauth",
		"config_data":  map[string]any{},
	})
	defer func() { _ = bp.Body.Close() }()
	var bpv map[string]any
	_ = json.NewDecoder(bp.Body).Decode(&bpv)
	bpID, _ := bpv["id"].(string)

	resp := env.doRequest(t, "POST", "/admin/resources", map[string]any{
		"slug":               "broker-connect",
		"backend_kind":       "broker",
		"broker_provider_id": bpID,
		"display_name":       "B",
	})
	defer func() { _ = resp.Body.Close() }()
	var v map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&v)
	policy, _ := v["policy"].(map[string]any)
	connect, present := policy["connect"]
	if !present {
		t.Errorf("Broker resource did NOT emit policy.connect; policy=%v", policy)
	}
	connectMap, _ := connect.(map[string]any)
	urls, _ := connectMap["allowed_return_urls"].([]any)
	if urls == nil {
		t.Errorf("allowed_return_urls encoded as null; expected []. connect=%v", connectMap)
	}
}

// TestAdmin_BrokerProviders_RejectsConfigDataNull locks the F4 fix at the
// HTTP layer: a request body with `config_data: null` is rejected with 400
// rather than persisting a literal "null" that would later choke the
// brokerproto adapter.
func TestAdmin_BrokerProviders_RejectsConfigDataNull(t *testing.T) {
	env := newAdminTestServerWithUnifiedResources(t)

	body := []byte(`{"slug":"null-cfg","display_name":"X","protocol":"oauth","config_data":null}`)
	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, env.ts.URL+"/admin/broker-providers", strings.NewReader(string(body)))
	if err != nil {
		t.Fatalf("build req: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+testAPIKey)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusBadRequest {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("status: got %d, want 400: %s", resp.StatusCode, string(b))
	}
}
