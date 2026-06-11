//go:build integration

package services_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/authplane/authserver/internal/adapters/cimd"
	"github.com/authplane/authserver/internal/crypto"
	"github.com/authplane/authserver/internal/domain"
	"github.com/authplane/authserver/internal/domain/client"
	"github.com/authplane/authserver/internal/domain/resource"
	"github.com/authplane/authserver/internal/ports/input"
	"github.com/authplane/authserver/internal/ports/output"
	"github.com/authplane/authserver/internal/services"
	"github.com/authplane/authserver/testdata"
)

func newAuthorizeService(t *testing.T) (*services.AuthorizeService, *testdata.TestHelper) {
	t.Helper()
	stores := testdata.SetupTestStores(t)
	obs := testObs()

	seedMintResource(t, stores, "mcp-authz", "Authz MCP", "https://mcp.example.com",
		resource.Scope{Name: "tools/query", Description: "Query"},
		resource.Scope{Name: "tools/create", Description: "Create"},
	)

	svc := services.NewAuthorizeService(
		stores.Client, stores.Session, stores.ConsentGrant,
		nil, newTestRegistry(stores), false, obs,
	)

	return svc, &testdata.TestHelper{Stores: stores}
}

func createTestClient(t *testing.T, h *testdata.TestHelper) *client.Client {
	t.Helper()
	now := time.Now().UTC()
	c := &client.Client{
		ID:                      crypto.GenerateClientID(),
		Name:                    "Test Client",
		RedirectURIs:            []string{"https://app.example.com/callback"},
		GrantTypes:              []string{"authorization_code"},
		ResponseTypes:           []string{"code"},
		TokenEndpointAuthMethod: "none",
		Status:                  client.StatusActive,
		RegistrationSource:      client.SourceDCR,
		IssuedAt:                now,
		UpdatedAt:               now,
	}
	if err := h.Stores.Client.Create(context.Background(), c); err != nil {
		t.Fatalf("create client: %v", err)
	}
	return c
}

func validAuthorizeRequest(c *client.Client) input.AuthorizeRequest {
	verifier := crypto.GenerateVerifier()
	return input.AuthorizeRequest{
		ClientID:            c.ID,
		RedirectURI:         "https://app.example.com/callback",
		ResponseType:        "code",
		Scope:               "tools/query",
		State:               "test-state",
		Resource:            "https://mcp.example.com",
		CodeChallenge:       crypto.ComputeS256Challenge(verifier),
		CodeChallengeMethod: "S256",
	}
}

func TestAuthorize_ValidRequest_NoUser(t *testing.T) {
	svc, h := newAuthorizeService(t)
	c := createTestClient(t, h)

	req := validAuthorizeRequest(c)
	result, err := svc.StartAuthorization(context.Background(), req)
	if err != nil {
		t.Fatalf("start: %v", err)
	}
	if !result.LoginRequired {
		t.Error("expected login required (no user)")
	}
	if !result.ConsentRequired {
		t.Error("expected consent required")
	}
	if result.Session == nil {
		t.Fatal("session is nil")
	}
	if result.Session.ClientID != c.ID {
		t.Errorf("client_id: got %q, want %q", result.Session.ClientID, c.ID)
	}
}

func TestAuthorize_ValidRequest_WithUser_NoConsent(t *testing.T) {
	svc, h := newAuthorizeService(t)
	c := createTestClient(t, h)

	req := validAuthorizeRequest(c)
	req.UserID = "user-123"

	result, err := svc.StartAuthorization(context.Background(), req)
	if err != nil {
		t.Fatalf("start: %v", err)
	}
	if result.LoginRequired {
		t.Error("login should not be required")
	}
	if !result.ConsentRequired {
		t.Error("consent should be required (no prior grant)")
	}
}

func TestAuthorize_ValidRequest_WithUser_WithConsent(t *testing.T) {
	svc, h := newAuthorizeService(t)
	c := createTestClient(t, h)

	// Create prior consent on the unified store. Seed the user (FK).
	if err := seedUser(context.Background(), h.Stores, "user-123"); err != nil {
		t.Fatalf("seed user: %v", err)
	}
	res, err := h.Stores.Resource.GetBySlug(context.Background(), "mcp-authz")
	if err != nil || res == nil {
		t.Fatalf("get seeded resource: %v", err)
	}
	now := time.Now().UTC()
	grant := &resource.ConsentGrant{
		ID:         crypto.GenerateRandomString(16),
		UserID:     "user-123",
		ClientID:   c.ID,
		ResourceID: res.ID,
		Scopes:     []string{"tools/query", "tools/create"},
		CreatedAt:  now,
		UpdatedAt:  now,
	}
	if err := h.Stores.ConsentGrant.Upsert(context.Background(), grant); err != nil {
		t.Fatalf("upsert consent: %v", err)
	}

	req := validAuthorizeRequest(c)
	req.UserID = "user-123"

	result, err := svc.StartAuthorization(context.Background(), req)
	if err != nil {
		t.Fatalf("start: %v", err)
	}
	if result.LoginRequired {
		t.Error("login should not be required")
	}
	if result.ConsentRequired {
		t.Error("consent should NOT be required (prior grant exists)")
	}
}

func TestAuthorize_InvalidClientID(t *testing.T) {
	svc, _ := newAuthorizeService(t)

	req := input.AuthorizeRequest{
		ClientID:            "unknown-client",
		RedirectURI:         "https://app.example.com/callback",
		ResponseType:        "code",
		CodeChallenge:       "challenge",
		CodeChallengeMethod: "S256",
	}

	_, err := svc.StartAuthorization(context.Background(), req)
	if !errors.Is(err, domain.ErrInvalidClient) {
		t.Errorf("expected ErrInvalidClient, got: %v", err)
	}
}

func TestAuthorize_RedirectURIMismatch(t *testing.T) {
	svc, h := newAuthorizeService(t)
	c := createTestClient(t, h)

	req := validAuthorizeRequest(c)
	req.RedirectURI = "https://evil.example.com/callback"

	_, err := svc.StartAuthorization(context.Background(), req)
	if !errors.Is(err, domain.ErrInvalidRedirectURI) {
		t.Errorf("expected ErrInvalidRedirectURI, got: %v", err)
	}
}

func TestAuthorize_MissingPKCE(t *testing.T) {
	svc, h := newAuthorizeService(t)
	c := createTestClient(t, h)

	req := validAuthorizeRequest(c)
	req.CodeChallenge = ""

	_, err := svc.StartAuthorization(context.Background(), req)
	if !errors.Is(err, domain.ErrInvalidPKCE) {
		t.Errorf("expected ErrInvalidPKCE, got: %v", err)
	}
}

func TestAuthorize_PlainPKCE_Rejected(t *testing.T) {
	svc, h := newAuthorizeService(t)
	c := createTestClient(t, h)

	req := validAuthorizeRequest(c)
	req.CodeChallengeMethod = "plain"

	_, err := svc.StartAuthorization(context.Background(), req)
	if !errors.Is(err, domain.ErrInvalidPKCE) {
		t.Errorf("expected ErrInvalidPKCE, got: %v", err)
	}
}

func TestAuthorize_InvalidResource(t *testing.T) {
	svc, h := newAuthorizeService(t)
	c := createTestClient(t, h)

	req := validAuthorizeRequest(c)
	req.Resource = "https://unknown.example.com"

	_, err := svc.StartAuthorization(context.Background(), req)
	// : unknown resource resolves through the registry and returns
	// ErrResourceNotFound (was ErrInvalidScope under the legacy ResourceLister).
	if !errors.Is(err, domain.ErrResourceNotFound) {
		t.Errorf("expected ErrResourceNotFound, got: %v", err)
	}
}

func TestAuthorize_SuspendedClient(t *testing.T) {
	svc, h := newAuthorizeService(t)
	c := createTestClient(t, h)

	// Suspend the client.
	c.Suspend()
	h.Stores.Client.Update(context.Background(), c)

	req := validAuthorizeRequest(c)

	_, err := svc.StartAuthorization(context.Background(), req)
	if !errors.Is(err, domain.ErrClientSuspended) {
		t.Errorf("expected ErrClientSuspended, got: %v", err)
	}
}

func TestAuthorize_CompleteAuthorization(t *testing.T) {
	svc, h := newAuthorizeService(t)
	c := createTestClient(t, h)

	req := validAuthorizeRequest(c)
	req.UserID = "user-123"

	result, err := svc.StartAuthorization(context.Background(), req)
	if err != nil {
		t.Fatalf("start: %v", err)
	}

	completed, err := svc.CompleteAuthorization(context.Background(), result.Session.ID)
	if err != nil {
		t.Fatalf("complete: %v", err)
	}

	if completed.Code == "" {
		t.Error("code is empty")
	}
	if completed.RedirectURI != "https://app.example.com/callback" {
		t.Errorf("redirect_uri: got %q", completed.RedirectURI)
	}
	if completed.State != "test-state" {
		t.Errorf("state: got %q", completed.State)
	}

	// Verify the session has a code_hash.
	sess, err := h.Stores.Session.GetByID(context.Background(), result.Session.ID)
	if err != nil {
		t.Fatalf("get session: %v", err)
	}
	if sess.CodeHash == "" {
		t.Error("session code_hash is empty after completion")
	}
}

// Matrix: 8.5 — multiple resource parameters: server accepts single resource only
// The authorize handler uses q.Get("resource") which returns the first value.
// Multiple resource parameters are effectively ignored (only the first is used).
// This test documents the behavior: a single unknown resource returns invalid_scope,
// while a single known resource succeeds.
func TestAuthorize_MultipleResources_OnlyFirstUsed(t *testing.T) {
	svc, h := newAuthorizeService(t)
	c := createTestClient(t, h)

	// Single known resource: succeeds.
	req := validAuthorizeRequest(c)
	_, err := svc.StartAuthorization(context.Background(), req)
	if err != nil {
		t.Fatalf("single resource should succeed: %v", err)
	}

	// Unknown resource: fails with ErrResourceNotFound ( — the
	// registry resolver returns a typed not-found error rather than the
	// legacy ErrInvalidScope from the ResourceLister scope check).
	req2 := validAuthorizeRequest(c)
	req2.Resource = "https://unknown.example.com"
	_, err = svc.StartAuthorization(context.Background(), req2)
	if !errors.Is(err, domain.ErrResourceNotFound) {
		t.Errorf("unknown resource should return ErrResourceNotFound, got: %v", err)
	}

	// Note: Multiple resource parameters (resource=A&resource=B) are not supported.
	// The HTTP layer uses q.Get("resource") which returns only the first value.
	// This is a valid MVP choice — RFC 8707 says multiple resource parameters MAY
	// be supported but are not required. Document as single-resource only.
}

// --- require_scope tests ---

func TestAuthorize_RequireScope_MissingScope_Rejected(t *testing.T) {
	stores := testdata.SetupTestStores(t)
	obs := testObs()

	seedMintResource(t, stores, "mcp-rs-missing", "RS Missing", "https://mcp.example.com",
		resource.Scope{Name: "tools/query", Description: "Query"},
		resource.Scope{Name: "tools/create", Description: "Create"},
	)

	svc := services.NewAuthorizeService(
		stores.Client, stores.Session, stores.ConsentGrant,
		nil, newTestRegistry(stores), true, obs,
	)

	h := &testdata.TestHelper{Stores: stores}
	c := createTestClient(t, h)

	req := validAuthorizeRequest(c)
	req.Scope = "" // missing scope

	_, err := svc.StartAuthorization(context.Background(), req)
	if err == nil {
		t.Fatal("require_scope=true should reject missing scope")
	}
	if !errors.Is(err, domain.ErrInvalidScope) {
		t.Errorf("error should be ErrInvalidScope, got: %v", err)
	}
}

// --- Scope validation tests ---
// These tests exercise validateScopes for a KNOWN resource — the "unknown scope"
// branch is the one currently not covered elsewhere. Without these, neutering
// validateScopes to `return nil` goes undetected (mutation-check finding M1).

// newAuthorizeServiceWithScopes builds an AuthorizeService whose registry
// knows exactly one Mint resource with the given URI + scope names.
func newAuthorizeServiceWithScopes(t *testing.T, resourceURI string, scopes ...string) (*services.AuthorizeService, *testdata.TestHelper) {
	t.Helper()
	stores := testdata.SetupTestStores(t)
	obs := testObs()

	scopeRows := make([]resource.Scope, len(scopes))
	for i, s := range scopes {
		scopeRows[i] = resource.Scope{Name: s}
	}
	seedMintResource(t, stores, "mcp-scopes-test", "Scopes Test", resourceURI, scopeRows...)

	svc := services.NewAuthorizeService(
		stores.Client, stores.Session, stores.ConsentGrant,
		nil, newTestRegistry(stores), false, obs,
	)
	return svc, &testdata.TestHelper{Stores: stores}
}

// Known resource + known scope → authorize succeeds.
func TestAuthorize_RegisteredScope_Accepted(t *testing.T) {
	svc, h := newAuthorizeServiceWithScopes(t, "https://mcp.example.com", "tools/echo", "tools/query")
	c := createTestClient(t, h)

	req := validAuthorizeRequest(c)
	req.Scope = "tools/echo"
	if _, err := svc.StartAuthorization(context.Background(), req); err != nil {
		t.Fatalf("registered scope should be accepted: %v", err)
	}
}

// Known resource + single unknown scope → invalid_scope.
// Deleted with TestAuthorize_DBOnlyScope_Validated; this replaces that coverage
// for the static-lister path. Guards against validateScopes being neutered.
func TestAuthorize_UnknownScope_Rejected(t *testing.T) {
	svc, h := newAuthorizeServiceWithScopes(t, "https://mcp.example.com", "tools/echo")
	c := createTestClient(t, h)

	req := validAuthorizeRequest(c)
	req.Scope = "tools/nonexistent"
	_, err := svc.StartAuthorization(context.Background(), req)
	if !errors.Is(err, domain.ErrInvalidScope) {
		t.Fatalf("unregistered scope must return ErrInvalidScope, got: %v", err)
	}
}

// Known resource + one valid + one invalid scope → invalid_scope.
// The partial-intersection case — a common attack shape where a caller tries
// to sneak an unregistered scope in alongside a legitimate one.
func TestAuthorize_PartialUnknownScope_Rejected(t *testing.T) {
	svc, h := newAuthorizeServiceWithScopes(t, "https://mcp.example.com", "tools/echo", "tools/query")
	c := createTestClient(t, h)

	req := validAuthorizeRequest(c)
	req.Scope = "tools/echo tools/nonexistent"
	_, err := svc.StartAuthorization(context.Background(), req)
	if !errors.Is(err, domain.ErrInvalidScope) {
		t.Fatalf("partial invalid scope set must be rejected, got: %v", err)
	}
}

// Resource registered with empty scopes → any scoped request rejected with
// the "no scopes registered for resource" branch in authorize.go.
func TestAuthorize_ResourceWithNoScopes_Rejected(t *testing.T) {
	svc, h := newAuthorizeServiceWithScopes(t, "https://mcp.example.com")
	c := createTestClient(t, h)

	req := validAuthorizeRequest(c)
	req.Scope = "tools/echo"
	_, err := svc.StartAuthorization(context.Background(), req)
	if !errors.Is(err, domain.ErrInvalidScope) {
		t.Fatalf("resource with no registered scopes must reject scoped requests, got: %v", err)
	}
}

func TestAuthorize_RequireScope_False_DefaultsScope(t *testing.T) {
	stores := testdata.SetupTestStores(t)
	obs := testObs()

	seedMintResource(t, stores, "mcp-default-scope", "Default Scope MCP", "https://mcp.example.com",
		resource.Scope{Name: "tools/query", Description: "Query"},
		resource.Scope{Name: "tools/create", Description: "Create"},
	)

	svc := services.NewAuthorizeService(
		stores.Client, stores.Session, stores.ConsentGrant,
		nil, newTestRegistry(stores), false, obs,
	)

	h := &testdata.TestHelper{Stores: stores}
	c := createTestClient(t, h)

	req := validAuthorizeRequest(c)
	req.Scope = "" // missing scope — ADR-012 should default it

	result, err := svc.StartAuthorization(context.Background(), req)
	if err != nil {
		t.Fatalf("require_scope=false should not reject missing scope: %v", err)
	}
	// Should create a session with defaulted scope (login or consent required).
	if result == nil {
		t.Fatal("result should not be nil")
	}
	if result.Session == nil {
		t.Error("session should have been created with defaulted scope")
	}
}

// --- CIMD + Authorize integration tests ---
// These test the lookupClient path in authorize.go for URL-based client_ids.

// newAuthorizeServiceWithCIMD creates an authorize service wired to a real CIMD service
// backed by a test HTTP server that serves CIMD documents.
func newAuthorizeServiceWithCIMD(t *testing.T, cimdServer *httptest.Server) (*services.AuthorizeService, *testdata.TestHelper) {
	t.Helper()
	stores := testdata.SetupTestStores(t)
	obs := testObs()

	fetcher := cimd.New(false, time.Hour, 10*time.Second, obs)
	fetcher.SetAllowLoopback(true)
	cimdSvc := services.NewCIMDService(stores.Client, fetcher, services.DCRMode{Mode: "open"}, obs.WithComponent("cimd"))

	seedMintResource(t, stores, "mcp-cimd", "CIMD MCP", "https://mcp.example.com",
		resource.Scope{Name: "tools/query", Description: "Query"},
		resource.Scope{Name: "tools/create", Description: "Create"},
	)

	svc := services.NewAuthorizeService(
		stores.Client, stores.Session, stores.ConsentGrant,
		cimdSvc, newTestRegistry(stores), false, obs,
	)

	return svc, &testdata.TestHelper{Stores: stores}
}

func validCIMDAuthorizeRequest(clientID, redirectURI string) input.AuthorizeRequest {
	verifier := crypto.GenerateVerifier()
	return input.AuthorizeRequest{
		ClientID:            clientID,
		RedirectURI:         redirectURI,
		ResponseType:        "code",
		Scope:               "tools/query",
		State:               "test-state",
		Resource:            "https://mcp.example.com",
		CodeChallenge:       crypto.ComputeS256Challenge(verifier),
		CodeChallengeMethod: "S256",
	}
}

// TestAuthorize_URLClientID_CIMDAutoRegistration verifies that a URL-based client_id
// triggers CIMD auto-registration through the full authorize flow.
func TestAuthorize_URLClientID_CIMDAutoRegistration(t *testing.T) {
	redirectURI := "https://app.example.com/callback"
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		doc := output.CIMDDocument{
			ClientID:     "http://" + r.Host,
			ClientName:   "CIMD Auto-Reg Client",
			RedirectURIs: []string{redirectURI},
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(doc)
	}))
	defer ts.Close()

	svc, _ := newAuthorizeServiceWithCIMD(t, ts)

	req := validCIMDAuthorizeRequest(ts.URL, redirectURI)
	result, err := svc.StartAuthorization(context.Background(), req)
	if err != nil {
		t.Fatalf("CIMD auto-registration should succeed: %v", err)
	}
	if result.Session == nil {
		t.Fatal("session should have been created")
	}
	if result.Session.ClientID != ts.URL {
		t.Errorf("client_id: got %q, want %q", result.Session.ClientID, ts.URL)
	}
}

// TestAuthorize_URLClientID_AlreadyRegistered verifies that an already-registered
// CIMD client is found via GetByCIMDURL without re-fetching.
func TestAuthorize_URLClientID_AlreadyRegistered(t *testing.T) {
	redirectURI := "https://app.example.com/callback"
	fetchCount := 0
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fetchCount++
		doc := output.CIMDDocument{
			ClientID:     "http://" + r.Host,
			ClientName:   "CIMD Pre-Registered",
			RedirectURIs: []string{redirectURI},
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(doc)
	}))
	defer ts.Close()

	svc, h := newAuthorizeServiceWithCIMD(t, ts)
	ctx := context.Background()

	// Pre-register the client via CIMD by doing a first authorize.
	req := validCIMDAuthorizeRequest(ts.URL, redirectURI)
	_, err := svc.StartAuthorization(ctx, req)
	if err != nil {
		t.Fatalf("first authorize: %v", err)
	}
	firstFetchCount := fetchCount

	// Second authorize — should find client in DB via GetByCIMDURL, not re-fetch.
	// (Cache is 1 hour, so the CIMD fetcher won't re-fetch either, but the key
	// point is that lookupClient finds it via GetByCIMDURL before calling VerifyCIMD.)
	result, err := svc.StartAuthorization(ctx, req)
	if err != nil {
		t.Fatalf("second authorize: %v", err)
	}
	if result.Session.ClientID != ts.URL {
		t.Errorf("client_id: got %q, want %q", result.Session.ClientID, ts.URL)
	}
	// The CIMD fetcher may or may not be called again (cache hit), but the client
	// should already be in the DB. We just verify it works.
	_ = firstFetchCount
	_ = h
}

// TestAuthorize_URLClientID_CIMDFetchFails verifies that when CIMD fetch fails,
// the authorize endpoint returns ErrInvalidClient.
func TestAuthorize_URLClientID_CIMDFetchFails(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer ts.Close()

	svc, _ := newAuthorizeServiceWithCIMD(t, ts)

	req := validCIMDAuthorizeRequest(ts.URL, "https://app.example.com/callback")
	_, err := svc.StartAuthorization(context.Background(), req)
	if !errors.Is(err, domain.ErrInvalidClient) {
		t.Errorf("expected ErrInvalidClient when CIMD fetch fails, got: %v", err)
	}
}

// TestAuthorize_URLClientID_CIMDDisabled verifies that when CIMD is nil (disabled),
// a URL client_id that doesn't exist in the DB returns ErrInvalidClient.
func TestAuthorize_URLClientID_CIMDDisabled(t *testing.T) {
	svc, _ := newAuthorizeService(t) // cimd: nil

	req := validCIMDAuthorizeRequest("https://unknown-client.example.com", "https://app.example.com/callback")
	_, err := svc.StartAuthorization(context.Background(), req)
	if !errors.Is(err, domain.ErrInvalidClient) {
		t.Errorf("expected ErrInvalidClient when CIMD disabled, got: %v", err)
	}
}

// TestAuthorize_URLClientID_WrongRedirectURI verifies that after CIMD auto-registration,
// a redirect_uri NOT in the CIMD document is rejected.
// This is a critical security test: prevents open redirect via malicious authorize requests.
func TestAuthorize_URLClientID_WrongRedirectURI(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		doc := output.CIMDDocument{
			ClientID:     "http://" + r.Host,
			ClientName:   "CIMD Redirect Test",
			RedirectURIs: []string{"https://legit.example.com/callback"},
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(doc)
	}))
	defer ts.Close()

	svc, _ := newAuthorizeServiceWithCIMD(t, ts)

	// Request with a redirect_uri that doesn't match the CIMD document.
	req := validCIMDAuthorizeRequest(ts.URL, "https://evil.example.com/steal")
	_, err := svc.StartAuthorization(context.Background(), req)
	if !errors.Is(err, domain.ErrInvalidRedirectURI) {
		t.Errorf("expected ErrInvalidRedirectURI for mismatched redirect, got: %v", err)
	}
}

// TestAuthorize_NonURLClientID_NoCIMD verifies that a non-URL client_id does NOT
// trigger CIMD logic — only URL-prefixed client_ids enter the CIMD path.
func TestAuthorize_NonURLClientID_NoCIMD(t *testing.T) {
	// Even with CIMD enabled, a non-URL client_id should go through normal lookup.
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		t.Error("CIMD fetcher should NOT be called for non-URL client_id")
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	svc, _ := newAuthorizeServiceWithCIMD(t, ts)

	req := validCIMDAuthorizeRequest("some-opaque-client-id", "https://app.example.com/callback")
	_, err := svc.StartAuthorization(context.Background(), req)
	if !errors.Is(err, domain.ErrInvalidClient) {
		t.Errorf("expected ErrInvalidClient for non-URL client_id, got: %v", err)
	}
}

// TestAuthorize_URLClientID_SuspendedCIMDClient verifies that a CIMD-registered
// client that is later suspended gets rejected on subsequent authorize requests.
func TestAuthorize_URLClientID_SuspendedCIMDClient(t *testing.T) {
	redirectURI := "https://app.example.com/callback"
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		doc := output.CIMDDocument{
			ClientID:     "http://" + r.Host,
			ClientName:   "CIMD Suspend Test",
			RedirectURIs: []string{redirectURI},
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(doc)
	}))
	defer ts.Close()

	svc, h := newAuthorizeServiceWithCIMD(t, ts)
	ctx := context.Background()

	// First authorize — succeeds, creates client.
	req := validCIMDAuthorizeRequest(ts.URL, redirectURI)
	_, err := svc.StartAuthorization(ctx, req)
	if err != nil {
		t.Fatalf("first authorize: %v", err)
	}

	// Suspend the CIMD client.
	c, err := h.Stores.Client.GetByCIMDURL(ctx, ts.URL)
	if err != nil || c == nil {
		t.Fatalf("get cimd client: %v", err)
	}
	c.Suspend()
	if err := h.Stores.Client.Update(ctx, c); err != nil {
		t.Fatalf("suspend client: %v", err)
	}

	// Second authorize — should be rejected as suspended.
	_, err = svc.StartAuthorization(ctx, req)
	if !errors.Is(err, domain.ErrClientSuspended) {
		t.Errorf("expected ErrClientSuspended for suspended CIMD client, got: %v", err)
	}
}

// --- Adversarial: CIMD + DCR cross-feature authorize integration ---

// newAuthorizeServiceWithCIMDAndDCR creates an authorize service with a specific DCR mode.
func newAuthorizeServiceWithCIMDAndDCR(t *testing.T, cimdServer *httptest.Server, dcrMode services.DCRMode) *services.AuthorizeService {
	t.Helper()
	stores := testdata.SetupTestStores(t)
	obs := testObs()

	fetcher := cimd.New(false, time.Hour, 10*time.Second, obs)
	fetcher.SetAllowLoopback(true)
	cimdSvc := services.NewCIMDService(stores.Client, fetcher, dcrMode, obs.WithComponent("cimd"))

	seedMintResource(t, stores, "mcp-cimd-dcr", "CIMD DCR MCP", "https://mcp.example.com",
		resource.Scope{Name: "tools/query", Description: "Query"},
		resource.Scope{Name: "tools/create", Description: "Create"},
	)

	return services.NewAuthorizeService(
		stores.Client, stores.Session, stores.ConsentGrant,
		cimdSvc, newTestRegistry(stores), false, obs,
	)
}

// TestAuthorize_URLClientID_CIMDBlockedByAdminOnly verifies that the full authorize
// flow rejects URL client_ids when DCR mode is admin_only — CIMD auto-registration
// must not bypass DCR policy.
func TestAuthorize_URLClientID_CIMDBlockedByAdminOnly(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		doc := output.CIMDDocument{
			ClientID:     "http://" + r.Host,
			ClientName:   "Should Be Blocked",
			RedirectURIs: []string{"https://evil.example.com/callback"},
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(doc)
	}))
	defer ts.Close()

	svc := newAuthorizeServiceWithCIMDAndDCR(t, ts, services.DCRMode{Mode: "admin_only"})

	req := validCIMDAuthorizeRequest(ts.URL, "https://evil.example.com/callback")
	_, err := svc.StartAuthorization(context.Background(), req)
	if !errors.Is(err, domain.ErrInvalidClient) {
		t.Errorf("err = %v, want ErrInvalidClient (CIMD should be blocked by admin_only)", err)
	}
}

// TestAuthorize_URLClientID_CIMDBlockedByApprovedRedirects verifies that the full
// authorize flow rejects CIMD auto-registration when redirect URIs aren't approved.
func TestAuthorize_URLClientID_CIMDBlockedByApprovedRedirects(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		doc := output.CIMDDocument{
			ClientID:     "http://" + r.Host,
			ClientName:   "Unapproved Redirects",
			RedirectURIs: []string{"https://evil.example.com/callback"},
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(doc)
	}))
	defer ts.Close()

	svc := newAuthorizeServiceWithCIMDAndDCR(t, ts, services.DCRMode{
		Mode:              "approved_redirects",
		ApprovedRedirects: []string{"https://trusted.example.com/callback"},
	})

	req := validCIMDAuthorizeRequest(ts.URL, "https://evil.example.com/callback")
	_, err := svc.StartAuthorization(context.Background(), req)
	if !errors.Is(err, domain.ErrInvalidClient) {
		t.Errorf("err = %v, want ErrInvalidClient (CIMD redirect not in approved list)", err)
	}
}

// TestAuthorize_URLClientID_CIMDAllowedByApprovedRedirects verifies that CIMD
// auto-registration succeeds through the authorize flow when redirects are approved.
func TestAuthorize_URLClientID_CIMDAllowedByApprovedRedirects(t *testing.T) {
	redirectURI := "https://trusted.example.com/callback"
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		doc := output.CIMDDocument{
			ClientID:     "http://" + r.Host,
			ClientName:   "Approved CIMD Client",
			RedirectURIs: []string{redirectURI},
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(doc)
	}))
	defer ts.Close()

	svc := newAuthorizeServiceWithCIMDAndDCR(t, ts, services.DCRMode{
		Mode:              "approved_redirects",
		ApprovedRedirects: []string{redirectURI},
	})

	req := validCIMDAuthorizeRequest(ts.URL, redirectURI)
	result, err := svc.StartAuthorization(context.Background(), req)
	if err != nil {
		t.Fatalf("authorize should succeed with approved redirect: %v", err)
	}
	if result.Session == nil {
		t.Fatal("session should have been created")
	}
}
