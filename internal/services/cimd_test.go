//go:build integration

package services_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/authplane/authserver/internal/adapters/cimd"
	"github.com/authplane/authserver/internal/domain"
	"github.com/authplane/authserver/internal/ports/output"
	"github.com/authplane/authserver/internal/services"
	"github.com/authplane/authserver/testdata"
)

func TestCIMD_CreateClient(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		doc := output.CIMDDocument{
			ClientID:     "http://" + r.Host,
			ClientName:   "CIMD Test Client",
			RedirectURIs: []string{"https://app.example.com/callback"},
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(doc)
	}))
	defer ts.Close()

	stores := testdata.SetupTestStores(t)
	obs := testObs()
	fetcher := cimd.New(obs)
	fetcher.SetAllowLoopback(true)
	svc := services.NewCIMDService(stores.Client, fetcher, staticDCRModeForTest{Mode: "open"}, enabledCIMDConfigForTest(), obs.WithComponent("cimd"))

	ctx := context.Background()
	c, err := svc.VerifyCIMD(ctx, ts.URL)
	if err != nil {
		t.Fatalf("verify cimd: %v", err)
	}
	if c.ID != ts.URL {
		t.Errorf("client_id: got %q, want %q", c.ID, ts.URL)
	}
	if c.Name != "CIMD Test Client" {
		t.Errorf("client_name: got %q", c.Name)
	}
	if c.RegistrationSource != "cimd" {
		t.Errorf("registration_source: got %q", c.RegistrationSource)
	}
	if c.CIMDURL != ts.URL {
		t.Errorf("cimd_url: got %q", c.CIMDURL)
	}
}

// Matrix: 3.3 — upgraded from warning: CIMD redirect_uris are enforced after client creation
func TestCIMD_RedirectURIsEnforced(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		doc := output.CIMDDocument{
			ClientID:     "http://" + r.Host,
			ClientName:   "CIMD Redirect Test",
			RedirectURIs: []string{"https://app.example.com/callback"},
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(doc)
	}))
	defer ts.Close()

	stores := testdata.SetupTestStores(t)
	obs := testObs()
	fetcher := cimd.New(obs)
	fetcher.SetAllowLoopback(true)
	svc := services.NewCIMDService(stores.Client, fetcher, staticDCRModeForTest{Mode: "open"}, enabledCIMDConfigForTest(), obs.WithComponent("cimd"))

	ctx := context.Background()
	c, err := svc.VerifyCIMD(ctx, ts.URL)
	if err != nil {
		t.Fatalf("verify cimd: %v", err)
	}

	// Verify the client's redirect_uris are stored from the CIMD document.
	if len(c.RedirectURIs) != 1 || c.RedirectURIs[0] != "https://app.example.com/callback" {
		t.Fatalf("redirect_uris: got %v", c.RedirectURIs)
	}

	// Verify a non-matching redirect_uri is rejected by HasRedirectURI.
	if c.HasRedirectURI("https://evil.example.com/callback") {
		t.Error("redirect_uri not in CIMD document should be rejected")
	}
	if !c.HasRedirectURI("https://app.example.com/callback") {
		t.Error("redirect_uri from CIMD document should be accepted")
	}
}

func TestCIMD_UpdateExistingClient(t *testing.T) {
	var callCount int
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		name := "Original Name"
		if callCount > 1 {
			name = "Updated Name"
		}
		doc := output.CIMDDocument{
			ClientID:     "http://" + r.Host,
			ClientName:   name,
			RedirectURIs: []string{"https://app.example.com/callback"},
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(doc)
	}))
	defer ts.Close()

	stores := testdata.SetupTestStores(t)
	obs := testObs()
	// Use short cache TTL so second call re-fetches.
	fetcher := cimd.New(obs)
	fetcher.SetAllowLoopback(true)
	svc := services.NewCIMDService(stores.Client, fetcher, staticDCRModeForTest{Mode: "open"}, enabledCIMDConfigForTest(), obs.WithComponent("cimd"))

	ctx := context.Background()

	// First call — creates client.
	c1, err := svc.VerifyCIMD(ctx, ts.URL)
	if err != nil {
		t.Fatalf("first verify: %v", err)
	}
	if c1.Name != "Original Name" {
		t.Errorf("first name: got %q", c1.Name)
	}

	// Wait for cache to expire.
	time.Sleep(5 * time.Millisecond)

	// Second call — updates existing client.
	c2, err := svc.VerifyCIMD(ctx, ts.URL)
	if err != nil {
		t.Fatalf("second verify: %v", err)
	}
	if c2.Name != "Updated Name" {
		t.Errorf("updated name: got %q", c2.Name)
	}
	if c2.ID != c1.ID {
		t.Errorf("client_id changed: %q → %q", c1.ID, c2.ID)
	}
}

func TestCIMD_FetchFailed(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer ts.Close()

	stores := testdata.SetupTestStores(t)
	obs := testObs()
	fetcher := cimd.New(obs)
	fetcher.SetAllowLoopback(true)
	svc := services.NewCIMDService(stores.Client, fetcher, staticDCRModeForTest{Mode: "open"}, enabledCIMDConfigForTest(), obs.WithComponent("cimd"))

	_, err := svc.VerifyCIMD(context.Background(), ts.URL)
	if err == nil {
		t.Fatal("expected error")
	}
	if !errors.Is(err, domain.ErrCIMDFetchFailed) {
		t.Errorf("expected ErrCIMDFetchFailed, got: %v", err)
	}
}

// TestCIMD_UpdateExisting_RedirectURIsChange verifies that when a CIMD document
// changes its redirect_uris, the existing client is updated accordingly.
func TestCIMD_UpdateExisting_RedirectURIsChange(t *testing.T) {
	var callCount int
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		uris := []string{"https://app.example.com/callback"}
		if callCount > 1 {
			uris = []string{"https://app.example.com/callback", "https://app.example.com/callback2"}
		}
		doc := output.CIMDDocument{
			ClientID:     "http://" + r.Host,
			ClientName:   "Redirect Test",
			RedirectURIs: uris,
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(doc)
	}))
	defer ts.Close()

	stores := testdata.SetupTestStores(t)
	obs := testObs()
	fetcher := cimd.New(obs)
	fetcher.SetAllowLoopback(true)
	svc := services.NewCIMDService(stores.Client, fetcher, staticDCRModeForTest{Mode: "open"}, enabledCIMDConfigForTest(), obs.WithComponent("cimd"))

	ctx := context.Background()

	// First call — creates client with 1 redirect_uri.
	c1, err := svc.VerifyCIMD(ctx, ts.URL)
	if err != nil {
		t.Fatalf("first verify: %v", err)
	}
	if len(c1.RedirectURIs) != 1 {
		t.Fatalf("first redirect_uris: got %d, want 1", len(c1.RedirectURIs))
	}

	time.Sleep(5 * time.Millisecond)

	// Second call — updates redirect_uris to 2.
	c2, err := svc.VerifyCIMD(ctx, ts.URL)
	if err != nil {
		t.Fatalf("second verify: %v", err)
	}
	if len(c2.RedirectURIs) != 2 {
		t.Fatalf("updated redirect_uris: got %d, want 2", len(c2.RedirectURIs))
	}
	if c2.RedirectURIs[1] != "https://app.example.com/callback2" {
		t.Errorf("second redirect_uri: got %q", c2.RedirectURIs[1])
	}
}

// TestCIMD_UpdateExisting_GrantTypesChange verifies that when a CIMD document
// changes grant_types, response_types, and token_endpoint_auth_method, they update.
func TestCIMD_UpdateExisting_GrantTypesChange(t *testing.T) {
	var callCount int
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		doc := output.CIMDDocument{
			ClientID:     "http://" + r.Host,
			ClientName:   "Grant Type Test",
			RedirectURIs: []string{"https://app.example.com/callback"},
		}
		if callCount > 1 {
			doc.GrantTypes = []string{"authorization_code", "client_credentials"}
			doc.ResponseTypes = []string{"code", "token"}
			doc.TokenEndpointAuthMethod = "client_secret_post"
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(doc)
	}))
	defer ts.Close()

	stores := testdata.SetupTestStores(t)
	obs := testObs()
	fetcher := cimd.New(obs)
	fetcher.SetAllowLoopback(true)
	svc := services.NewCIMDService(stores.Client, fetcher, staticDCRModeForTest{Mode: "open"}, enabledCIMDConfigForTest(), obs.WithComponent("cimd"))

	ctx := context.Background()

	// First call — defaults applied (authorization_code, code, none).
	c1, err := svc.VerifyCIMD(ctx, ts.URL)
	if err != nil {
		t.Fatalf("first verify: %v", err)
	}
	if len(c1.GrantTypes) != 1 || c1.GrantTypes[0] != "authorization_code" {
		t.Errorf("first grant_types: got %v", c1.GrantTypes)
	}
	if c1.TokenEndpointAuthMethod != "none" {
		t.Errorf("first auth method: got %q", c1.TokenEndpointAuthMethod)
	}

	time.Sleep(5 * time.Millisecond)

	// Second call — updated grant_types and auth method.
	c2, err := svc.VerifyCIMD(ctx, ts.URL)
	if err != nil {
		t.Fatalf("second verify: %v", err)
	}
	if len(c2.GrantTypes) != 2 {
		t.Fatalf("updated grant_types: got %v, want 2 entries", c2.GrantTypes)
	}
	if c2.TokenEndpointAuthMethod != "client_secret_post" {
		t.Errorf("updated auth method: got %q", c2.TokenEndpointAuthMethod)
	}
	if len(c2.ResponseTypes) != 2 {
		t.Errorf("updated response_types: got %v, want 2 entries", c2.ResponseTypes)
	}
}

// TestCIMD_ClientStatus_Active verifies newly created CIMD client has active status.
func TestCIMD_ClientStatus_Active(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		doc := output.CIMDDocument{
			ClientID:     "http://" + r.Host,
			ClientName:   "Status Test",
			RedirectURIs: []string{"https://app.example.com/callback"},
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(doc)
	}))
	defer ts.Close()

	stores := testdata.SetupTestStores(t)
	obs := testObs()
	fetcher := cimd.New(obs)
	fetcher.SetAllowLoopback(true)
	svc := services.NewCIMDService(stores.Client, fetcher, staticDCRModeForTest{Mode: "open"}, enabledCIMDConfigForTest(), obs.WithComponent("cimd"))

	c, err := svc.VerifyCIMD(context.Background(), ts.URL)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if !c.IsActive() {
		t.Errorf("CIMD client should be active, got status: %q", c.Status)
	}
}

// --- Adversarial tests: CIMD + DCR cross-feature interaction ---

// TestCIMD_AdminOnly_BlocksAutoRegistration verifies that CIMD auto-registration
// is rejected when DCR mode is admin_only.
func TestCIMD_AdminOnly_BlocksAutoRegistration(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		doc := output.CIMDDocument{
			ClientID:     "http://" + r.Host,
			ClientName:   "Blocked Client",
			RedirectURIs: []string{"https://evil.example.com/callback"},
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(doc)
	}))
	defer ts.Close()

	stores := testdata.SetupTestStores(t)
	obs := testObs()
	fetcher := cimd.New(obs)
	fetcher.SetAllowLoopback(true)
	svc := services.NewCIMDService(stores.Client, fetcher, staticDCRModeForTest{Mode: "admin_only"}, enabledCIMDConfigForTest(), obs.WithComponent("cimd"))

	_, err := svc.VerifyCIMD(context.Background(), ts.URL)
	if !errors.Is(err, domain.ErrRegistrationDisabled) {
		t.Errorf("err = %v, want ErrRegistrationDisabled (admin_only should block CIMD)", err)
	}

	// Verify no client was created in the DB.
	c, _ := stores.Client.GetByCIMDURL(context.Background(), ts.URL)
	if c != nil {
		t.Error("client should NOT have been created in admin_only mode")
	}
}

// TestCIMD_ProviderError_RejectsRegistration verifies CIMD fails closed: when
// the DCR mode provider errors, VerifyCIMD must reject before fetching and must
// not auto-register a client, rather than falling back to a permissive default.
func TestCIMD_ProviderError_RejectsRegistration(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		doc := output.CIMDDocument{
			ClientID:     "http://" + r.Host,
			ClientName:   "Would-Be Client",
			RedirectURIs: []string{"https://app.example.com/callback"},
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(doc)
	}))
	defer ts.Close()

	stores := testdata.SetupTestStores(t)
	obs := testObs()
	fetcher := cimd.New(obs)
	fetcher.SetAllowLoopback(true)
	svc := services.NewCIMDService(stores.Client, fetcher, failingDCRModeForTest{}, enabledCIMDConfigForTest(), obs.WithComponent("cimd"))

	_, err := svc.VerifyCIMD(context.Background(), ts.URL)
	if err == nil {
		t.Fatal("expected VerifyCIMD to fail closed when the mode provider errors, got nil")
	}
	if !errors.Is(err, errProviderUnavailable) {
		t.Errorf("error should wrap the provider failure, got %v", err)
	}

	// Fail-closed must not auto-register a client.
	c, _ := stores.Client.GetByCIMDURL(context.Background(), ts.URL)
	if c != nil {
		t.Error("client should NOT have been created on provider error")
	}
}

// TestCIMD_UnknownMode_RejectsRegistration verifies CIMD fails closed on an
// unrecognized DCR mode (allowlist/default-deny), matching DCRService rather
// than falling through to auto-registration.
func TestCIMD_UnknownMode_RejectsRegistration(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		doc := output.CIMDDocument{
			ClientID:     "http://" + r.Host,
			ClientName:   "Would-Be Client",
			RedirectURIs: []string{"https://app.example.com/callback"},
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(doc)
	}))
	defer ts.Close()

	stores := testdata.SetupTestStores(t)
	obs := testObs()
	fetcher := cimd.New(obs)
	fetcher.SetAllowLoopback(true)
	svc := services.NewCIMDService(stores.Client, fetcher, staticDCRModeForTest{Mode: "bogus"}, enabledCIMDConfigForTest(), obs.WithComponent("cimd"))

	_, err := svc.VerifyCIMD(context.Background(), ts.URL)
	if err == nil {
		t.Fatal("expected VerifyCIMD to reject an unknown DCR mode, got nil")
	}

	// Fail-closed must not auto-register a client.
	c, _ := stores.Client.GetByCIMDURL(context.Background(), ts.URL)
	if c != nil {
		t.Error("client should NOT have been created under an unknown mode")
	}
}

// TestCIMD_ApprovedRedirects_RejectsUnapprovedURI verifies that CIMD auto-registration
// is rejected when the CIMD document contains redirect URIs not in the approved list.
func TestCIMD_ApprovedRedirects_RejectsUnapprovedURI(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		doc := output.CIMDDocument{
			ClientID:     "http://" + r.Host,
			ClientName:   "Attacker Client",
			RedirectURIs: []string{"https://evil.example.com/callback"},
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(doc)
	}))
	defer ts.Close()

	stores := testdata.SetupTestStores(t)
	obs := testObs()
	fetcher := cimd.New(obs)
	fetcher.SetAllowLoopback(true)
	svc := services.NewCIMDService(stores.Client, fetcher, staticDCRModeForTest{
		Mode:              "approved_redirects",
		ApprovedRedirects: []string{"https://trusted.example.com/callback"},
	}, enabledCIMDConfigForTest(), obs.WithComponent("cimd"))

	_, err := svc.VerifyCIMD(context.Background(), ts.URL)
	if !errors.Is(err, domain.ErrInvalidRedirectURI) {
		t.Errorf("err = %v, want ErrInvalidRedirectURI (unapproved redirect_uri)", err)
	}

	// Verify no client was created.
	c, _ := stores.Client.GetByCIMDURL(context.Background(), ts.URL)
	if c != nil {
		t.Error("client should NOT have been created with unapproved redirect_uri")
	}
}

// TestCIMD_ApprovedRedirects_AllowsApprovedURI verifies CIMD auto-registration
// succeeds when all redirect URIs are in the approved list.
func TestCIMD_ApprovedRedirects_AllowsApprovedURI(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		doc := output.CIMDDocument{
			ClientID:     "http://" + r.Host,
			ClientName:   "Approved Client",
			RedirectURIs: []string{"https://trusted.example.com/callback"},
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(doc)
	}))
	defer ts.Close()

	stores := testdata.SetupTestStores(t)
	obs := testObs()
	fetcher := cimd.New(obs)
	fetcher.SetAllowLoopback(true)
	svc := services.NewCIMDService(stores.Client, fetcher, staticDCRModeForTest{
		Mode:              "approved_redirects",
		ApprovedRedirects: []string{"https://trusted.example.com/callback"},
	}, enabledCIMDConfigForTest(), obs.WithComponent("cimd"))

	c, err := svc.VerifyCIMD(context.Background(), ts.URL)
	if err != nil {
		t.Fatalf("verify: %v (approved redirect should be allowed)", err)
	}
	if c.ID != ts.URL {
		t.Errorf("client_id: got %q, want %q", c.ID, ts.URL)
	}
}

// TestCIMD_ApprovedRedirects_MixedURIs verifies that when a CIMD document has
// multiple redirect URIs and only some are approved, the registration is rejected.
func TestCIMD_ApprovedRedirects_MixedURIs(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		doc := output.CIMDDocument{
			ClientID:     "http://" + r.Host,
			ClientName:   "Mixed Client",
			RedirectURIs: []string{"https://trusted.example.com/callback", "https://evil.example.com/callback"},
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(doc)
	}))
	defer ts.Close()

	stores := testdata.SetupTestStores(t)
	obs := testObs()
	fetcher := cimd.New(obs)
	fetcher.SetAllowLoopback(true)
	svc := services.NewCIMDService(stores.Client, fetcher, staticDCRModeForTest{
		Mode:              "approved_redirects",
		ApprovedRedirects: []string{"https://trusted.example.com/callback"},
	}, enabledCIMDConfigForTest(), obs.WithComponent("cimd"))

	_, err := svc.VerifyCIMD(context.Background(), ts.URL)
	if !errors.Is(err, domain.ErrInvalidRedirectURI) {
		t.Errorf("err = %v, want ErrInvalidRedirectURI (one URI unapproved)", err)
	}
}

// TestCIMD_Open_AllowsAutoRegistration verifies the default open mode
// still works (regression test).
func TestCIMD_Open_AllowsAutoRegistration(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		doc := output.CIMDDocument{
			ClientID:     "http://" + r.Host,
			ClientName:   "Open Mode Client",
			RedirectURIs: []string{"https://any.example.com/callback"},
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(doc)
	}))
	defer ts.Close()

	stores := testdata.SetupTestStores(t)
	obs := testObs()
	fetcher := cimd.New(obs)
	fetcher.SetAllowLoopback(true)
	svc := services.NewCIMDService(stores.Client, fetcher, staticDCRModeForTest{Mode: "open"}, enabledCIMDConfigForTest(), obs.WithComponent("cimd"))

	c, err := svc.VerifyCIMD(context.Background(), ts.URL)
	if err != nil {
		t.Fatalf("verify: %v (open mode should allow any client)", err)
	}
	if c.ID != ts.URL {
		t.Errorf("client_id: got %q, want %q", c.ID, ts.URL)
	}
}

// TestCIMD_ApprovedRedirects_BlocksUpdateWithUnapprovedURI verifies that when
// an existing CIMD client updates and the new CIMD document has unapproved
// redirect_uris, the update is rejected. The DCR check runs before the
// create-or-update logic, so both paths are protected.
func TestCIMD_ApprovedRedirects_BlocksUpdateWithUnapprovedURI(t *testing.T) {
	var callCount int
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		uris := []string{"https://trusted.example.com/callback"} // first: approved
		if callCount > 1 {
			uris = []string{"https://evil.example.com/callback"} // second: unapproved
		}
		doc := output.CIMDDocument{
			ClientID:     "http://" + r.Host,
			ClientName:   "Update Test",
			RedirectURIs: uris,
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(doc)
	}))
	defer ts.Close()

	stores := testdata.SetupTestStores(t)
	obs := testObs()
	fetcher := cimd.New(obs)
	fetcher.SetAllowLoopback(true)
	svc := services.NewCIMDService(stores.Client, fetcher, staticDCRModeForTest{
		Mode:              "approved_redirects",
		ApprovedRedirects: []string{"https://trusted.example.com/callback"},
	}, enabledCIMDConfigForTest(), obs.WithComponent("cimd"))

	ctx := context.Background()

	// First call — approved redirect, should succeed.
	c, err := svc.VerifyCIMD(ctx, ts.URL)
	if err != nil {
		t.Fatalf("first verify: %v", err)
	}
	if c.ID != ts.URL {
		t.Errorf("client_id: got %q, want %q", c.ID, ts.URL)
	}

	time.Sleep(5 * time.Millisecond) // expire cache

	// Second call — CIMD doc now has unapproved redirect, should be rejected.
	_, err = svc.VerifyCIMD(ctx, ts.URL)
	if !errors.Is(err, domain.ErrInvalidRedirectURI) {
		t.Errorf("err = %v, want ErrInvalidRedirectURI (update with unapproved URI)", err)
	}
}

// CIMD must reject fetched docs whose grant_types aren't in the
// runtime-enabled set. Without this guard, CIMD remained the third path
// (alongside admin REST and DCR) that could persist status=active
// clients whose grants /oauth/token can't serve.
func TestCIMD_GrantNotEnabled_Rejected(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		doc := output.CIMDDocument{
			ClientID:                "http://" + r.Host,
			ClientName:              "CIMD CC Client",
			RedirectURIs:            []string{"https://app.example.com/callback"},
			GrantTypes:              []string{"client_credentials"},
			TokenEndpointAuthMethod: "client_secret_post",
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(doc)
	}))
	defer ts.Close()

	stores := testdata.SetupTestStores(t)
	obs := testObs()
	fetcher := cimd.New(obs)
	fetcher.SetAllowLoopback(true)
	svc := services.NewCIMDService(
		stores.Client, fetcher, staticDCRModeForTest{Mode: "open"},
		enabledCIMDConfigForTest(),
		obs.WithComponent("cimd"),
		services.WithCIMDEnabledGrants(staticGrantsForTest{grants: []string{"authorization_code", "refresh_token"}}),
	)

	_, err := svc.VerifyCIMD(context.Background(), ts.URL)
	if err == nil {
		t.Fatal("CIMD must reject doc with disabled grant_type")
	}
	if !errors.Is(err, domain.ErrInvalidClient) {
		t.Errorf("expected ErrInvalidClient, got: %v", err)
	}
	if !strings.Contains(err.Error(), "AUTHPLANE_CLIENT_CREDENTIALS_ENABLED") {
		t.Errorf("error should name the env var: %v", err)
	}

	// And nothing was persisted — fail-loud beats silent half-write.
	persisted, lookupErr := stores.Client.GetByCIMDURL(context.Background(), ts.URL)
	if lookupErr != nil {
		t.Fatalf("GetByCIMDURL: %v", lookupErr)
	}
	if persisted != nil {
		t.Errorf("rejected CIMD doc must not have persisted a client row, got %+v", persisted)
	}
}

// CIMD with an enabled grant continues to work — the new guard
// must not regress the ordinary CIMD path.
func TestCIMD_GrantEnabled_Accepted(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		doc := output.CIMDDocument{
			ClientID:                "http://" + r.Host,
			ClientName:              "CIMD CC Client",
			RedirectURIs:            []string{"https://app.example.com/callback"},
			GrantTypes:              []string{"client_credentials"},
			TokenEndpointAuthMethod: "client_secret_post",
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(doc)
	}))
	defer ts.Close()

	stores := testdata.SetupTestStores(t)
	obs := testObs()
	fetcher := cimd.New(obs)
	fetcher.SetAllowLoopback(true)
	svc := services.NewCIMDService(
		stores.Client, fetcher, staticDCRModeForTest{Mode: "open"},
		enabledCIMDConfigForTest(),
		obs.WithComponent("cimd"),
		services.WithCIMDEnabledGrants(staticGrantsForTest{grants: []string{"authorization_code", "refresh_token", "client_credentials"}}),
	)

	c, err := svc.VerifyCIMD(context.Background(), ts.URL)
	if err != nil {
		t.Fatalf("verify cimd with enabled grant: %v", err)
	}
	if c.ID != ts.URL {
		t.Errorf("client_id: got %q, want %q", c.ID, ts.URL)
	}
}

// staticGrantsForTest is a test-local output.EnabledGrantsProvider returning a
// fixed set. Defined here (not imported from internal/adapters/static) to
// respect the integration-test import ratchet.
type staticGrantsForTest struct{ grants []string }

func (p staticGrantsForTest) Get(context.Context) ([]string, error) { return p.grants, nil }

// failingGrantsForTest errors on Get to exercise the fail-closed path.
type failingGrantsForTest struct{}

var errGrantsUnavailable = errors.New("enabled grants provider unavailable")

func (failingGrantsForTest) Get(context.Context) ([]string, error) {
	return nil, errGrantsUnavailable
}

// staticCIMDConfigForTest is a test-local output.CIMDConfigProvider returning a
// fixed config. Defined here (not imported from internal/adapters/static) to
// respect the integration-test import ratchet.
type staticCIMDConfigForTest struct{ cfg output.CIMDConfig }

func (p staticCIMDConfigForTest) Config(context.Context) (output.CIMDConfig, error) {
	return p.cfg, nil
}

// failingCIMDConfigForTest errors on Config to exercise the fail-closed path.
type failingCIMDConfigForTest struct{}

var errCIMDConfigUnavailable = errors.New("cimd config provider unavailable")

func (failingCIMDConfigForTest) Config(context.Context) (output.CIMDConfig, error) {
	return output.CIMDConfig{}, errCIMDConfigUnavailable
}

// enabledCIMDConfigForTest is the default config provider for CIMD service
// tests: feature enabled, loopback-friendly (RequireHTTPS=false), and a 1ms
// cache TTL so the update tests' re-fetch-after-expiry path works (harmless for
// the single-call tests). cimdConfig is a required positional constructor arg,
// so every service construction passes this (or its own provider).
func enabledCIMDConfigForTest() output.CIMDConfigProvider {
	return staticCIMDConfigForTest{cfg: output.CIMDConfig{
		Enabled:      true,
		RequireHTTPS: false,
		CacheTTL:     time.Millisecond,
		FetchTimeout: 10 * time.Second,
	}}
}

// TestCIMD_ConfigDisabled_RejectsRegistration verifies that when the config
// provider reports Enabled=false, VerifyCIMD denies with ErrRegistrationDisabled
// before fetching and persists nothing.
func TestCIMD_ConfigDisabled_RejectsRegistration(t *testing.T) {
	var fetchCalled bool
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fetchCalled = true
		doc := output.CIMDDocument{
			ClientID:     "http://" + r.Host,
			ClientName:   "Disabled Test",
			RedirectURIs: []string{"https://app.example.com/callback"},
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(doc)
	}))
	defer ts.Close()

	stores := testdata.SetupTestStores(t)
	obs := testObs()
	fetcher := cimd.New(obs)
	fetcher.SetAllowLoopback(true)
	svc := services.NewCIMDService(
		stores.Client, fetcher, staticDCRModeForTest{Mode: "open"},
		staticCIMDConfigForTest{cfg: output.CIMDConfig{
			Enabled: false, RequireHTTPS: false, CacheTTL: time.Hour, FetchTimeout: 10 * time.Second,
		}},
		obs.WithComponent("cimd"),
	)

	_, err := svc.VerifyCIMD(context.Background(), ts.URL)
	if !errors.Is(err, domain.ErrRegistrationDisabled) {
		t.Fatalf("expected ErrRegistrationDisabled, got %v", err)
	}
	if fetchCalled {
		t.Error("fetcher must not be called when CIMD config is disabled")
	}
	if c, _ := stores.Client.GetByCIMDURL(context.Background(), ts.URL); c != nil {
		t.Error("client must NOT be created when CIMD disabled")
	}
}

// TestCIMD_ConfigProviderError_RejectsRegistration verifies the fail-closed path:
// a config provider error rejects before fetching and persists nothing.
func TestCIMD_ConfigProviderError_RejectsRegistration(t *testing.T) {
	var fetchCalled bool
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fetchCalled = true
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	stores := testdata.SetupTestStores(t)
	obs := testObs()
	fetcher := cimd.New(obs)
	fetcher.SetAllowLoopback(true)
	svc := services.NewCIMDService(
		stores.Client, fetcher, staticDCRModeForTest{Mode: "open"},
		failingCIMDConfigForTest{},
		obs.WithComponent("cimd"),
	)

	_, err := svc.VerifyCIMD(context.Background(), ts.URL)
	if err == nil {
		t.Fatal("expected fail-closed error when config provider errors")
	}
	if !errors.Is(err, errCIMDConfigUnavailable) {
		t.Errorf("error should wrap the provider failure, got %v", err)
	}
	if fetchCalled {
		t.Error("fetcher must not be called when config provider errors")
	}
	if c, _ := stores.Client.GetByCIMDURL(context.Background(), ts.URL); c != nil {
		t.Error("client must NOT be created on provider error")
	}
}

// TestCIMD_GrantsProviderError_RejectsRegistration verifies fail-closed: when the
// enabled-grants provider errors, VerifyCIMD rejects before persisting.
func TestCIMD_GrantsProviderError_RejectsRegistration(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		doc := output.CIMDDocument{
			ClientID:     "http://" + r.Host,
			ClientName:   "Grants Provider Error",
			RedirectURIs: []string{"https://app.example.com/callback"},
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(doc)
	}))
	defer ts.Close()

	stores := testdata.SetupTestStores(t)
	obs := testObs()
	fetcher := cimd.New(obs)
	fetcher.SetAllowLoopback(true)
	svc := services.NewCIMDService(
		stores.Client, fetcher, staticDCRModeForTest{Mode: "open"},
		enabledCIMDConfigForTest(), obs.WithComponent("cimd"),
		services.WithCIMDEnabledGrants(failingGrantsForTest{}),
	)

	_, err := svc.VerifyCIMD(context.Background(), ts.URL)
	if !errors.Is(err, errGrantsUnavailable) {
		t.Fatalf("expected wrapped errGrantsUnavailable, got %v", err)
	}
	if c, _ := stores.Client.GetByCIMDURL(context.Background(), ts.URL); c != nil {
		t.Error("client must NOT be created when the grants provider errors")
	}
}
