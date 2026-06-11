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
	fetcher := cimd.New(false, time.Hour, 10*time.Second, obs)
	fetcher.SetAllowLoopback(true)
	svc := services.NewCIMDService(stores.Client, fetcher, services.DCRMode{Mode: "open"}, obs.WithComponent("cimd"))

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
	fetcher := cimd.New(false, time.Hour, 10*time.Second, obs)
	fetcher.SetAllowLoopback(true)
	svc := services.NewCIMDService(stores.Client, fetcher, services.DCRMode{Mode: "open"}, obs.WithComponent("cimd"))

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
	fetcher := cimd.New(false, time.Millisecond, 10*time.Second, obs)
	fetcher.SetAllowLoopback(true)
	svc := services.NewCIMDService(stores.Client, fetcher, services.DCRMode{Mode: "open"}, obs.WithComponent("cimd"))

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
	fetcher := cimd.New(false, time.Hour, 10*time.Second, obs)
	fetcher.SetAllowLoopback(true)
	svc := services.NewCIMDService(stores.Client, fetcher, services.DCRMode{Mode: "open"}, obs.WithComponent("cimd"))

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
	fetcher := cimd.New(false, time.Millisecond, 10*time.Second, obs)
	fetcher.SetAllowLoopback(true)
	svc := services.NewCIMDService(stores.Client, fetcher, services.DCRMode{Mode: "open"}, obs.WithComponent("cimd"))

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
	fetcher := cimd.New(false, time.Millisecond, 10*time.Second, obs)
	fetcher.SetAllowLoopback(true)
	svc := services.NewCIMDService(stores.Client, fetcher, services.DCRMode{Mode: "open"}, obs.WithComponent("cimd"))

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
	fetcher := cimd.New(false, time.Hour, 10*time.Second, obs)
	fetcher.SetAllowLoopback(true)
	svc := services.NewCIMDService(stores.Client, fetcher, services.DCRMode{Mode: "open"}, obs.WithComponent("cimd"))

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
	fetcher := cimd.New(false, time.Hour, 10*time.Second, obs)
	fetcher.SetAllowLoopback(true)
	svc := services.NewCIMDService(stores.Client, fetcher, services.DCRMode{Mode: "admin_only"}, obs.WithComponent("cimd"))

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
	fetcher := cimd.New(false, time.Hour, 10*time.Second, obs)
	fetcher.SetAllowLoopback(true)
	svc := services.NewCIMDService(stores.Client, fetcher, services.DCRMode{
		Mode:              "approved_redirects",
		ApprovedRedirects: []string{"https://trusted.example.com/callback"},
	}, obs.WithComponent("cimd"))

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
	fetcher := cimd.New(false, time.Hour, 10*time.Second, obs)
	fetcher.SetAllowLoopback(true)
	svc := services.NewCIMDService(stores.Client, fetcher, services.DCRMode{
		Mode:              "approved_redirects",
		ApprovedRedirects: []string{"https://trusted.example.com/callback"},
	}, obs.WithComponent("cimd"))

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
	fetcher := cimd.New(false, time.Hour, 10*time.Second, obs)
	fetcher.SetAllowLoopback(true)
	svc := services.NewCIMDService(stores.Client, fetcher, services.DCRMode{
		Mode:              "approved_redirects",
		ApprovedRedirects: []string{"https://trusted.example.com/callback"},
	}, obs.WithComponent("cimd"))

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
	fetcher := cimd.New(false, time.Hour, 10*time.Second, obs)
	fetcher.SetAllowLoopback(true)
	svc := services.NewCIMDService(stores.Client, fetcher, services.DCRMode{Mode: "open"}, obs.WithComponent("cimd"))

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
	fetcher := cimd.New(false, time.Millisecond, 10*time.Second, obs)
	fetcher.SetAllowLoopback(true)
	svc := services.NewCIMDService(stores.Client, fetcher, services.DCRMode{
		Mode:              "approved_redirects",
		ApprovedRedirects: []string{"https://trusted.example.com/callback"},
	}, obs.WithComponent("cimd"))

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
	fetcher := cimd.New(false, time.Hour, 10*time.Second, obs)
	fetcher.SetAllowLoopback(true)
	svc := services.NewCIMDService(
		stores.Client, fetcher, services.DCRMode{Mode: "open"},
		obs.WithComponent("cimd"),
		services.WithCIMDEnabledGrants([]string{"authorization_code", "refresh_token"}),
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
	fetcher := cimd.New(false, time.Hour, 10*time.Second, obs)
	fetcher.SetAllowLoopback(true)
	svc := services.NewCIMDService(
		stores.Client, fetcher, services.DCRMode{Mode: "open"},
		obs.WithComponent("cimd"),
		services.WithCIMDEnabledGrants([]string{"authorization_code", "refresh_token", "client_credentials"}),
	)

	c, err := svc.VerifyCIMD(context.Background(), ts.URL)
	if err != nil {
		t.Fatalf("verify cimd with enabled grant: %v", err)
	}
	if c.ID != ts.URL {
		t.Errorf("client_id: got %q, want %q", c.ID, ts.URL)
	}
}
