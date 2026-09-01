package admin_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	apiadmin "github.com/authplane/authserver/api/admin"
	"github.com/authplane/authserver/internal/config"
	"github.com/authplane/authserver/internal/observability"
	"github.com/authplane/authserver/internal/services"
	"github.com/authplane/authserver/testdata"
)

// stubAuth is an injected AuthWrapper that short-circuits every request with
// 418, proving the injected strategy gated the route (never reaching handlers).
type stubAuth struct{ called *bool }

func (s stubAuth) Wrap(http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		*s.called = true
		w.WriteHeader(http.StatusTeapot)
	})
}

// newSeamServerErr constructs the admin server and returns its constructor
// error, for tests that assert on malformed-extra-route validation.
func newSeamServerErr(t *testing.T, cfg config.AdminConfig, opts apiadmin.OptionalDeps) (*apiadmin.Server, error) {
	t.Helper()
	stores := testdata.SetupTestStores(t)
	obs := observability.NewNoop()
	adminSvc := services.NewAdminService(
		stores.Client, stores.User, stores.Token, stores.Audit,
		obs, nil,
		services.WithMachineTokenStore(stores.MachineToken),
		services.WithRevocationStore(stores.Revocation),
	)
	return apiadmin.NewServer(context.Background(), cfg, adminSvc, obs, opts)
}

// mustNewServer constructs the admin server, failing the test on a
// construction error. For happy-path tests that don't exercise extra-route
// validation.
func mustNewServer(t *testing.T, cfg config.AdminConfig, admin apiadmin.Provider, obs *observability.Provider, opts apiadmin.OptionalDeps) *apiadmin.Server {
	t.Helper()
	srv, err := apiadmin.NewServer(context.Background(), cfg, admin, obs, opts)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	return srv
}

func newSeamServer(t *testing.T, cfg config.AdminConfig, opts apiadmin.OptionalDeps) *httptest.Server {
	t.Helper()
	srv, err := newSeamServerErr(t, cfg, opts)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	return ts
}

// getStatus issues an unauthenticated GET and returns the response status
// code, closing the body. The tests only assert on the status.
func getStatus(t *testing.T, url string) int {
	t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, url, nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	return resp.StatusCode
}

func TestInjectedAuthWrapper_GatesBusinessRoutes(t *testing.T) {
	called := false
	ts := newSeamServer(t,
		config.AdminConfig{Enabled: true, Address: ":0"},
		apiadmin.OptionalDeps{Auth: stubAuth{called: &called}},
	)
	status := getStatus(t, ts.URL+"/admin/clients")
	if status != http.StatusTeapot {
		t.Errorf("business route should be gated by injected Auth (418), got %d", status)
	}
	if !called {
		t.Error("injected AuthWrapper.Wrap was not invoked")
	}
}

func TestInjectedAuthWrapper_UIRouteBypassesIt(t *testing.T) {
	called := false
	ts := newSeamServer(t,
		config.AdminConfig{Enabled: true, Address: ":0"},
		apiadmin.OptionalDeps{Auth: stubAuth{called: &called}},
	)
	status := getStatus(t, ts.URL+"/admin/ui/")
	if status == http.StatusTeapot {
		t.Error("/admin/ui/ must be registered outside the auth wrapper")
	}
}

// TestNoAuthWrapper_EmptyAPIKey_FailsClosed: no injected wrapper and no API key
// → the empty-key API-key gate rejects all requests (fail-closed). This is the
// path a server fronted by external auth hits if it forgets to inject a wrapper.
func TestNoAuthWrapper_EmptyAPIKey_FailsClosed(t *testing.T) {
	ts := newSeamServer(t,
		config.AdminConfig{Enabled: true, Address: ":0"}, // no Auth injected, no APIKey
		apiadmin.OptionalDeps{},
	)
	status := getStatus(t, ts.URL+"/admin/clients")
	if status != http.StatusUnauthorized {
		t.Errorf("no wrapper + empty API key must fail closed (401), got %d", status)
	}
}

// TestDefault_APIKeyGateWhenNoAuthInjected covers the OSS default path: no
// AuthWrapper injected → the API-key gate built from cfg.APIKey rejects an
// unauthenticated request.
func TestDefault_APIKeyGateWhenNoAuthInjected(t *testing.T) {
	ts := newSeamServer(t,
		config.AdminConfig{Enabled: true, Address: ":0", APIKey: "test-admin-api-key-123"},
		apiadmin.OptionalDeps{}, // no Auth injected
	)
	status := getStatus(t, ts.URL+"/admin/clients")
	if status != http.StatusUnauthorized {
		t.Errorf("default path must use API-key gate (401 without a token), got %d", status)
	}
}
