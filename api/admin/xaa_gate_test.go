package admin_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	apiadmin "github.com/authplane/authserver/api/admin"
	"github.com/authplane/authserver/internal/adapters/static"
	"github.com/authplane/authserver/internal/config"
	"github.com/authplane/authserver/internal/domain/idp"
	"github.com/authplane/authserver/internal/observability"
	"github.com/authplane/authserver/internal/ports/input"
	"github.com/authplane/authserver/internal/ports/output"
	"github.com/authplane/authserver/internal/services"
	"github.com/authplane/authserver/testdata"
)

// stubIDP is a non-nil XAAIDPPort so the XAA routes mount. RegisterIDP records
// that it was reached (the gate dispatched) and returns an error so the handler
// writes a clean response without building a TrustedIDP.
type stubIDP struct{ called *bool }

func (s stubIDP) RegisterIDP(context.Context, input.RegisterIDPRequest) (*idp.TrustedIDP, error) {
	*s.called = true
	return nil, errors.New("stub")
}
func (stubIDP) GetIDP(context.Context, string) (*idp.TrustedIDP, error) {
	return nil, errors.New("stub")
}
func (stubIDP) ListIDPs(context.Context) ([]idp.TrustedIDP, error) { return nil, errors.New("stub") }
func (stubIDP) UpdateIDP(context.Context, string, input.UpdateIDPRequest) (*idp.TrustedIDP, error) {
	return nil, errors.New("stub")
}
func (stubIDP) DeleteIDP(context.Context, string) error   { return errors.New("stub") }
func (stubIDP) RefreshKeys(context.Context, string) error { return errors.New("stub") }

// erroringXAA always fails, exercising the gate's 500 path.
type erroringXAA struct{}

func (erroringXAA) Config(context.Context) (output.XAAConfig, error) {
	return output.XAAConfig{}, errors.New("boom")
}

func newXAAServer(t *testing.T, called *bool, cfgp output.XAAConfigProvider) *httptest.Server {
	t.Helper()
	stores := testdata.SetupTestStores(t)
	obs := observability.NewNoop()
	adminSvc := services.NewAdminService(
		stores.Client, stores.User, stores.Token, stores.Audit,
		obs, nil,
		services.WithMachineTokenStore(stores.MachineToken),
		services.WithRevocationStore(stores.Revocation),
	)
	srv := mustNewServer(t, config.AdminConfig{
		Enabled: true, Address: ":0", APIKey: sysAPIKey,
	}, adminSvc, obs, apiadmin.OptionalDeps{
		XAA: &apiadmin.XAADeps{IDP: stubIDP{called: called}, Config: cfgp},
	})
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	return ts
}

func postIDP(t *testing.T, url string) int {
	t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, url+"/admin/idps", strings.NewReader(`{"name":"x","issuer":"https://idp.example"}`))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+sysAPIKey)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	return resp.StatusCode
}

func TestXAAGate_DisabledReturns503(t *testing.T) {
	called := false
	ts := newXAAServer(t, &called, static.NewXAAConfigProvider(output.XAAConfig{Enabled: false}))
	if got := postIDP(t, ts.URL); got != http.StatusServiceUnavailable {
		t.Fatalf("status: got %d, want 503", got)
	}
	if called {
		t.Fatal("handler was reached despite feature disabled")
	}
}

func TestXAAGate_ProviderErrorReturns500(t *testing.T) {
	called := false
	ts := newXAAServer(t, &called, erroringXAA{})
	if got := postIDP(t, ts.URL); got != http.StatusInternalServerError {
		t.Fatalf("status: got %d, want 500", got)
	}
	if called {
		t.Fatal("handler was reached despite provider error")
	}
}

func TestXAAGate_EnabledDispatches(t *testing.T) {
	called := false
	ts := newXAAServer(t, &called, static.NewXAAConfigProvider(output.XAAConfig{Enabled: true}))
	_ = postIDP(t, ts.URL)
	if !called {
		t.Fatal("handler was not reached despite feature enabled")
	}
}

func TestXAAGate_NilConfigReturns500(t *testing.T) {
	called := false
	ts := newXAAServer(t, &called, nil) // routes mount (IDP set) but Config unwired
	if got := postIDP(t, ts.URL); got != http.StatusInternalServerError {
		t.Fatalf("status: got %d, want 500", got)
	}
	if called {
		t.Fatal("handler was reached despite nil config provider")
	}
}
