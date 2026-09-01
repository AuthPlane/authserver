//go:build integration

package public_test

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	apipublic "github.com/authplane/authserver/api/public"
	"github.com/authplane/authserver/internal/adapters/static"
	"github.com/authplane/authserver/internal/config"
	"github.com/authplane/authserver/internal/observability"
	"github.com/authplane/authserver/internal/services"
	"github.com/authplane/authserver/testdata"
)

// newIdentityServer is the same default-wiring shape we ship —
// captured here explicitly to keep the test self-contained.
func newIdentityServer(t *testing.T, oidcCfg config.OIDCConfig, mock *mockOIDCFlowProvider) *httptest.Server {
	t.Helper()
	obs := observability.NewNoop()
	stores := testdata.SetupTestStores(t)
	authSvc := services.NewUserAuthService(stores.User, obs, nil)
	srv := apipublic.NewServer(context.Background(), testServerCfg(), apipublic.Deps{
		CORSConfigProvider:      testCORS(),
		Auth:                    authSvc,
		OIDC:                    mock,
		LoginDisplay:            static.NewLoginDisplayProvider(oidcCfg),
		URLs:                    static.NewURLBuilder(),
		SessionSecretProvider:   testSessionSecret(),
		SessionConfigProvider:   testSessionConfig(),
		OIDCStateConfigProvider: testOIDCStateConfig(),
		StateCodec:              newStateCodecForTest([]byte("integration-test-key")),
		SessionCookie:           apipublic.SessionCookie{Name: "authserver_session"},
	}, obs)
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	return ts
}

func TestLoginPage_StaticResolver_RendersOIDCButton(t *testing.T) {
	cfg := config.OIDCConfig{
		Enabled:        true,
		DisplayName:    "Identity IdP",
		RedirectURI:    "https://as.example.com/oidc/callback",
		ShowLocalLogin: true,
	}
	mock := &mockOIDCFlowProvider{authURL: "https://idp.example.com/authorize"}
	ts := newIdentityServer(t, cfg, mock)

	resp, err := http.Get(ts.URL + "/login")
	if err != nil {
		t.Fatalf("get /login: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	html := string(body)
	if !strings.Contains(html, "Identity IdP") {
		t.Errorf("/login HTML missing OIDC DisplayName; body=%s", html)
	}
	if !strings.Contains(html, "/oidc/start?redirect=") {
		t.Errorf("/login HTML missing OIDC start link; body=%s", html)
	}
}

func TestLoginPage_StaticResolver_HidesOIDCWhenDisplayNameEmpty(t *testing.T) {
	cfg := config.OIDCConfig{Enabled: true, ShowLocalLogin: true}
	mock := &mockOIDCFlowProvider{authURL: "https://idp.example.com/authorize"}
	ts := newIdentityServer(t, cfg, mock)

	resp, err := http.Get(ts.URL + "/login")
	if err != nil {
		t.Fatalf("get /login: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	html := string(body)
	if strings.Contains(html, "/oidc/start?redirect=") {
		t.Errorf("/login should not advertise OIDC button when DisplayName empty; body=%s", html)
	}
}
