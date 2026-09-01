//go:build integration

package public_test

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	apipublic "github.com/authplane/authserver/api/public"
	"github.com/authplane/authserver/internal/adapters/static"
	"github.com/authplane/authserver/internal/observability"
	"github.com/authplane/authserver/internal/ports/output"
	"github.com/authplane/authserver/internal/services"
	"github.com/authplane/authserver/testdata"
)

// errorLoginDisplayProvider always fails — exercises the login page's
// 500-on-error guard.
type errorLoginDisplayProvider struct{}

func (errorLoginDisplayProvider) LoginDisplay(_ context.Context) (output.LoginDisplay, error) {
	return output.LoginDisplay{}, errors.New("synthetic login-display failure")
}

func newErrorResolverServer(t *testing.T) *httptest.Server {
	t.Helper()
	obs := observability.NewNoop()
	stores := testdata.SetupTestStores(t)
	authSvc := services.NewUserAuthService(stores.User, obs, nil)
	mock := &mockOIDCFlowProvider{authURL: "https://idp.example.com/authorize"}
	srv := apipublic.NewServer(context.Background(), testServerCfg(), apipublic.Deps{
		CORSConfigProvider:      testCORS(),
		Auth:                    authSvc,
		OIDC:                    mock,
		LoginDisplay:            errorLoginDisplayProvider{},
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

// TestOIDCCallback_BadStateBeforeResolver_Returns400 verifies that a
// request with an undecodable state short-circuits at 400 during
// request-shape validation.
func TestOIDCCallback_BadStateBeforeResolver_Returns400(t *testing.T) {
	ts := newErrorResolverServer(t)
	// "y" is a single character — not valid base64-URL, so the state
	// decode fails before any further check.
	resp, err := http.Get(ts.URL + "/oidc/callback?code=x&state=y")
	if err != nil {
		t.Fatalf("GET /oidc/callback: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", resp.StatusCode)
	}
}

func TestLoginPage_GetResolverError_Returns500(t *testing.T) {
	ts := newErrorResolverServer(t)
	resp, err := http.Get(ts.URL + "/login")
	if err != nil {
		t.Fatalf("GET /login: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", resp.StatusCode)
	}
}

// POST /login resolves the display provider once, up front (the local-login
// gate), so a failing resolver answers 500 before the body, nonce or CSRF are
// looked at. The error re-render reuses that result and resolves nothing.
func TestLoginPage_PostResolverError_Returns500(t *testing.T) {
	ts := newErrorResolverServer(t)
	form := url.Values{
		"email":      {"user@example.com"},
		"password":   {"wrong"},
		"csrf_token": {"invalid-csrf-token"},
	}
	resp, err := http.PostForm(ts.URL+"/login", form)
	if err != nil {
		t.Fatalf("POST /login: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusInternalServerError {
		body, readErr := io.ReadAll(io.LimitReader(resp.Body, 512))
		if readErr != nil {
			t.Fatalf("status = %d, want 500; body read error: %v", resp.StatusCode, readErr)
		}
		t.Fatalf("status = %d, want 500; body=%q", resp.StatusCode, strings.TrimSpace(string(body)))
	}
}
