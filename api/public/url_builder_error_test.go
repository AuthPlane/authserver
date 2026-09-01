//go:build integration

package public_test

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"

	apipublic "github.com/authplane/authserver/api/public"
	"github.com/authplane/authserver/internal/adapters/static"
	"github.com/authplane/authserver/internal/config"
	"github.com/authplane/authserver/internal/domain/user"
	"github.com/authplane/authserver/internal/observability"
	"github.com/authplane/authserver/internal/ports/output"
	"github.com/authplane/authserver/internal/services"
	"github.com/authplane/authserver/testdata"
)

// failingURLBuilder always returns an error on every call. Used to
// exercise the 500-on-error guard at every URLBuilder consumer site.
type failingURLBuilder struct{}

func (failingURLBuilder) Resolve(_ context.Context, _ string) (string, error) {
	return "", errors.New("synthetic url-builder failure")
}

var _ output.URLBuilder = failingURLBuilder{}

// toggleableURLBuilder delegates to a healthy static.URLBuilder until
// SetFailing(true) is called, after which every method returns an error.
// Mirrors toggleableOIDCProvider from oidc_provider_error_test.go: used
// to simulate a healthy server that loses its URL builder mid-flow —
// for example, a DB-backed builder whose connection drops between
// /oidc/start and /oidc/callback, or between the GET /login that issued
// the CSRF token and the POST /login that consumes it.
type toggleableURLBuilder struct {
	inner output.URLBuilder
	mu    sync.RWMutex
	bad   bool
}

func (b *toggleableURLBuilder) Resolve(ctx context.Context, path string) (string, error) {
	b.mu.RLock()
	defer b.mu.RUnlock()
	if b.bad {
		return "", errors.New("toggleable: synthetic mid-flow url-builder failure")
	}
	return b.inner.Resolve(ctx, path)
}

func (b *toggleableURLBuilder) SetFailing(v bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.bad = v
}

var _ output.URLBuilder = (*toggleableURLBuilder)(nil)

// newURLBuilderErrorServer wires a server with a failing URLBuilder and a
// caller-supplied OIDC config. The OIDC flow provider is the same mock
// used elsewhere in this package; the auth service is backed by the
// in-memory test stores so callers can seed users via the returned
// services.UserAuthService.
func newURLBuilderErrorServer(t *testing.T, oidcCfg config.OIDCConfig, urls output.URLBuilder) (*httptest.Server, *services.UserAuthService) {
	t.Helper()
	obs := observability.NewNoop()
	stores := testdata.SetupTestStores(t)
	authSvc := services.NewUserAuthService(stores.User, obs, nil)
	mock := &mockOIDCFlowProvider{authURL: "https://idp.example.com/authorize"}
	srv := apipublic.NewServer(context.Background(), testServerCfg(), apipublic.Deps{
		CORSConfigProvider:      testCORS(),
		Auth:                    authSvc,
		OIDC:                    mock,
		LoginDisplay:            static.NewLoginDisplayProvider(oidcCfg),
		URLs:                    urls,
		SessionSecretProvider:   testSessionSecret(),
		SessionConfigProvider:   testSessionConfig(),
		OIDCStateConfigProvider: testOIDCStateConfig(),
		StateCodec:              newStateCodecForTest([]byte("integration-test-key")),
		SessionCookie:           apipublic.SessionCookie{Name: "authserver_session"},
	}, obs)
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	return ts, authSvc
}

// TestLogin_GetOIDCStartResolveError_Returns500 asserts that when OIDC is
// enabled (DisplayName != "") and urls.Resolve(ctx, "/oidc/start?redirect=...")
// fails inside handleGetLogin, the response is 500.
func TestLogin_GetOIDCStartResolveError_Returns500(t *testing.T) {
	ts, _ := newURLBuilderErrorServer(t, config.OIDCConfig{
		Enabled:        true,
		DisplayName:    "Test IdP",
		RedirectURI:    "http://localhost:9000/oidc/callback",
		ShowLocalLogin: true,
	}, failingURLBuilder{})

	resp, err := http.Get(ts.URL + "/login")
	if err != nil {
		t.Fatalf("GET /login: %v", err)
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

// TestLocalLogin_PostLoginResolveError_Returns500 exercises the
// urls.Resolve(ctx, safe) error guard in handlePostLogin. The builder starts
// healthy so the GET /login that fetches the form (and any OIDC start
// link rendering) succeeds, then we flip it into failing mode right
// before submitting the POST. By the time the handler reaches the
// Resolve call all upstream checks (CSRF, Authenticate, session
// cookie set) have already passed.
//
// OIDC is disabled at the resolver level (DisplayName empty) so the
// failing Resolve path for OIDC-start is not exercised here — this test isolates
// the post-login Resolve failure point.
func TestLocalLogin_PostLoginResolveError_Returns500(t *testing.T) {
	builder := &toggleableURLBuilder{inner: static.NewURLBuilder()}
	ts, authSvc := newURLBuilderErrorServer(t, config.OIDCConfig{
		Enabled:        true,
		DisplayName:    "",
		ShowLocalLogin: true,
	}, builder)

	// Seed a user so Authenticate succeeds and the handler reaches the
	// post-login Resolve call site.
	ctx := t.Context()
	if _, err := authSvc.CreateUser(ctx, "urlb-local@example.com", "", "secret123", user.RoleUser); err != nil {
		t.Fatalf("create user: %v", err)
	}

	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}

	// Flip the builder into failing mode just before POST. There is no
	// GET in handlePostLogin, so we don't need to keep the builder
	// healthy past this point.
	builder.SetFailing(true)

	resp, err := postLogin(t, client, ts.URL, "urlb-local@example.com", "secret123")
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

// TestOIDC_CallbackPostLoginResolveError_Returns500 exercises the
// urls.Resolve(ctx, safe) error guard in handleOIDCCallback. The builder starts
// healthy so GET /oidc/start succeeds and emits a valid state + state
// cookie; we then flip it into failing mode and submit the callback. A
// mockOIDCFlowProvider seeded with a user makes AuthenticateOIDC
// succeed, so the handler reaches Resolve — which fails.
func TestOIDC_CallbackPostLoginResolveError_Returns500(t *testing.T) {
	builder := &toggleableURLBuilder{inner: static.NewURLBuilder()}

	obs := observability.NewNoop()
	stores := testdata.SetupTestStores(t)
	authSvc := services.NewUserAuthService(stores.User, obs, nil)
	mock := &mockOIDCFlowProvider{
		authURL: "https://idp.example.com/authorize",
		user: &user.User{
			ID:     "user-oidc-urlb-cb",
			Email:  "oidc-urlb-cb@example.com",
			Status: user.StatusActive,
			Role:   user.RoleUser,
		},
	}
	srv := apipublic.NewServer(context.Background(), testServerCfg(), apipublic.Deps{
		CORSConfigProvider:      testCORS(),
		Auth:                    authSvc,
		LoginDisplay:            static.NewLoginDisplayProvider(config.OIDCConfig{ShowLocalLogin: true}),
		OIDC:                    mock,
		URLs:                    builder,
		SessionSecretProvider:   testSessionSecret(),
		SessionConfigProvider:   testSessionConfig(),
		OIDCStateConfigProvider: testOIDCStateConfig(),
		StateCodec:              newStateCodecForTest([]byte("integration-test-key")),
		SessionCookie:           apipublic.SessionCookie{Name: "authserver_session"},
	}, obs)
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)

	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatalf("cookiejar: %v", err)
	}
	client := &http.Client{
		Jar: jar,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	// Step 1: drive /oidc/start while the builder is healthy so we get a
	// valid state + state cookie that will pass all callback validation.
	startResp, err := client.Get(ts.URL + "/oidc/start?redirect=/")
	if err != nil {
		t.Fatalf("GET /oidc/start: %v", err)
	}
	startResp.Body.Close()
	if startResp.StatusCode != http.StatusFound {
		t.Fatalf("start status = %d, want 302", startResp.StatusCode)
	}
	loc, err := url.Parse(startResp.Header.Get("Location"))
	if err != nil {
		t.Fatalf("parse Location: %v", err)
	}
	state := loc.Query().Get("state")
	if state == "" {
		t.Fatal("state is empty in start redirect")
	}

	// Step 2: flip the builder into failing mode, then submit the
	// callback. All upstream gates pass; the post-login Resolve is the failure
	// point.
	builder.SetFailing(true)

	cbURL := fmt.Sprintf("%s/oidc/callback?code=test-auth-code&state=%s", ts.URL, url.QueryEscape(state))
	cbResp, err := client.Get(cbURL)
	if err != nil {
		t.Fatalf("GET /oidc/callback: %v", err)
	}
	defer cbResp.Body.Close()

	if cbResp.StatusCode != http.StatusInternalServerError {
		body, readErr := io.ReadAll(io.LimitReader(cbResp.Body, 512))
		if readErr != nil {
			t.Fatalf("callback status = %d, want 500; body read error: %v", cbResp.StatusCode, readErr)
		}
		t.Fatalf("callback status = %d, want 500; body=%q", cbResp.StatusCode, strings.TrimSpace(string(body)))
	}
}

// TestLogin_NoOIDC_BuilderNotCalled_Returns200 documents that when OIDC
// is disabled (DisplayName == ""), the GET /login handler does NOT resolve
// the OIDC-start path — so wiring an always-failing builder must
// still produce 200. This is the negative counterpart to
// TestLogin_GetOIDCStartResolveError_Returns500: it proves the call is
// gated on DisplayName != "".
func TestLogin_NoOIDC_BuilderNotCalled_Returns200(t *testing.T) {
	ts, _ := newURLBuilderErrorServer(t, config.OIDCConfig{
		Enabled:        true,
		DisplayName:    "",
		ShowLocalLogin: true,
	}, failingURLBuilder{})

	resp, err := http.Get(ts.URL + "/login")
	if err != nil {
		t.Fatalf("GET /login: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, readErr := io.ReadAll(io.LimitReader(resp.Body, 512))
		if readErr != nil {
			t.Fatalf("status = %d, want 200 (builder must not be called when DisplayName is empty); body read error: %v", resp.StatusCode, readErr)
		}
		t.Fatalf("status = %d, want 200 (builder must not be called when DisplayName is empty); body=%q", resp.StatusCode, strings.TrimSpace(string(body)))
	}
}
