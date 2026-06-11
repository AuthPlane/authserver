//go:build integration

package public_test

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	apipublic "github.com/authplane/authserver/api/public"
	"github.com/authplane/authserver/internal/config"
	"github.com/authplane/authserver/internal/domain/user"
	"github.com/authplane/authserver/internal/observability"
	"github.com/authplane/authserver/internal/services"
	"github.com/authplane/authserver/testdata"
)

// mockOIDCFlowProvider implements apipublic.OIDCFlowProvider for HTTP tests.
type mockOIDCFlowProvider struct {
	authURL string
	user    *user.User
	err     error
}

func (m *mockOIDCFlowProvider) AuthorizationURL(state, nonce, codeChallenge, redirectURI string) string {
	return fmt.Sprintf("%s?state=%s&nonce=%s&code_challenge=%s&redirect_uri=%s",
		m.authURL, state, nonce, codeChallenge, redirectURI)
}

func (m *mockOIDCFlowProvider) AuthenticateOIDC(ctx context.Context, code, nonce, codeVerifier, redirectURI string) (*user.User, error) {
	if m.err != nil {
		return nil, m.err
	}
	return m.user, nil
}

// oidcTestEnv holds the test environment for OIDC endpoint tests.
type oidcTestEnv struct {
	ts   *httptest.Server
	mock *mockOIDCFlowProvider
}

func newOIDCTestServer(t *testing.T, mock *mockOIDCFlowProvider) *oidcTestEnv {
	t.Helper()

	obs := observability.NewNoop()
	stores := testdata.SetupTestStores(t)

	authSvc := services.NewUserAuthService(stores.User, obs, nil)

	srv := apipublic.NewServer(context.Background(), testServerCfg(), apipublic.Deps{
		Auth: authSvc,
		OIDC: mock,
		OIDCConfig: config.OIDCConfig{
			Enabled:        true,
			DisplayName:    "Test IdP",
			RedirectURI:    "http://localhost:9000/oidc/callback",
			ShowLocalLogin: true,
		},
		SessionCfg: config.SessionConfig{
			CookieName: "authserver_session",
			MaxAge:     24 * time.Hour,
			Secret:     "test-secret-32-bytes-long-enough",
			SameSite:   "lax",
		},
	}, obs)

	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)

	return &oidcTestEnv{ts: ts, mock: mock}
}

// --- GET /oidc/start ---

func TestOIDCStart_RedirectsToUpstreamIdP(t *testing.T) {
	mock := &mockOIDCFlowProvider{authURL: "https://idp.example.com/authorize"}
	env := newOIDCTestServer(t, mock)

	client := &http.Client{CheckRedirect: func(r *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}}

	resp, err := client.Get(env.ts.URL + "/oidc/start?redirect=/oauth/authorize%3Fclient_id%3Dabc")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusFound {
		t.Fatalf("status: got %d, want 302", resp.StatusCode)
	}

	loc := resp.Header.Get("Location")
	if !strings.HasPrefix(loc, "https://idp.example.com/authorize?") {
		t.Fatalf("redirect location: got %q, want prefix https://idp.example.com/authorize?", loc)
	}

	locURL, err := url.Parse(loc)
	if err != nil {
		t.Fatalf("parse location: %v", err)
	}
	if locURL.Query().Get("state") == "" {
		t.Error("missing state parameter in redirect URL")
	}
	if locURL.Query().Get("nonce") == "" {
		t.Error("missing nonce parameter in redirect URL")
	}
	// Verify PKCE challenge is present.
	if locURL.Query().Get("code_challenge") == "" {
		t.Error("missing code_challenge parameter in redirect URL")
	}

	// Verify browser-binding state cookie is set.
	var hasStateCookie bool
	for _, c := range resp.Cookies() {
		if c.Name == "authserver_oidc_state" && c.Value != "" {
			hasStateCookie = true
		}
	}
	if !hasStateCookie {
		t.Error("expected authserver_oidc_state cookie to be set")
	}
}

// --- GET /oidc/callback ---

func TestOIDCCallback_StateMismatch_Rejected(t *testing.T) {
	mock := &mockOIDCFlowProvider{authURL: "https://idp.example.com/authorize"}
	env := newOIDCTestServer(t, mock)

	// Send callback with invalid state (not HMAC-signed by our server).
	resp, err := http.Get(env.ts.URL + "/oidc/callback?code=testcode&state=invalid-state")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status: got %d, want 400", resp.StatusCode)
	}
}

func TestOIDCCallback_MissingCode_Rejected(t *testing.T) {
	mock := &mockOIDCFlowProvider{authURL: "https://idp.example.com/authorize"}
	env := newOIDCTestServer(t, mock)

	resp, err := http.Get(env.ts.URL + "/oidc/callback?state=some-state")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status: got %d, want 400", resp.StatusCode)
	}
}

func TestOIDCCallback_UpstreamError_SafeError(t *testing.T) {
	mock := &mockOIDCFlowProvider{authURL: "https://idp.example.com/authorize"}
	env := newOIDCTestServer(t, mock)

	// Upstream IdP returns an error.
	resp, err := http.Get(env.ts.URL + "/oidc/callback?error=access_denied&error_description=user+denied+consent")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status: got %d, want 400", resp.StatusCode)
	}
}

func TestOIDCCallback_Success_CreatesSession(t *testing.T) {
	testUser := &user.User{
		ID:     "user-oidc-1",
		Email:  "oidc-user@example.com",
		Status: user.StatusActive,
		Role:   user.RoleUser,
	}
	mock := &mockOIDCFlowProvider{
		authURL: "https://idp.example.com/authorize",
		user:    testUser,
	}
	env := newOIDCTestServer(t, mock)

	// Use a cookie jar so the state cookie from /oidc/start flows to /oidc/callback.
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatalf("cookiejar: %v", err)
	}
	noRedirect := &http.Client{
		Jar: jar,
		CheckRedirect: func(r *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	// Step 1: Start OIDC flow to get a valid state parameter.
	startResp, err := noRedirect.Get(env.ts.URL + "/oidc/start?redirect=/")
	if err != nil {
		t.Fatalf("start: %v", err)
	}
	startResp.Body.Close()

	// Extract state from the redirect URL.
	loc := startResp.Header.Get("Location")
	locURL, err := url.Parse(loc)
	if err != nil {
		t.Fatalf("parse location: %v", err)
	}
	state := locURL.Query().Get("state")
	if state == "" {
		t.Fatal("state is empty in start redirect")
	}

	// Step 2: Simulate callback with the valid state (jar carries the state cookie).
	cbURL := fmt.Sprintf("%s/oidc/callback?code=test-auth-code&state=%s", env.ts.URL, url.QueryEscape(state))
	cbResp, err := noRedirect.Get(cbURL)
	if err != nil {
		t.Fatalf("callback: %v", err)
	}
	cbResp.Body.Close()

	if cbResp.StatusCode != http.StatusSeeOther {
		t.Fatalf("status: got %d, want 303", cbResp.StatusCode)
	}

	// Check session cookie was set.
	var hasCookie bool
	for _, c := range cbResp.Cookies() {
		if c.Name == "authserver_session" && c.Value != "" {
			hasCookie = true
		}
	}
	if !hasCookie {
		t.Error("expected authserver_session cookie to be set")
	}
}

func TestOIDCCallback_AuthFailed_ShowsError(t *testing.T) {
	mock := &mockOIDCFlowProvider{
		authURL: "https://idp.example.com/authorize",
		err:     fmt.Errorf("upstream auth failed"),
	}
	env := newOIDCTestServer(t, mock)

	// Use a cookie jar so the state cookie from /oidc/start flows to /oidc/callback.
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatalf("cookiejar: %v", err)
	}
	noRedirect := &http.Client{
		Jar: jar,
		CheckRedirect: func(r *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	// Step 1: Start OIDC flow to get valid state.
	startResp, err := noRedirect.Get(env.ts.URL + "/oidc/start?redirect=/")
	if err != nil {
		t.Fatalf("start: %v", err)
	}
	startResp.Body.Close()

	loc := startResp.Header.Get("Location")
	locURL, _ := url.Parse(loc)
	state := locURL.Query().Get("state")

	// Step 2: Callback with valid state but mock returns error.
	cbURL := fmt.Sprintf("%s/oidc/callback?code=bad-code&state=%s", env.ts.URL, url.QueryEscape(state))
	cbResp, err := noRedirect.Get(cbURL)
	if err != nil {
		t.Fatalf("callback: %v", err)
	}
	cbResp.Body.Close()

	if cbResp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status: got %d, want 401", cbResp.StatusCode)
	}
}

// --- Login page OIDC button ---

func TestLoginPage_ShowsOIDCButton(t *testing.T) {
	mock := &mockOIDCFlowProvider{authURL: "https://idp.example.com/authorize"}
	env := newOIDCTestServer(t, mock)

	resp, err := http.Get(env.ts.URL + "/login?redirect=/oauth/authorize")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status: got %d, want 200", resp.StatusCode)
	}

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	body := string(bodyBytes)

	if !strings.Contains(body, "Continue with Test IdP") {
		t.Error("login page missing OIDC button text 'Continue with Test IdP'")
	}
	if !strings.Contains(body, "/oidc/start") {
		t.Error("login page missing OIDC start URL")
	}
}

func TestLoginPage_NoOIDCButton_WhenDisabled(t *testing.T) {
	obs := observability.NewNoop()
	stores := testdata.SetupTestStores(t)
	authSvc := services.NewUserAuthService(stores.User, obs, nil)

	// No OIDC provider configured.
	srv := apipublic.NewServer(context.Background(), testServerCfg(), apipublic.Deps{
		Auth: authSvc,
		OIDCConfig: config.OIDCConfig{
			ShowLocalLogin: true,
		},
		SessionCfg: config.SessionConfig{
			CookieName: "authserver_session",
			MaxAge:     24 * time.Hour,
			Secret:     "test-secret-32-bytes-long-enough",
			SameSite:   "lax",
		},
	}, obs)

	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/login")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer resp.Body.Close()

	bodyBytes, _ := io.ReadAll(resp.Body)
	body := string(bodyBytes)

	if strings.Contains(body, "Continue with") {
		t.Error("login page should NOT show OIDC button when OIDC is disabled")
	}
}

// --- show_local_login tests ---

func TestLoginPage_HidesPasswordForm_WhenShowLocalLoginFalse(t *testing.T) {
	obs := observability.NewNoop()
	stores := testdata.SetupTestStores(t)
	authSvc := services.NewUserAuthService(stores.User, obs, nil)

	mock := &mockOIDCFlowProvider{authURL: "https://idp.example.com/authorize"}

	srv := apipublic.NewServer(context.Background(), testServerCfg(), apipublic.Deps{
		Auth: authSvc,
		OIDC: mock,
		OIDCConfig: config.OIDCConfig{
			Enabled:        true,
			DisplayName:    "Corporate SSO",
			RedirectURI:    "http://localhost:9000/oidc/callback",
			ShowLocalLogin: false,
		},
		SessionCfg: config.SessionConfig{
			CookieName: "authserver_session",
			MaxAge:     24 * time.Hour,
			Secret:     "test-secret-32-bytes-long-enough",
			SameSite:   "lax",
		},
	}, obs)

	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/login")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer resp.Body.Close()

	bodyBytes, _ := io.ReadAll(resp.Body)
	body := string(bodyBytes)

	// Should show the OIDC button.
	if !strings.Contains(body, "Continue with Corporate SSO") {
		t.Error("login page should show OIDC button")
	}

	// Should NOT show the password form.
	if strings.Contains(body, `type="password"`) {
		t.Error("login page should NOT show password form when showLocalLogin=false")
	}

	// Should NOT show the divider.
	if strings.Contains(body, "or sign in with email") {
		t.Error("login page should NOT show divider when showLocalLogin=false")
	}
}

// Compile-time check that mockOIDCFlowProvider satisfies the interface the HTTP layer needs.
var _ interface {
	AuthorizationURL(state, nonce, codeChallenge, redirectURI string) string
	AuthenticateOIDC(ctx context.Context, code, nonce, codeVerifier, redirectURI string) (*user.User, error)
} = (*mockOIDCFlowProvider)(nil)
