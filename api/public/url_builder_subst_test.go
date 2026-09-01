//go:build integration

package public_test

import (
	"context"
	"html/template"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
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

// prefixURLBuilder prepends a fixed prefix to all internal URLs. It
// illustrates how a custom URLBuilder can route requests behind a path
// prefix (e.g., for alternative deployments sharing a single host).
type prefixURLBuilder struct {
	prefix string
}

func (b prefixURLBuilder) Resolve(_ context.Context, path string) (string, error) {
	return b.prefix + path, nil
}

// Compile-time conformance.
var _ output.URLBuilder = prefixURLBuilder{}

// newPrefixURLBuilderServer wires a public Server with a prefixURLBuilder
// and a static OIDC resolver. It mirrors the helpers in the F0-03
// substitution test (oidc_provider_subst_test.go) so this file stays
// self-contained.
func newPrefixURLBuilderServer(t *testing.T, prefix string, oidcCfg config.OIDCConfig) (*httptest.Server, *services.UserAuthService) {
	t.Helper()
	obs := observability.NewNoop()
	stores := testdata.SetupTestStores(t)
	authSvc := services.NewUserAuthService(stores.User, obs, nil)
	srv := apipublic.NewServer(context.Background(), testServerCfg(), apipublic.Deps{
		CORSConfigProvider:    testCORS(),
		Auth:                  authSvc,
		LoginDisplay:          static.NewLoginDisplayProvider(oidcCfg),
		URLs:                  prefixURLBuilder{prefix: prefix},
		SessionSecretProvider: testSessionSecret(),
		SessionConfigProvider: testSessionConfig(),
		SessionCookie:         apipublic.SessionCookie{Name: "authserver_session"},
	}, obs)
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	return ts, authSvc
}

// TestLoginHTML_PrefixURLBuilder_RewritesOIDCStart asserts that when a
// custom URLBuilder is injected via Deps, the rendered /login HTML uses
// the prefixed OIDC start link instead of the hardcoded default path. This
// proves the builder is honoured by the template path (not bypassed).
func TestLoginHTML_PrefixURLBuilder_RewritesOIDCStart(t *testing.T) {
	const prefix = "/d1"
	ts, _ := newPrefixURLBuilderServer(t, prefix, config.OIDCConfig{
		Enabled:        true,
		DisplayName:    "Test IdP",
		RedirectURI:    "https://as.example.com/oidc/callback",
		ShowLocalLogin: true,
	})

	// Request /login with redirect=/ so we have a deterministic, escaped
	// value to assert on. Both net/url.QueryEscape and
	// html/template.URLQueryEscaper encode "/" as "%2F", so either
	// substring should match — we accept both to keep the test honest
	// about the contract not pinning callers to a specific escape func.
	resp, err := http.Get(ts.URL + "/login?redirect=/")
	if err != nil {
		t.Fatalf("GET /login: %v", err)
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

	// Either escape function is acceptable per the URLBuilder contract.
	wantURL := url.QueryEscape("/")
	wantTpl := template.URLQueryEscaper("/")
	wantPrefixedNetURL := `href="` + prefix + "/oidc/start?redirect=" + wantURL + `"`
	wantPrefixedTpl := `href="` + prefix + "/oidc/start?redirect=" + wantTpl + `"`
	if !strings.Contains(html, wantPrefixedNetURL) && !strings.Contains(html, wantPrefixedTpl) {
		t.Fatalf("HTML missing prefixed OIDC start link; wanted one of %q / %q.\nFragment around /oidc/start:\n%s",
			wantPrefixedNetURL, wantPrefixedTpl, extractOIDCStartFragment(html))
	}

	// And the unprefixed (hardcoded) form must NOT appear — that
	// would mean a hardcoded fallback bypassed the builder.
	unprefixedNetURL := `href="/oidc/start?redirect=` + wantURL
	unprefixedTpl := `href="/oidc/start?redirect=` + wantTpl
	if strings.Contains(html, unprefixedNetURL) || strings.Contains(html, unprefixedTpl) {
		t.Fatalf("HTML still contains the unprefixed OIDC start link — the URLBuilder was bypassed.\nFragment around /oidc/start:\n%s",
			extractOIDCStartFragment(html))
	}
}

// TestPostLogin_PrefixURLBuilder_RewritesRedirect drives a successful
// local-login POST and asserts that the 303 Location header has the
// configured prefix applied. This proves the post-login Resolve is called by the
// login handler after shared.SafeRedirect — the post-login redirect
// path is part of the URLBuilder contract.
func TestPostLogin_PrefixURLBuilder_RewritesRedirect(t *testing.T) {
	const prefix = "/d1"
	ts, authSvc := newPrefixURLBuilderServer(t, prefix, config.OIDCConfig{
		// OIDC disabled so the login form just exercises the local path.
		Enabled:        false,
		ShowLocalLogin: true,
	})

	// Seed a local user. Pattern matches login_test.go's TestLogin_PostValid.
	ctx := t.Context()
	if _, err := authSvc.CreateUser(ctx, "prefix-user@example.com", "", "secret123", user.RoleUser); err != nil {
		t.Fatalf("create user: %v", err)
	}

	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}

	// GET /login first to obtain the pre-session nonce cookie and the token
	// rendered into the form, the way a browser does (see loginPageCSRF in
	// login_test.go). The client has no cookie jar, so the nonce cookie is
	// attached to the POST explicitly.
	token, nonce := loginPageCSRF(t, client, ts.URL)

	form := url.Values{
		"email":      {"prefix-user@example.com"},
		"password":   {"secret123"},
		"redirect":   {"/dashboard"},
		"csrf_token": {token},
	}
	req, err := http.NewRequest(http.MethodPost, ts.URL+"/login", strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatalf("build login request: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if nonce != nil {
		req.AddCookie(nonce)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("POST /login: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("status = %d, want 303 (See Other)", resp.StatusCode)
	}

	got := resp.Header.Get("Location")
	const want = "/d1/dashboard"
	if got != want {
		t.Fatalf("Location header = %q, want %q (post-login Resolve prefix was not applied)", got, want)
	}
}

// TestLoginHTML_PrefixURLBuilder_RewritesFormAction proves the login form's
// POST action is resolved through the URLBuilder — under a prefix it carries
// the mount, and the bare "/login" action must not appear.
func TestLoginHTML_PrefixURLBuilder_RewritesFormAction(t *testing.T) {
	const prefix = "/d1"
	ts, _ := newPrefixURLBuilderServer(t, prefix, config.OIDCConfig{ShowLocalLogin: true})
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/login")
	if err != nil {
		t.Fatalf("GET /login: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	html := string(body)

	if !strings.Contains(html, `action="`+prefix+`/login"`) {
		t.Fatalf("form action not prefixed; want action=%q\nHTML:\n%s", prefix+"/login", html)
	}
	if strings.Contains(html, `action="/login"`) {
		t.Fatalf("form action still bare /login — URLBuilder bypassed:\n%s", html)
	}
}

// TestOIDCError_PrefixURLBuilder_RewritesBackLink proves the OIDC error page's
// "Back to sign in" link is resolved through the URLBuilder.
func TestOIDCError_PrefixURLBuilder_RewritesBackLink(t *testing.T) {
	const prefix = "/d1"

	// Need OIDC routes registered so /oidc/callback is handled.
	// Wire a minimal server with a no-op OIDC provider + state codec.
	obs := observability.NewNoop()
	stores := testdata.SetupTestStores(t)
	authSvc := services.NewUserAuthService(stores.User, obs, nil)
	mock := &mockOIDCFlowProvider{authURL: "https://idp.example.com/authorize"}
	srv := apipublic.NewServer(context.Background(), testServerCfg(), apipublic.Deps{
		CORSConfigProvider:      testCORS(),
		Auth:                    authSvc,
		SessionSecretProvider:   testSessionSecret(),
		SessionConfigProvider:   testSessionConfig(),
		OIDC:                    mock,
		LoginDisplay:            static.NewLoginDisplayProvider(config.OIDCConfig{Enabled: true, DisplayName: "Test IdP"}),
		URLs:                    prefixURLBuilder{prefix: prefix},
		OIDCStateConfigProvider: testOIDCStateConfig(),
		StateCodec:              newStateCodecForTest([]byte("integration-test-key")),
		SessionCookie:           apipublic.SessionCookie{Name: "authserver_session"},
	}, obs)
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	// A callback with no code/state renders the OIDC error page.
	resp, err := http.Get(ts.URL + "/oidc/callback")
	if err != nil {
		t.Fatalf("GET /oidc/callback: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	html := string(body)

	if !strings.Contains(html, `href="`+prefix+`/login"`) {
		t.Fatalf("back-link not prefixed; want href=%q\nHTML:\n%s", prefix+"/login", html)
	}
	if strings.Contains(html, `href="/login"`) {
		t.Fatalf("back-link still bare /login — URLBuilder bypassed:\n%s", html)
	}
}

// TestLogout_PrefixURLBuilder_RedirectsToPrefixedLogin proves the post-logout
// redirect Location carries the mount prefix.
func TestLogout_PrefixURLBuilder_RedirectsToPrefixedLogin(t *testing.T) {
	const prefix = "/d1"
	ts, _ := newPrefixURLBuilderServer(t, prefix, config.OIDCConfig{})
	defer ts.Close()

	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse // capture the 303, don't follow it
	}}
	resp, err := client.Post(ts.URL+"/logout", "application/x-www-form-urlencoded", nil)
	if err != nil {
		t.Fatalf("POST /logout: %v", err)
	}
	defer resp.Body.Close()

	if got, want := resp.Header.Get("Location"), prefix+"/login"; got != want {
		t.Fatalf("logout Location = %q, want %q", got, want)
	}
}

// extractOIDCStartFragment returns a short window of bytes around the
// first occurrence of "/oidc/start" in s for use in assertion failure
// messages, or a placeholder when the substring is absent.
func extractOIDCStartFragment(s string) string {
	const needle = "/oidc/start"
	const width = 80
	i := strings.Index(s, needle)
	if i < 0 {
		return "(no /oidc/start in body)"
	}
	start := i - width
	if start < 0 {
		start = 0
	}
	end := i + len(needle) + width
	if end > len(s) {
		end = len(s)
	}
	return s[start:end]
}
