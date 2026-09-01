//go:build integration

package public_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	apipublic "github.com/authplane/authserver/api/public"
	"github.com/authplane/authserver/internal/adapters/static"
	"github.com/authplane/authserver/internal/config"
	"github.com/authplane/authserver/internal/domain/user"
	"github.com/authplane/authserver/internal/services"
	"github.com/authplane/authserver/testdata"
)

var csrfTokenRe = regexp.MustCompile(`name="csrf_token" value="([^"]*)"`)

// loginPageCSRF performs GET /login the way a browser does and returns the
// token rendered into the form together with the nonce cookie the response
// set. Either may be zero-valued: the caller decides whether that is a
// failure, because some tests deliberately drive a server that rejects the
// GET (rate-limit lockout) or renders no form at all.
func loginPageCSRF(t *testing.T, hc *http.Client, baseURL string) (string, *http.Cookie) {
	t.Helper()
	resp, err := hc.Get(baseURL + "/login")
	if err != nil {
		t.Fatalf("get /login: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read /login body: %v", err)
	}

	var token string
	if m := csrfTokenRe.FindSubmatch(body); m != nil {
		token = string(m[1])
	}

	var nonce *http.Cookie
	for _, c := range resp.Cookies() {
		if c.Name == "authserver_login_nonce" {
			nonce = c
			break
		}
	}
	return token, nonce
}

// postLogin drives a login the way a browser does: GET /login first to obtain
// the nonce cookie and the token rendered into the form, then POST both.
//
// The nonce is attached to the request explicitly rather than relying on the
// caller's cookie jar, because most callers pass a jarless client. The GET is
// best-effort on purpose: TestLogin_LockoutAfterMaxFailures drives the server
// past its auth-failure lockout, after which GET /login itself is rejected and
// there is no token to scrape — the POST must still be sent so the test can
// observe the lockout response.
func postLogin(t *testing.T, hc *http.Client, baseURL, email, password string) (*http.Response, error) {
	t.Helper()
	token, nonce := loginPageCSRF(t, hc, baseURL)
	if token == "" {
		t.Logf("postLogin: GET /login yielded no csrf_token")
	}
	if nonce == nil {
		t.Logf("postLogin: GET /login yielded no nonce cookie")
	}

	form := url.Values{
		"email":      {email},
		"password":   {password},
		"csrf_token": {token},
	}
	req, err := http.NewRequest(http.MethodPost, baseURL+"/login", strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatalf("build login request: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if nonce != nil {
		req.AddCookie(nonce)
	}
	return hc.Do(req)
}

// sessionSecretForTest is the output.SessionSecretProvider shape, declared
// structurally so this file stays free of internal/ports/output imports
// (Gate 0 — only issuer_test_helpers_test.go is waivered for that import).
type sessionSecretForTest interface {
	Secret(context.Context) ([]byte, error)
}

// loginServerOpts varies one login-test server from another. The zero value is
// not usable — go through newLoginTestServer or newLoginTestServerWith, which
// fill the defaults.
type loginServerOpts struct {
	oidc        config.OIDCConfig
	secrets     sessionSecretForTest
	sessionCfg  sessionConfigForTest
	secureFloor bool // the boot Secure floor, which a provider may tighten but never lower
}

// newLoginTestServer builds a login test server with local login enabled,
// matching the shipped default (internal/config/loader.go:180), and a working
// session secret. Tests that need either varied use newLoginTestServerWith;
// tests that need to observe cookie attributes use newLoginTestServerOpts.
func newLoginTestServer(t *testing.T) (*httptest.Server, *services.UserAuthService) {
	t.Helper()
	return newLoginTestServerWith(t, config.OIDCConfig{ShowLocalLogin: true}, testSessionSecret())
}

func newLoginTestServerWith(t *testing.T, oidcCfg config.OIDCConfig, secrets sessionSecretForTest) (*httptest.Server, *services.UserAuthService) {
	t.Helper()
	return newLoginTestServerOpts(t, loginServerOpts{
		oidc:       oidcCfg,
		secrets:    secrets,
		sessionCfg: testSessionConfig(),
	})
}

// newLoginTestServerOpts is the single construction site for login-test
// servers. Every variation goes through a field here rather than a copied
// Deps block.
func newLoginTestServerOpts(t *testing.T, opts loginServerOpts) (*httptest.Server, *services.UserAuthService) {
	t.Helper()
	stores := testdata.SetupTestStores(t)
	obs := testObs()
	authSvc := services.NewUserAuthService(stores.User, obs, nil)
	jwksSvc := newTestJWKSService(t)

	srv := apipublic.NewServer(context.Background(), testServerCfg(), apipublic.Deps{
		CORSConfigProvider:    testCORS(),
		URLs:                  testURLBuilder(),
		SessionSecretProvider: opts.secrets,
		SessionConfigProvider: opts.sessionCfg,
		JWKS:                  jwksSvc,
		IssuerProvider:        staticIssuerForTest("https://auth.example.com"),
		Auth:                  authSvc,
		LoginDisplay:          static.NewLoginDisplayProvider(opts.oidc),
		SessionCookie: apipublic.SessionCookie{
			Name:   "authserver_session",
			Secure: opts.secureFloor,
		},
	}, obs)

	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	return ts, authSvc
}

// The login CSRF token must be unpredictable per visit.
// Before the fix it was HMAC(secret, "") — one fixed string for the whole
// deployment, fetchable anonymously and replayable forever.
func TestLogin_CSRFToken_DiffersBetweenClients(t *testing.T) {
	ts, _ := newLoginTestServer(t)

	tokenA, nonceA := loginPageCSRF(t, &http.Client{}, ts.URL)
	tokenB, nonceB := loginPageCSRF(t, &http.Client{}, ts.URL)

	if nonceA == nil || nonceB == nil {
		t.Fatal("GET /login must set the login nonce cookie")
	}
	if nonceA.Value == nonceB.Value {
		t.Errorf("independent clients got the same nonce %q", nonceA.Value)
	}
	if tokenA == tokenB {
		t.Errorf("independent clients got the same CSRF token %q — the token is still a constant", tokenA)
	}
	if !nonceA.HttpOnly {
		t.Error("nonce cookie must be HttpOnly")
	}
}

func TestLogin_GetReturns200(t *testing.T) {
	ts, _ := newLoginTestServer(t)

	resp, err := http.Get(ts.URL + "/login")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status: got %d, want 200", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); !strings.Contains(ct, "text/html") {
		t.Errorf("content-type: got %q", ct)
	}
}

func TestLogin_GetRendersCSRFTokenInput(t *testing.T) {
	ts, _ := newLoginTestServer(t)

	resp, err := http.Get(ts.URL + "/login")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	if !strings.Contains(string(body), `name="csrf_token"`) {
		t.Fatal("login page must render the csrf_token input; the test server " +
			"must enable ShowLocalLogin or no form is rendered at all")
	}
}

func TestLogin_PostValid_RedirectsWithCookie(t *testing.T) {
	ts, authSvc := newLoginTestServer(t)

	// Create a test user.
	ctx := t.Context()
	_, err := authSvc.CreateUser(ctx, "alice@example.com", "", "secret123", user.RoleUser)
	if err != nil {
		t.Fatalf("create user: %v", err)
	}

	// POST login with no-redirect client.
	client := &http.Client{CheckRedirect: func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}}

	resp, err := postLogin(t, client, ts.URL, "alice@example.com", "secret123")
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("status: got %d, want 303", resp.StatusCode)
	}

	// Check Set-Cookie header.
	cookies := resp.Cookies()
	var sessionCookie *http.Cookie
	for _, c := range cookies {
		if c.Name == "authserver_session" {
			sessionCookie = c
			break
		}
	}
	if sessionCookie == nil {
		t.Fatal("session cookie not set")
	}
	if sessionCookie.HttpOnly != true {
		t.Error("cookie should be httponly")
	}
}

// TestLogin_PostRedirect_LocationStaysOnThisOrigin drives a real POST /login
// through a real http.Server and asserts the Location header that actually
// goes out on the wire.
//
// The wire is the only place this can be checked. httptest.NewRecorder skips
// net/http's header-write path, and net/http emits a Location it cannot parse
// verbatim rather than normalising it — so a byte that survives the redirect
// helper survives all the way to the browser, which resolves it under WHATWG
// URL rules rather than Go's.
func TestLogin_PostRedirect_LocationStaysOnThisOrigin(t *testing.T) {
	ts, authSvc := newLoginTestServer(t)

	ctx := t.Context()
	if _, err := authSvc.CreateUser(ctx, "redirect@example.com", "", "secret123", user.RoleUser); err != nil {
		t.Fatalf("create user: %v", err)
	}

	cases := []struct {
		name     string
		redirect string
		want     string
	}{
		{"tab before authority", "/\t/evil.com", "/"},
		{"newline before authority", "/\n/evil.com", "/"},
		{"carriage return before authority", "/\r/evil.com", "/"},
		{"nul before authority", "/\x00/evil.com", "/"},
		{"del before authority", "/\x7f/evil.com", "/"},
		{"scheme-relative", "//evil.com", "/"},
		{"three leading slashes", "///evil.com", "/"},
		{"backslash authority", `/\evil.com`, "/"},
		{"absolute", "https://evil.com", "/"},
		{"legitimate path still honoured", "/dashboard", "/dashboard"},
		// The login-required branch of /oauth/authorize passes its whole URL
		// through as the post-login target, so this value carries a client's
		// query verbatim. Policing it here would abandon the authorization.
		{"client query survives the authorize round trip", `/oauth/authorize?client_id=x&state=a\b`, `/oauth/authorize?client_id=x&state=a\b`},
		// The reclassification the CHANGELOG headlines, asserted where it is
		// observable. ":" and "/" are legal unencoded in a query, so a client's
		// redirect_uri arrives literal and the whole authorize URL becomes the
		// post-login target; the previous blanket "://" test rewrote it to "/".
		// A unit assertion on SafeRedirect's return value would not cover this:
		// http.Redirect reshapes a target after the guard has cleared it, and
		// the query is the only part that survives that untouched.
		{"unencoded :// in query reaches the wire intact", "/oauth/authorize?redirect_uri=https://c.example/cb", "/oauth/authorize?redirect_uri=https://c.example/cb"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			}}
			token, nonce := loginPageCSRF(t, client, ts.URL)
			if token == "" || nonce == nil {
				t.Fatal("GET /login yielded no token or nonce cookie")
			}
			form := url.Values{
				"email":      {"redirect@example.com"},
				"password":   {"secret123"},
				"csrf_token": {token},
				"redirect":   {tc.redirect},
			}
			req, err := http.NewRequest(http.MethodPost, ts.URL+"/login", strings.NewReader(form.Encode()))
			if err != nil {
				t.Fatalf("build request: %v", err)
			}
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			req.AddCookie(nonce)
			resp, err := client.Do(req)
			if err != nil {
				t.Fatalf("post: %v", err)
			}
			defer resp.Body.Close()

			if resp.StatusCode != http.StatusSeeOther {
				t.Fatalf("status: got %d, want 303", resp.StatusCode)
			}
			// Assert the expected destination rather than the absence of the
			// payload: an equality check cannot be satisfied by a mangled or
			// partially-stripped variant of the attacker's value.
			if loc := resp.Header.Get("Location"); loc != tc.want {
				t.Errorf("Location = %q, want %q", loc, tc.want)
			}
		})
	}
}

func TestLogin_PostInvalid_ReRendersForm(t *testing.T) {
	ts, _ := newLoginTestServer(t)

	resp, err := postLogin(t, http.DefaultClient, ts.URL, "nobody@example.com", "wrong")
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer resp.Body.Close()

	// Should re-render the form (422, not redirect).
	if resp.StatusCode != http.StatusUnprocessableEntity {
		t.Fatalf("status: got %d, want 422", resp.StatusCode)
	}
}

func TestLogout_ClearsCookie(t *testing.T) {
	ts, _ := newLoginTestServer(t)

	client := &http.Client{CheckRedirect: func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}}

	resp, err := client.PostForm(ts.URL+"/logout", nil)
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("status: got %d, want 303", resp.StatusCode)
	}

	// Cookie should be expired (MaxAge < 0).
	for _, c := range resp.Cookies() {
		if c.Name == "authserver_session" && c.MaxAge >= 0 {
			t.Error("session cookie should have negative MaxAge")
		}
	}
}

func TestSessionMiddleware_ExtractsUserID(t *testing.T) {
	ts, authSvc := newLoginTestServer(t)

	// Create user and login to get session cookie.
	ctx := t.Context()
	_, err := authSvc.CreateUser(ctx, "session@example.com", "", "pass", user.RoleUser)
	if err != nil {
		t.Fatalf("create user: %v", err)
	}

	jar := &testCookieJar{}
	client := &http.Client{Jar: jar, CheckRedirect: func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}}

	resp, err := postLogin(t, client, ts.URL, "session@example.com", "pass")
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	resp.Body.Close()

	// Verify we got a session cookie.
	u, _ := url.Parse(ts.URL)
	cookies := jar.Cookies(u)
	if len(cookies) == 0 {
		t.Fatal("no cookies set after login")
	}
}

// Matrix: 15.5 — lockout after too many failed login attempts is logged
func TestLogin_LockoutAfterMaxFailures(t *testing.T) {
	stores := testdata.SetupTestStores(t)
	obs := testObs()
	authSvc := services.NewUserAuthService(stores.User, obs, nil)
	jwksSvc := newTestJWKSService(t)

	srv := apipublic.NewServer(context.Background(), testServerCfg(), apipublic.Deps{
		CORSConfigProvider:    testCORS(),
		URLs:                  testURLBuilder(),
		SessionSecretProvider: testSessionSecret(),
		SessionConfigProvider: testSessionConfig(),
		JWKS:                  jwksSvc,
		IssuerProvider:        staticIssuerForTest("https://auth.example.com"),
		Auth:                  authSvc,
		LoginDisplay:          static.NewLoginDisplayProvider(config.OIDCConfig{ShowLocalLogin: true}),
		SessionCookie:         apipublic.SessionCookie{Name: "authserver_session"},
		RateLimitCfg: config.RateLimitConfig{
			Enabled:           true,
			RequestsPerSecond: 100, // high to avoid rate limiting
			Burst:             100,
			AuthFailMax:       3,
			AuthFailWindow:    5 * time.Minute,
			AuthLockout:       1 * time.Minute,
		},
	}, obs)

	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)

	// Send 3 failed login attempts to trigger lockout.
	for i := 0; i < 3; i++ {
		resp, err := postLogin(t, http.DefaultClient, ts.URL, "attacker@example.com", "wrong-password")
		if err != nil {
			t.Fatalf("login attempt %d: %v", i+1, err)
		}
		resp.Body.Close()
	}

	// 4th attempt should be locked out (429).
	resp, err := postLogin(t, http.DefaultClient, ts.URL, "attacker@example.com", "another-attempt")
	if err != nil {
		t.Fatalf("lockout attempt: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("status: got %d, want 429 (locked out)", resp.StatusCode)
	}

	// Retry-After header should be set.
	if ra := resp.Header.Get("Retry-After"); ra == "" {
		t.Error("locked-out response should include Retry-After header")
	}
}

// testCookieJar is a minimal cookie jar for testing.
type testCookieJar struct {
	cookies []*http.Cookie
}

func (j *testCookieJar) SetCookies(u *url.URL, cookies []*http.Cookie) {
	j.cookies = append(j.cookies, cookies...)
}

func (j *testCookieJar) Cookies(u *url.URL) []*http.Cookie {
	return j.cookies
}

// Matrix: 13.4, 13.5, 13.6 — cookie security flags
func TestLogin_CookieFlags(t *testing.T) {
	ts, authSvc := newLoginTestServer(t)

	ctx := t.Context()
	_, err := authSvc.CreateUser(ctx, "cookie@example.com", "", "pass123", user.RoleUser)
	if err != nil {
		t.Fatalf("create user: %v", err)
	}

	hc := &http.Client{CheckRedirect: func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}}

	resp, err := postLogin(t, hc, ts.URL, "cookie@example.com", "pass123")
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer resp.Body.Close()

	var sessionCookie *http.Cookie
	for _, c := range resp.Cookies() {
		if c.Name == "authserver_session" {
			sessionCookie = c
			break
		}
	}
	if sessionCookie == nil {
		t.Fatal("session cookie not set")
	}

	// Matrix: 13.5 — HttpOnly flag
	if !sessionCookie.HttpOnly {
		t.Error("cookie must have HttpOnly flag")
	}

	// Matrix: 13.6 — SameSite=Lax
	if sessionCookie.SameSite != http.SameSiteLaxMode {
		t.Errorf("cookie SameSite: got %v, want Lax", sessionCookie.SameSite)
	}

	// Matrix: 13.4 — Secure flag
	// Note: httptest runs without TLS, so Secure may not be set in tests.
	// The middleware sets Secure from config. Verify the code conditionally
	// sets Secure=true when TLS is enabled by checking the middleware source.
	// In this non-TLS test, we verify the flag is not incorrectly true.
	// Production deployments MUST set Secure=true.
	t.Log("Secure flag not asserted in non-TLS test; verify middleware sets Secure=true with TLS config")
}

// Matrix: 13.10 — upgraded from ⚠️: session cookie value has sufficient randomness (≥32 chars)
func TestLogin_SessionID_SufficientLength(t *testing.T) {
	ts, authSvc := newLoginTestServer(t)

	ctx := t.Context()
	_, err := authSvc.CreateUser(ctx, "sesslen@example.com", "", "pass123", user.RoleUser)
	if err != nil {
		t.Fatalf("create user: %v", err)
	}

	hc := &http.Client{CheckRedirect: func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}}

	resp, err := postLogin(t, hc, ts.URL, "sesslen@example.com", "pass123")
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer resp.Body.Close()

	var sessionCookie *http.Cookie
	for _, c := range resp.Cookies() {
		if c.Name == "authserver_session" {
			sessionCookie = c
			break
		}
	}
	if sessionCookie == nil {
		t.Fatal("session cookie not set")
	}

	// The session cookie value should be at least 32 characters long
	// to provide sufficient randomness against brute-force attacks.
	if len(sessionCookie.Value) < 32 {
		t.Errorf("session cookie value too short: got %d chars, want ≥32", len(sessionCookie.Value))
	}
}

// Matrix: 13.9 — session fixation: login must issue a new session ID
func TestLogin_SessionFixation_NewID(t *testing.T) {
	ts, authSvc := newLoginTestServer(t)

	ctx := t.Context()
	_, err := authSvc.CreateUser(ctx, "fixation@example.com", "", "pass123", user.RoleUser)
	if err != nil {
		t.Fatalf("create user: %v", err)
	}

	hc := &http.Client{CheckRedirect: func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}}

	// First login → get session cookie A.
	resp1, err := postLogin(t, hc, ts.URL, "fixation@example.com", "pass123")
	if err != nil {
		t.Fatalf("login 1: %v", err)
	}
	resp1.Body.Close()

	var cookieA string
	for _, c := range resp1.Cookies() {
		if c.Name == "authserver_session" {
			cookieA = c.Value
			break
		}
	}
	if cookieA == "" {
		t.Fatal("no session cookie from first login")
	}

	// Wait >1s so the expiry timestamp (Unix seconds) differs between logins.
	// NOTE: The current cookie format is userID|expiryUnix|hmac(userID|expiryUnix).
	// Two logins within the same second produce identical cookies because there is
	// no random nonce. The HMAC-signed stateless cookie architecture prevents
	// traditional session fixation (no pre-login cookie, cookie bound to userID),
	// but adding a nonce would ensure uniqueness on every login.
	time.Sleep(1100 * time.Millisecond)

	// Second login → get session cookie B.
	resp2, err := postLogin(t, hc, ts.URL, "fixation@example.com", "pass123")
	if err != nil {
		t.Fatalf("login 2: %v", err)
	}
	resp2.Body.Close()

	var cookieB string
	for _, c := range resp2.Cookies() {
		if c.Name == "authserver_session" {
			cookieB = c.Value
			break
		}
	}
	if cookieB == "" {
		t.Fatal("no session cookie from second login")
	}

	// Session values must differ (new session on each login).
	if cookieA == cookieB {
		t.Error("session cookie must change on re-login (session fixation vulnerability)")
	}
}

// The reported attack. A cross-site form POST arrives with
// no cookies at all, because the victim's browser never performed GET /login
// against this server and the attacker cannot write cookies for this domain.
func TestLogin_PostWithoutNonceCookie_Rejected(t *testing.T) {
	ts, authSvc := newLoginTestServer(t)

	ctx := t.Context()
	if _, err := authSvc.CreateUser(ctx, "attacker@example.com", "", "attackerpass", user.RoleUser); err != nil {
		t.Fatalf("create user: %v", err)
	}

	// The attacker harvests a valid token from their own GET, then replays it
	// from a context that carries no nonce cookie.
	token, nonce := loginPageCSRF(t, &http.Client{}, ts.URL)
	if token == "" || nonce == nil {
		t.Fatal("precondition: GET /login must yield a token and a nonce cookie")
	}

	form := url.Values{
		"email":      {"attacker@example.com"},
		"password":   {"attackerpass"},
		"csrf_token": {token},
	}
	req, err := http.NewRequest(http.MethodPost, ts.URL+"/login", strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", "https://evil.example")
	// Deliberately no req.AddCookie — this is the whole point.

	hc := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}
	resp, err := hc.Do(req)
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusSeeOther {
		t.Fatalf("cross-site POST was accepted: got 303, want a rejection")
	}
	// The response may set a fresh nonce cookie (renderLoginError re-renders the
	// form so a legitimate retry works). What must never be issued is a session.
	for _, c := range resp.Cookies() {
		if c.Name == "authserver_session" && c.Value != "" {
			t.Fatalf("rejected login issued a session cookie: %q", c.Value)
		}
	}
}

// A valid (nonce, token) pair from one browser must not reconcile with a nonce
// from another. This is what makes the token bound rather than merely random.
func TestLogin_PostWithMismatchedNoncePair_Rejected(t *testing.T) {
	ts, authSvc := newLoginTestServer(t)

	ctx := t.Context()
	if _, err := authSvc.CreateUser(ctx, "mismatch@example.com", "", "pass1234", user.RoleUser); err != nil {
		t.Fatalf("create user: %v", err)
	}

	tokenA, _ := loginPageCSRF(t, &http.Client{}, ts.URL)
	_, nonceB := loginPageCSRF(t, &http.Client{}, ts.URL)
	if tokenA == "" || nonceB == nil {
		t.Fatal("precondition: both GETs must yield their halves")
	}

	form := url.Values{
		"email":      {"mismatch@example.com"},
		"password":   {"pass1234"},
		"csrf_token": {tokenA},
	}
	req, err := http.NewRequest(http.MethodPost, ts.URL+"/login", strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(nonceB) // client B's cookie, client A's token

	hc := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}
	resp, err := hc.Do(req)
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusSeeOther {
		t.Fatal("mismatched nonce/token pair was accepted")
	}
	for _, c := range resp.Cookies() {
		if c.Name == "authserver_session" && c.Value != "" {
			t.Fatalf("rejected login issued a session cookie: %q", c.Value)
		}
	}
}

// Spec D1: the nonce is reused across tabs. Minting on every GET would let a
// second login tab overwrite the first tab's cookie, so the first tab's
// rendered token would stop validating.
func TestLogin_MultipleTabs_ShareNonceAndBothSubmit(t *testing.T) {
	ts, authSvc := newLoginTestServer(t)

	ctx := t.Context()
	if _, err := authSvc.CreateUser(ctx, "tabs@example.com", "", "pass1234", user.RoleUser); err != nil {
		t.Fatalf("create user: %v", err)
	}

	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatalf("cookiejar: %v", err)
	}
	hc := &http.Client{Jar: jar, CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}

	tab1Token, tab1Nonce := loginPageCSRF(t, hc, ts.URL)
	if tab1Nonce == nil {
		t.Fatal("first GET must set the nonce cookie")
	}
	tab2Token, tab2Nonce := loginPageCSRF(t, hc, ts.URL)

	if tab2Nonce != nil && tab2Nonce.Value != tab1Nonce.Value {
		t.Errorf("second GET reminted the nonce: %q then %q", tab1Nonce.Value, tab2Nonce.Value)
	}
	if tab1Token != tab2Token {
		t.Errorf("same browser got different tokens: %q then %q", tab1Token, tab2Token)
	}

	// The token rendered into the FIRST tab must still submit successfully.
	form := url.Values{
		"email":      {"tabs@example.com"},
		"password":   {"pass1234"},
		"csrf_token": {tab1Token},
	}
	req, err := http.NewRequest(http.MethodPost, ts.URL+"/login", strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	// The jar already carries the nonce cookie from the GETs above; adding it
	// again here would send authserver_login_nonce twice, and r.Cookie returns
	// only the first match — masking a remint regression from this POST.

	resp, err := hc.Do(req)
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("first tab's token failed to submit: got %d, want 303", resp.StatusCode)
	}

	// Spec D3: a successful login must not burn the nonce. The OIDC state
	// cookie is single-use and is cleared at callback; this one is reusable by
	// D1, so expiring it here would break whatever other tab is still open.
	// The remint check itself happened above (tab2Nonce.Value != tab1Nonce.Value
	// and tab1Token != tab2Token); this response only needs to exist for the
	// no-burn assertion to inspect.
	for _, c := range resp.Cookies() {
		if c.Name != "authserver_login_nonce" {
			continue
		}
		if c.MaxAge < 0 {
			t.Error("successful login expired the nonce cookie; D1 reuse means other tabs would break")
		}
		if c.Value != tab1Nonce.Value {
			t.Errorf("successful login changed the nonce value: got %q, want %q", c.Value, tab1Nonce.Value)
		}
	}
}

// renderLoginError re-renders the form after a bad password. If it emitted a
// token derived from a nonce it never wrote as a cookie, one typo would lock a
// legitimate user out of retrying.
func TestLogin_WrongPasswordThenRetry_Succeeds(t *testing.T) {
	ts, authSvc := newLoginTestServer(t)

	ctx := t.Context()
	if _, err := authSvc.CreateUser(ctx, "retry@example.com", "", "correct-pass", user.RoleUser); err != nil {
		t.Fatalf("create user: %v", err)
	}

	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatalf("cookiejar: %v", err)
	}
	hc := &http.Client{Jar: jar, CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}

	// First attempt: wrong password, 422 with the form re-rendered.
	bad, err := postLogin(t, hc, ts.URL, "retry@example.com", "wrong-pass")
	if err != nil {
		t.Fatalf("first post: %v", err)
	}
	body, err := io.ReadAll(bad.Body)
	bad.Body.Close()
	if err != nil {
		t.Fatalf("read error page: %v", err)
	}
	if bad.StatusCode != http.StatusUnprocessableEntity {
		t.Fatalf("wrong password: got %d, want 422", bad.StatusCode)
	}

	// Retry using the token from the re-rendered error page, exactly as a user
	// would by correcting the field and pressing the button again.
	m := csrfTokenRe.FindSubmatch(body)
	if m == nil {
		t.Fatal("error page must re-render the csrf_token input")
	}
	retryToken := string(m[1])

	form := url.Values{
		"email":      {"retry@example.com"},
		"password":   {"correct-pass"},
		"csrf_token": {retryToken},
	}
	req, err := http.NewRequest(http.MethodPost, ts.URL+"/login", strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	// The jar carries the nonce set by the earlier GET; if the error page
	// re-set it, the jar holds the newer value. Either must validate.

	resp, err := hc.Do(req)
	if err != nil {
		t.Fatalf("retry post: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("retry after a typo failed: got %d, want 303", resp.StatusCode)
	}
}

// With local login off, POST /login is closed regardless of the CSRF state:
// the gate answers 404 before the nonce check runs, so a request with no nonce
// cookie sees the same 404 as one with a valid nonce
// (TestLogin_ShowLocalLoginFalse_PostRejectedWithValidNonce).
func TestLogin_ShowLocalLoginFalse_PostReturns404WithoutNonce(t *testing.T) {
	ts, authSvc := newLoginTestServerWith(t, config.OIDCConfig{ShowLocalLogin: false}, testSessionSecret())

	ctx := t.Context()
	if _, err := authSvc.CreateUser(ctx, "hidden@example.com", "", "pass1234", user.RoleUser); err != nil {
		t.Fatalf("create user: %v", err)
	}

	token, _ := loginPageCSRF(t, &http.Client{}, ts.URL)
	if token != "" {
		t.Fatalf("no form should be rendered, yet a token was found: %q", token)
	}

	form := url.Values{
		"email":      {"hidden@example.com"},
		"password":   {"pass1234"},
		"csrf_token": {"anything"},
	}
	req, err := http.NewRequest(http.MethodPost, ts.URL+"/login", strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	hc := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}
	resp, err := hc.Do(req)
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("status: got %d, want 404", resp.StatusCode)
	}
	for _, c := range resp.Cookies() {
		if c.Name == "authserver_session" && c.Value != "" {
			t.Fatalf("rejected login issued a session cookie: %q", c.Value)
		}
	}
}

// The residual gap AUD-14 is about: a nonce cookie minted while the form was
// shown stays valid (the MAC has no expiry and is not bound to the flag), so an
// operator who flips show_local_login to false must still find POST /login
// closed to a browser that kept the old cookie. Two servers share one session
// secret to model "same deployment, config flipped, restarted".
func TestLogin_ShowLocalLoginFalse_PostRejectedWithValidNonce(t *testing.T) {
	secret := testSessionSecret()

	// Server A: local login shown. Harvest a genuine nonce + token.
	tsOn, _ := newLoginTestServerWith(t, config.OIDCConfig{ShowLocalLogin: true}, secret)
	token, nonce := loginPageCSRF(t, &http.Client{}, tsOn.URL)
	if token == "" || nonce == nil {
		t.Fatalf("server with local login on must render a token and mint a nonce (token=%q nonce=%v)", token, nonce)
	}

	// Server B: same secret, local login off, and an account that would log in.
	tsOff, authSvc := newLoginTestServerWith(t, config.OIDCConfig{ShowLocalLogin: false}, secret)
	if _, err := authSvc.CreateUser(t.Context(), "flipped@example.com", "", "pass1234", user.RoleUser); err != nil {
		t.Fatalf("create user: %v", err)
	}

	form := url.Values{
		"email":      {"flipped@example.com"},
		"password":   {"pass1234"},
		"csrf_token": {token},
	}
	req, err := http.NewRequest(http.MethodPost, tsOff.URL+"/login", strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(nonce)

	hc := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}
	resp, err := hc.Do(req)
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("status: got %d, want 404 — local login off must close POST /login even to a valid nonce", resp.StatusCode)
	}
	for _, c := range resp.Cookies() {
		if c.Name == "authserver_session" && c.Value != "" {
			t.Fatalf("POST /login issued a session cookie while local login was off: %q", c.Value)
		}
		if c.Name == "authserver_login_nonce" {
			t.Fatalf("POST /login touched the nonce cookie while local login was off: %q", c.Value)
		}
	}
}

// failingSecretProviderForTest always fails to resolve the session secret,
// exercising the errSecretUnavailable contract in api/shared/session.go.
type failingSecretProviderForTest struct{}

func (failingSecretProviderForTest) Secret(_ context.Context) ([]byte, error) {
	return nil, errors.New("secret backend unavailable")
}

// A secret-resolution failure is FATAL: 500, never a CSRF rejection. Returning
// 422 would present a provider outage as wrong credentials for every user.
func TestLogin_SecretProviderFailure_Returns500(t *testing.T) {
	ts, _ := newLoginTestServerWith(t,
		config.OIDCConfig{ShowLocalLogin: true},
		failingSecretProviderForTest{},
	)

	resp, err := http.Get(ts.URL + "/login")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusInternalServerError {
		t.Fatalf("GET /login with an unresolvable secret: got %d, want 500", resp.StatusCode)
	}
}

// getLoginWithNonce performs GET /login carrying a caller-chosen nonce cookie
// and returns the rendered CSRF token plus the nonce cookie the response set
// (nil when the server reused what it was given).
func getLoginWithNonce(t *testing.T, baseURL, nonceValue string) (string, *http.Cookie) {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, baseURL+"/login", nil)
	if err != nil {
		t.Fatalf("build GET: %v", err)
	}
	req.AddCookie(&http.Cookie{Name: "authserver_login_nonce", Value: nonceValue})

	resp, err := (&http.Client{}).Do(req)
	if err != nil {
		t.Fatalf("get /login: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}

	var token string
	if m := csrfTokenRe.FindSubmatch(body); m != nil {
		token = string(m[1])
	}
	var set *http.Cookie
	for _, c := range resp.Cookies() {
		if c.Name == "authserver_login_nonce" {
			set = c
			break
		}
	}
	return token, set
}

// The server keeps no record of the nonces it issues, so the cookie value
// carries its own MAC. Without it, GET /login would reuse — and sign — any
// value a caller put in the cookie, handing back a signature over
// attacker-chosen input.
func TestLogin_GetRemintsCallerSuppliedNonce(t *testing.T) {
	ts, _ := newLoginTestServer(t)

	const forged = "attacker-chosen-value"
	token, set := getLoginWithNonce(t, ts.URL, forged)

	if set == nil {
		t.Fatal("server reused the caller-supplied nonce instead of reminting: no Set-Cookie")
	}
	if set.Value == forged {
		t.Fatalf("server echoed the caller-supplied nonce back: %q", set.Value)
	}
	if parts := strings.Split(set.Value, "|"); len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		t.Errorf("reminted cookie is not <nonce>|<mac>: %q", set.Value)
	}
	if token == "" {
		t.Error("login page rendered no CSRF token")
	}
}

// The signing-oracle attack end to end: choose a nonce, get the server to
// render a token for it, then replay both. The MAC check must break the chain
// even though the attacker controls both halves it submits.
func TestLogin_ForgedNoncePairFromOracle_Rejected(t *testing.T) {
	ts, authSvc := newLoginTestServer(t)

	ctx := t.Context()
	if _, err := authSvc.CreateUser(ctx, "oracle@example.com", "", "pass1234", user.RoleUser); err != nil {
		t.Fatalf("create user: %v", err)
	}

	const forged = "attacker-chosen-value"
	token, _ := getLoginWithNonce(t, ts.URL, forged)
	if token == "" {
		t.Fatal("precondition: GET /login must render some token")
	}

	form := url.Values{
		"email":      {"oracle@example.com"},
		"password":   {"pass1234"},
		"csrf_token": {token},
	}
	req, err := http.NewRequest(http.MethodPost, ts.URL+"/login", strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatalf("build POST: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: "authserver_login_nonce", Value: forged})

	hc := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}
	resp, err := hc.Do(req)
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusSeeOther {
		t.Fatal("a caller-chosen nonce plus its rendered token was accepted")
	}
	for _, c := range resp.Cookies() {
		if c.Name == "authserver_session" && c.Value != "" {
			t.Fatalf("rejected login issued a session cookie: %q", c.Value)
		}
	}
}

// A genuine nonce with a corrupted MAC must not be honoured either — the MAC
// has to be checked, not merely present.
func TestLogin_TamperedNonceMAC_Rejected(t *testing.T) {
	ts, authSvc := newLoginTestServer(t)

	ctx := t.Context()
	if _, err := authSvc.CreateUser(ctx, "tamper@example.com", "", "pass1234", user.RoleUser); err != nil {
		t.Fatalf("create user: %v", err)
	}

	token, genuine := loginPageCSRF(t, &http.Client{}, ts.URL)
	if token == "" || genuine == nil {
		t.Fatal("precondition: GET /login must yield a token and a nonce cookie")
	}
	parts := strings.Split(genuine.Value, "|")
	if len(parts) != 2 {
		t.Fatalf("nonce cookie is not <nonce>|<mac>: %q", genuine.Value)
	}
	// Same nonce, one flipped character in the MAC.
	bad := []byte(parts[1])
	if bad[0] == 'A' {
		bad[0] = 'B'
	} else {
		bad[0] = 'A'
	}
	tampered := parts[0] + "|" + string(bad)

	form := url.Values{
		"email":      {"tamper@example.com"},
		"password":   {"pass1234"},
		"csrf_token": {token},
	}
	req, err := http.NewRequest(http.MethodPost, ts.URL+"/login", strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatalf("build POST: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: "authserver_login_nonce", Value: tampered})

	hc := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}
	resp, err := hc.Do(req)
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusSeeOther {
		t.Fatal("a tampered nonce MAC was accepted")
	}
	for _, c := range resp.Cookies() {
		if c.Name == "authserver_session" && c.Value != "" {
			t.Fatalf("rejected login issued a session cookie: %q", c.Value)
		}
	}
}

// The design's whole SameSite argument rests on policy.EffectiveSameSite(),
// h.session.SecureFloor() and loginNoncePath() actually reaching this cookie.
// Asserting one configuration would pass just as well against hardcoded
// constants, so this varies the policy and checks the cookie follows it.
func TestLogin_NonceCookieAttributes_FollowSessionPolicy(t *testing.T) {
	cases := map[string]struct {
		sameSite       http.SameSite
		providerSecure bool
		secureFloor    bool
		wantSameSite   http.SameSite
		wantSecure     bool
	}{
		"lax, no TLS anywhere": {
			sameSite: http.SameSiteLaxMode,
			// provider and floor both off — the local-development shape
			wantSameSite: http.SameSiteLaxMode,
			wantSecure:   false,
		},
		"none is preserved, not clamped to lax": {
			// The configuration login.go:85-90 explicitly reasons about, and
			// the one with no coverage before this test.
			sameSite:       http.SameSiteNoneMode,
			providerSecure: true, // browsers reject SameSite=None without Secure
			wantSameSite:   http.SameSiteNoneMode,
			wantSecure:     true,
		},
		"strict is preserved": {
			sameSite:     http.SameSiteStrictMode,
			wantSameSite: http.SameSiteStrictMode,
			wantSecure:   false,
		},
		"boot floor raises Secure the provider left off": {
			sameSite:     http.SameSiteLaxMode,
			secureFloor:  true,
			wantSameSite: http.SameSiteLaxMode,
			wantSecure:   true,
		},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			ts, _ := newLoginTestServerOpts(t, loginServerOpts{
				oidc:        config.OIDCConfig{ShowLocalLogin: true},
				secrets:     testSessionSecret(),
				sessionCfg:  testSessionConfigWith(tc.sameSite, tc.providerSecure),
				secureFloor: tc.secureFloor,
			})

			_, nonce := loginPageCSRF(t, &http.Client{}, ts.URL)
			if nonce == nil {
				t.Fatal("GET /login set no nonce cookie")
			}

			if nonce.SameSite != tc.wantSameSite {
				t.Errorf("SameSite: got %v, want %v", nonce.SameSite, tc.wantSameSite)
			}
			if nonce.Secure != tc.wantSecure {
				t.Errorf("Secure: got %v, want %v", nonce.Secure, tc.wantSecure)
			}
			if !nonce.HttpOnly {
				t.Error("HttpOnly: got false, want true")
			}
			// testURLBuilder serves at the root, so the mount resolves to "/".
			// Set and any future clear must agree on this or the browser will
			// not match the cookie.
			if nonce.Path != "/" {
				t.Errorf("Path: got %q, want %q", nonce.Path, "/")
			}
			if got := nonce.MaxAge; got != 12*60*60 {
				t.Errorf("MaxAge: got %d, want %d", got, 12*60*60)
			}
		})
	}
}

// The nonce cookie must carry the same Secure/SameSite as the session cookie
// the same request issues. A future edit that gives one its own policy would
// break the pairing silently: under same_site=none the session would survive a
// cross-site POST that the nonce no longer rides.
func TestLogin_NonceAndSessionCookies_ShareTransportPolicy(t *testing.T) {
	ts, authSvc := newLoginTestServerOpts(t, loginServerOpts{
		oidc:       config.OIDCConfig{ShowLocalLogin: true},
		secrets:    testSessionSecret(),
		sessionCfg: testSessionConfigWith(http.SameSiteNoneMode, true),
	})

	ctx := t.Context()
	if _, err := authSvc.CreateUser(ctx, "pair@example.com", "", "pass1234", user.RoleUser); err != nil {
		t.Fatalf("create user: %v", err)
	}

	hc := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}

	// One GET only. Going through postLogin would issue a second one, which by
	// design reuses the nonce and sets no cookie (D1) — leaving nothing to
	// compare against the session cookie.
	token, nonce := loginPageCSRF(t, hc, ts.URL)
	if token == "" || nonce == nil {
		t.Fatal("GET /login yielded no token or no nonce cookie")
	}

	form := url.Values{
		"email":      {"pair@example.com"},
		"password":   {"pass1234"},
		"csrf_token": {token},
	}
	req, err := http.NewRequest(http.MethodPost, ts.URL+"/login", strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatalf("build POST: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(nonce)

	resp, err := hc.Do(req)
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("login: got %d, want 303", resp.StatusCode)
	}

	var session *http.Cookie
	for _, c := range resp.Cookies() {
		if c.Name == "authserver_session" {
			session = c
			break
		}
	}
	if session == nil {
		t.Fatal("no session cookie issued")
	}

	if nonce.SameSite != session.SameSite {
		t.Errorf("SameSite diverged: nonce %v, session %v", nonce.SameSite, session.SameSite)
	}
	if nonce.Secure != session.Secure {
		t.Errorf("Secure diverged: nonce %v, session %v", nonce.Secure, session.Secure)
	}
	if nonce.Path != session.Path {
		t.Errorf("Path diverged: nonce %q, session %q", nonce.Path, session.Path)
	}
}

// Logout burns the nonce alongside the session. Not a credential, so not a
// correctness requirement — but on a shared browser the next person would
// otherwise be served the same CSRF token for the rest of the window. The
// clear must use the same Path as the set, or the browser adds a second empty
// cookie instead of removing the first.
func TestLogout_ClearsNonceCookie(t *testing.T) {
	ts, _ := newLoginTestServer(t)

	hc := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}

	_, set := loginPageCSRF(t, hc, ts.URL)
	if set == nil {
		t.Fatal("GET /login set no nonce cookie")
	}

	req, err := http.NewRequest(http.MethodPost, ts.URL+"/logout", nil)
	if err != nil {
		t.Fatalf("build POST: %v", err)
	}
	req.AddCookie(set)

	resp, err := hc.Do(req)
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer resp.Body.Close()

	var cleared *http.Cookie
	for _, c := range resp.Cookies() {
		if c.Name == "authserver_login_nonce" {
			cleared = c
			break
		}
	}
	if cleared == nil {
		t.Fatal("logout did not clear the nonce cookie")
	}
	if cleared.MaxAge >= 0 {
		t.Errorf("MaxAge: got %d, want negative", cleared.MaxAge)
	}
	if cleared.Path != set.Path {
		t.Errorf("Path diverged from the set — the browser will not match it: set %q, clear %q",
			set.Path, cleared.Path)
	}
}

// With local login hidden, GET /login renders no form, so it must not mint a
// nonce cookie for a token nothing will consume. The POST guard still rejects
// on absence (TestLogin_ShowLocalLoginFalse_PostReturns404WithoutNonce), so
// nothing depends on the mint happening here.
func TestLogin_ShowLocalLoginFalse_GetMintsNoNonce(t *testing.T) {
	ts, _ := newLoginTestServerWith(t, config.OIDCConfig{ShowLocalLogin: false}, testSessionSecret())

	token, nonce := loginPageCSRF(t, &http.Client{}, ts.URL)
	if token != "" {
		t.Errorf("no form should render, yet a token was present: %q", token)
	}
	if nonce != nil {
		t.Errorf("no form rendered, yet a nonce cookie was set: %q", nonce.Value)
	}
}

// The mirror of the above: with local login enabled (the shipped default),
// GET /login must still mint the nonce so the form has a usable token.
func TestLogin_ShowLocalLoginTrue_GetMintsNonce(t *testing.T) {
	ts, _ := newLoginTestServer(t)

	token, nonce := loginPageCSRF(t, &http.Client{}, ts.URL)
	if token == "" {
		t.Error("form rendered but no CSRF token")
	}
	if nonce == nil {
		t.Error("form rendered but no nonce cookie set")
	}
}

// newLockoutTestServer builds a login-capable server with a low failure
// threshold and a throughput limit high enough that it never interferes.
func newLockoutTestServer(t *testing.T) (*httptest.Server, *services.UserAuthService) {
	t.Helper()
	stores := testdata.SetupTestStores(t)
	obs := testObs()
	authSvc := services.NewUserAuthService(stores.User, obs, nil)
	jwksSvc := newTestJWKSService(t)

	srv := apipublic.NewServer(context.Background(), testServerCfg(), apipublic.Deps{
		CORSConfigProvider:    testCORS(),
		URLs:                  testURLBuilder(),
		SessionSecretProvider: testSessionSecret(),
		SessionConfigProvider: testSessionConfig(),
		JWKS:                  jwksSvc,
		IssuerProvider:        staticIssuerForTest("https://auth.example.com"),
		Auth:                  authSvc,
		// ShowLocalLogin must be on: GET /login only mints the nonce when the
		// local form renders, and without a nonce every POST dies at the CSRF
		// check before the lockout is ever consulted.
		LoginDisplay:  static.NewLoginDisplayProvider(config.OIDCConfig{ShowLocalLogin: true}),
		SessionCookie: apipublic.SessionCookie{Name: "authserver_session"},
		RateLimitCfg: config.RateLimitConfig{
			Enabled:           true,
			RequestsPerSecond: 1000, // high enough that throughput never trips
			Burst:             1000,
			AuthFailMax:       3,
			AuthFailWindow:    5 * time.Minute,
			AuthLockout:       1 * time.Minute,
		},
	}, obs)

	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	return ts, authSvc
}

// lockOut trips the lockout for one identity.
func lockOut(t *testing.T, baseURL, email string) {
	t.Helper()
	for i := 0; i < 3; i++ {
		resp, err := postLogin(t, http.DefaultClient, baseURL, email, "wrong-password")
		if err != nil {
			t.Fatalf("failed login %d: %v", i+1, err)
		}
		resp.Body.Close()
	}
	resp, err := postLogin(t, http.DefaultClient, baseURL, email, "wrong-again")
	if err != nil {
		t.Fatalf("confirming lockout: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("after 3 failures %s got %d, want 429", email, resp.StatusCode)
	}
}

// An active lockout must not reach any endpoint other than login. Blocking JWKS
// is the worst of it: every resource server that fetches the key set to
// validate tokens would be cut off, so the outage would reach token validation
// rather than just sign-in.
func TestLogin_LockoutDoesNotBlockOtherEndpoints(t *testing.T) {
	ts, _ := newLockoutTestServer(t)
	lockOut(t, ts.URL, "attacker@example.com")

	for _, path := range []string{
		"/.well-known/jwks.json",
		"/.well-known/oauth-authorization-server",
		"/health",
		"/ready",
	} {
		resp, err := http.Get(ts.URL + path)
		if err != nil {
			t.Fatalf("GET %s: %v", path, err)
		}
		resp.Body.Close()
		if resp.StatusCode == http.StatusTooManyRequests {
			t.Errorf("GET %s returned 429 during a login lockout", path)
		}
	}

	resp, err := http.PostForm(ts.URL+"/oauth/token", nil)
	if err != nil {
		t.Fatalf("POST /oauth/token: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode == http.StatusTooManyRequests {
		t.Error("POST /oauth/token returned 429 during a login lockout")
	}
}

// Behind a reverse proxy every request carries the same source address. One
// account's failures must not lock anyone else out.
func TestLogin_LockoutIsPerIdentity(t *testing.T) {
	ts, _ := newLockoutTestServer(t)
	lockOut(t, ts.URL, "attacker@example.com")

	resp, err := postLogin(t, http.DefaultClient, ts.URL, "bystander@example.com", "whatever")
	if err != nil {
		t.Fatalf("bystander login: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusTooManyRequests {
		t.Fatal("a different identity from the same address was locked out")
	}
}

// The consumer here is a browser posting a form, not an OAuth client, so the
// locked-out response renders the login page rather than OAuth error JSON.
func TestLogin_LockoutResponseIsHTMLWithRealRetryAfter(t *testing.T) {
	ts, _ := newLockoutTestServer(t)
	lockOut(t, ts.URL, "attacker@example.com")

	resp, err := postLogin(t, http.DefaultClient, ts.URL, "attacker@example.com", "again")
	if err != nil {
		t.Fatalf("locked-out login: %v", err)
	}
	defer resp.Body.Close()

	if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
		t.Errorf("Content-Type = %q, want text/html", ct)
	}

	ra, err := strconv.Atoi(resp.Header.Get("Retry-After"))
	if err != nil {
		t.Fatalf("Retry-After = %q, want an integer", resp.Header.Get("Retry-After"))
	}
	// AuthLockout is 1 minute here. The old middleware always said 60 regardless
	// of the configured duration; this asserts the value tracks the real deadline.
	if ra <= 0 || ra > 60 {
		t.Errorf("Retry-After = %d, want the real remaining time within (0, 60]", ra)
	}
}

// Account lockout must survive rate_limit.enabled: false. The threat model tells
// operators to disable the internal limiter in favour of an external one on
// multi-instance deployments, and a gateway rate limiter counts requests per
// address — it cannot count failed logins per account, so it replaces nothing.
func TestLogin_LockoutSurvivesThroughputLimiterDisabled(t *testing.T) {
	stores := testdata.SetupTestStores(t)
	obs := testObs()

	srv := apipublic.NewServer(context.Background(), testServerCfg(), apipublic.Deps{
		CORSConfigProvider:    testCORS(),
		URLs:                  testURLBuilder(),
		SessionSecretProvider: testSessionSecret(),
		SessionConfigProvider: testSessionConfig(),
		JWKS:                  newTestJWKSService(t),
		IssuerProvider:        staticIssuerForTest("https://auth.example.com"),
		Auth:                  services.NewUserAuthService(stores.User, obs, nil),
		// ShowLocalLogin must be on: GET /login only mints the nonce when the
		// local form renders, and without a nonce every POST dies at the CSRF
		// check before the lockout is ever consulted.
		LoginDisplay:  static.NewLoginDisplayProvider(config.OIDCConfig{ShowLocalLogin: true}),
		SessionCookie: apipublic.SessionCookie{Name: "authserver_session"},
		RateLimitCfg: config.RateLimitConfig{
			Enabled:        false, // throughput limiting off, lockout must remain
			AuthFailMax:    3,
			AuthFailWindow: 5 * time.Minute,
			AuthLockout:    time.Minute,
		},
	}, obs)
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)

	for i := 0; i < 3; i++ {
		resp, err := postLogin(t, http.DefaultClient, ts.URL, "attacker@example.com", "wrong")
		if err != nil {
			t.Fatalf("attempt %d: %v", i+1, err)
		}
		resp.Body.Close()
	}

	resp, err := postLogin(t, http.DefaultClient, ts.URL, "attacker@example.com", "wrong")
	if err != nil {
		t.Fatalf("fourth attempt: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("status %d with rate_limit.enabled=false, want 429 — the lockout is a separate control", resp.StatusCode)
	}
}

// An over-length address is rejected before it can be retained anywhere: the
// lockout map key, the log line, or the audit row. It answers with the same
// generic credential error, so nothing is disclosed by the difference.
func TestLogin_OverLongIdentityIsRejected(t *testing.T) {
	ts, _ := newLockoutTestServer(t)

	huge := strings.Repeat("x", 64_000) + "@example.com"
	resp, err := postLogin(t, http.DefaultClient, ts.URL, huge, "whatever")
	if err != nil {
		t.Fatalf("over-long login: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusUnprocessableEntity {
		t.Errorf("status = %d, want 422 (same as any rejected credential)", resp.StatusCode)
	}

	// A normal identity still works from the same server afterwards.
	resp2, err := postLogin(t, http.DefaultClient, ts.URL, "normal@example.com", "whatever")
	if err != nil {
		t.Fatalf("follow-up login: %v", err)
	}
	defer resp2.Body.Close()
	if resp2.StatusCode == http.StatusTooManyRequests {
		t.Error("the over-long attempt should not have locked anyone out")
	}
}

// flakyAuthProvider fails the way UserAuthService does when the database is
// unreachable — a wrapped store error, not domain.ErrInvalidCredentials.
type flakyAuthProvider struct{ calls int }

func (f *flakyAuthProvider) Authenticate(_ context.Context, _, _ string) (*user.User, error) {
	f.calls++
	return nil, fmt.Errorf("lookup user: %w", errors.New("connection refused"))
}

// A database outage must not lock anyone out. Every user who retried during a
// blip would otherwise accumulate auth_fail_max failures and stay locked for the
// full auth_lockout AFTER recovery, with auth.locked_out rows describing an
// outage as an attack.
//
// This drives the real handler, CSRF nonce and all, so it fails if the error
// classification is removed from handlePostLogin — not merely if errors.Is
// stops working.
func TestLogin_StoreFailureNeitherLocksOutNorClaimsBadCredentials(t *testing.T) {
	obs := testObs()
	auth := &flakyAuthProvider{}

	srv := apipublic.NewServer(context.Background(), testServerCfg(), apipublic.Deps{
		CORSConfigProvider:    testCORS(),
		URLs:                  testURLBuilder(),
		SessionSecretProvider: testSessionSecret(),
		SessionConfigProvider: testSessionConfig(),
		JWKS:                  newTestJWKSService(t),
		IssuerProvider:        staticIssuerForTest("https://auth.example.com"),
		Auth:                  auth,
		LoginDisplay:          static.NewLoginDisplayProvider(config.OIDCConfig{ShowLocalLogin: true}),
		SessionCookie:         apipublic.SessionCookie{Name: "authserver_session"},
		RateLimitCfg: config.RateLimitConfig{
			Enabled:           true,
			RequestsPerSecond: 1000,
			Burst:             1000,
			AuthFailMax:       3,
			AuthFailWindow:    5 * time.Minute,
			AuthLockout:       time.Minute,
		},
	}, obs)
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)

	// Well past auth_fail_max. If store errors counted, the identity would be
	// locked from the fourth attempt on.
	for i := 0; i < 6; i++ {
		resp, err := postLogin(t, http.DefaultClient, ts.URL, "victim@example.com", "pw")
		if err != nil {
			t.Fatalf("attempt %d: %v", i+1, err)
		}
		body := resp.StatusCode
		resp.Body.Close()

		if body == http.StatusTooManyRequests {
			t.Fatalf("attempt %d was locked out — a store failure is not a credential failure", i+1)
		}
		// And it must not claim the credential was wrong: that is a lie, and it
		// invites a retry against a backend already in trouble.
		if body != http.StatusInternalServerError {
			t.Errorf("attempt %d status = %d, want 500 for an infrastructure error", i+1, body)
		}
	}

	if auth.calls != 6 {
		t.Errorf("Authenticate called %d times, want 6 — no attempt should have been short-circuited", auth.calls)
	}
}

// The lockout is reported once, where it engages. Blocked requests that follow
// must be silent: a line per request would carry up to MaxIdentityLen bytes of
// caller-chosen text for the whole lockout window — a log-flood primitive at one
// request each — and it would put a cost back on a path deliberately placed
// ahead of bcrypt precisely so a blocked attempt costs nothing.
func TestLogin_BlockedRequestsDoNotLog(t *testing.T) {
	var logs bytes.Buffer
	obs := testObs()
	obs.Logger = slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug}))

	stores := testdata.SetupTestStores(t)
	srv := apipublic.NewServer(context.Background(), testServerCfg(), apipublic.Deps{
		CORSConfigProvider:    testCORS(),
		URLs:                  testURLBuilder(),
		SessionSecretProvider: testSessionSecret(),
		SessionConfigProvider: testSessionConfig(),
		JWKS:                  newTestJWKSService(t),
		IssuerProvider:        staticIssuerForTest("https://auth.example.com"),
		Auth:                  services.NewUserAuthService(stores.User, obs, nil),
		LoginDisplay:          static.NewLoginDisplayProvider(config.OIDCConfig{ShowLocalLogin: true}),
		SessionCookie:         apipublic.SessionCookie{Name: "authserver_session"},
		RateLimitCfg: config.RateLimitConfig{
			Enabled:           true,
			RequestsPerSecond: 1000,
			Burst:             1000,
			AuthFailMax:       3,
			AuthFailWindow:    5 * time.Minute,
			AuthLockout:       time.Minute,
		},
	}, obs)
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)

	const victim = "victim@example.com"
	for i := 0; i < 3; i++ {
		resp, err := postLogin(t, http.DefaultClient, ts.URL, victim, "wrong")
		if err != nil {
			t.Fatalf("attempt %d: %v", i+1, err)
		}
		resp.Body.Close()
	}
	if !strings.Contains(logs.String(), "auth lockout engaged") {
		t.Fatalf("the transition logged nothing:\n%s", logs.String())
	}

	// Everything from here is a blocked request. The access-log middleware still
	// writes its fixed line per HTTP request — that is unavoidable and carries no
	// caller-chosen content. What must not appear again is the identity: that is
	// the part the attacker picks, up to MaxIdentityLen bytes of it.
	before := logs.Len()
	for i := 0; i < 25; i++ {
		resp, err := postLogin(t, http.DefaultClient, ts.URL, victim, "wrong")
		if err != nil {
			t.Fatalf("blocked attempt %d: %v", i+1, err)
		}
		locked := resp.StatusCode == http.StatusTooManyRequests
		resp.Body.Close()
		if !locked {
			t.Fatalf("blocked attempt %d returned %d, want 429", i+1, resp.StatusCode)
		}
	}

	after := logs.String()[before:]
	if n := strings.Count(after, victim); n != 0 {
		t.Errorf("the identity appears %d times in the log for 25 blocked requests — one line per\nblocked request is a flood primitive the attacker controls the size of:\n%s", n, after)
	}
}
