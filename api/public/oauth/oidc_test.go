package oauth

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/authplane/authserver/api/shared"
	"github.com/authplane/authserver/internal/adapters/static"
	"github.com/authplane/authserver/internal/domain"
	"github.com/authplane/authserver/internal/domain/user"
	"github.com/authplane/authserver/internal/observability"
	"github.com/authplane/authserver/internal/ports/output"
)

// failingCodec returns the configured error from Encode/Decode and is
// used to exercise the handler's 500/400 paths.
type failingCodec struct{ err error }

func (f *failingCodec) Encode(_ context.Context, _ output.State) ([]byte, error) {
	return nil, f.err
}
func (f *failingCodec) Decode(_ context.Context, _ []byte) (output.State, error) {
	return output.State{}, f.err
}

// emptyCodec returns (nil, nil) from Encode — violates the StateCodec
// contract ("On success, the returned slice MUST be non-nil and
// non-empty") and exercises the len(stateBytes)==0 guard in
// handleOIDCStart.
type emptyCodec struct{}

func (e *emptyCodec) Encode(_ context.Context, _ output.State) ([]byte, error) {
	return nil, nil
}
func (e *emptyCodec) Decode(_ context.Context, _ []byte) (output.State, error) {
	return output.State{}, nil
}

// stubOIDC is a minimal OIDCFlowProvider for handler tests.
type stubOIDC struct {
	authURL    string
	authURLErr error // when set, AuthorizationURL returns this error
	authErr    error
}

func (s *stubOIDC) AuthorizationURL(_ context.Context, state, nonce, challenge string) (string, error) {
	if s.authURLErr != nil {
		return "", s.authURLErr
	}
	if s.authURL != "" {
		return s.authURL, nil
	}
	return "https://idp.example/auth?state=" + state, nil
}
func (s *stubOIDC) AuthenticateOIDC(ctx context.Context, code, nonce, codeVerifier string) (*user.User, error) {
	if s.authErr != nil {
		return nil, s.authErr
	}
	return &user.User{ID: "user-1", Email: "u@example.com"}, nil
}

func newTestHandler(t *testing.T, codec output.StateCodec, oidc OIDCFlowProvider) *oidcHandler {
	t.Helper()
	return newTestHandlerWithStateMaxAge(t, 10*time.Minute, codec, oidc)
}

func newTestHandlerWithStateMaxAge(t *testing.T, maxAge time.Duration, codec output.StateCodec, oidc OIDCFlowProvider) *oidcHandler {
	t.Helper()
	obs := observability.NewNoop()
	sessMW := shared.NewSessionMiddleware(static.NewSessionSecretProvider([]byte("test-secret-32-bytes-padding-xxxxx")), static.NewSessionConfigProvider(output.SessionConfig{MaxAge: time.Hour, SameSite: http.SameSiteLaxMode}), "test_session", false)
	return &oidcHandler{
		oidc:     oidc,
		session:  sessMW,
		obs:      obs,
		codec:    codec,
		urls:     static.NewURLBuilder(),
		stateCfg: static.NewOIDCStateConfigProvider(output.OIDCStateConfig{MaxAge: maxAge}),
	}
}

// Coverage note: the handler-level redirect_uri tests
// (TestOIDCStart_StaticResolver_RedirectURIBytesIdentical and
// oidc_provider_subst_test.go) were removed deliberately, not lost. In the
// per-call design the /oidc/start handler no longer builds the redirect_uri —
// it lives in the upstream config the adapter resolves per call — so the
// byte-identity and per-request-variation guarantees are now covered at the
// provider level (internal/adapters/oidc: TestAuthorizationURL_ContainsRequiredParams
// asserts redirect_uri=, plus the golden-bytes test). The handler tests below
// cover its own responsibilities: state encode/decode, freshness, cookie
// binding, and error-status mapping.

func TestOIDCStart_EncodesState_HappyPath(t *testing.T) {
	codec := static.NewStateCodec(static.NewStateCodecConfigProvider([]byte("test-key-anything-non-empty")))
	h := newTestHandler(t, codec, &stubOIDC{})

	req := httptest.NewRequestWithContext(context.Background(), "GET", "/oidc/start?redirect=/home", nil)
	w := httptest.NewRecorder()
	h.handleOIDCStart(w, req)

	if w.Code != http.StatusFound {
		t.Fatalf("status=%d, want 302", w.Code)
	}
	loc := w.Header().Get("Location")
	if !strings.Contains(loc, "state=") {
		t.Errorf("expected state= in redirect Location, got: %s", loc)
	}
}

func TestOIDCStart_AuthorizationURLError_Returns500(t *testing.T) {
	codec := static.NewStateCodec(static.NewStateCodecConfigProvider([]byte("test-key-anything-non-empty")))
	h := newTestHandler(t, codec, &stubOIDC{authURLErr: errors.New("boom")})

	req := httptest.NewRequestWithContext(context.Background(), "GET", "/oidc/start", nil)
	w := httptest.NewRecorder()
	h.handleOIDCStart(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status=%d, want 500", w.Code)
	}
	if ct := w.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
		t.Errorf("Content-Type=%q, want text/html", ct)
	}
	// On AuthorizationURL failure the handler must render the error page,
	// not redirect the user to a bogus upstream URL.
	if loc := w.Header().Get("Location"); loc != "" {
		t.Errorf("expected no redirect on AuthorizationURL error, got Location=%q", loc)
	}
}

func TestOIDCStart_CodecEncodeError_Returns500(t *testing.T) {
	codec := &failingCodec{err: errors.New("boom")}
	h := newTestHandler(t, codec, &stubOIDC{})

	req := httptest.NewRequestWithContext(context.Background(), "GET", "/oidc/start", nil)
	w := httptest.NewRecorder()
	h.handleOIDCStart(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Errorf("status=%d, want 500", w.Code)
	}
	if ct := w.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
		t.Errorf("Content-Type=%q, want text/html after UX fix", ct)
	}

	// Document the set-cookie-before-encode ordering: the OIDC state
	// cookie is written to the response before Encode runs, so a failed
	// Encode leaves the cookie orphan in the browser. It is harmless
	// (carries only the browser-binding nonce, self-expires via MaxAge),
	// but a future reader might misread it as a leak — this assertion
	// pins the current behavior so any change to the ordering surfaces
	// in test results.
	var foundStateCookie bool
	for _, c := range w.Result().Cookies() {
		if c.Name == oidcStateCookieName {
			foundStateCookie = true
			break
		}
	}
	if !foundStateCookie {
		t.Errorf("expected %s cookie to be present even on Encode failure (orphan-but-harmless contract)", oidcStateCookieName)
	}
}

func TestOIDCStart_CodecEncodeReturnsEmpty_Returns500(t *testing.T) {
	h := newTestHandler(t, &emptyCodec{}, &stubOIDC{})
	req := httptest.NewRequestWithContext(context.Background(), "GET", "/oidc/start", nil)
	w := httptest.NewRecorder()
	h.handleOIDCStart(w, req)
	if w.Code != http.StatusInternalServerError {
		t.Errorf("status=%d, want 500 for empty Encode result", w.Code)
	}
	if ct := w.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
		t.Errorf("Content-Type=%q, want text/html (RenderTemplate path)", ct)
	}
}

func TestOIDCCallback_DecodeError_Returns400(t *testing.T) {
	codec := &failingCodec{err: errors.New("bad bytes")}
	h := newTestHandler(t, codec, &stubOIDC{})

	req := httptest.NewRequestWithContext(context.Background(), "GET", "/oidc/callback?code=c&state=garbage", nil)
	w := httptest.NewRecorder()
	h.handleOIDCCallback(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("status=%d, want 400", w.Code)
	}
}

func TestOIDCCallback_ExpiredState_Returns400(t *testing.T) {
	codec := static.NewStateCodec(static.NewStateCodecConfigProvider([]byte("test-key-anything-non-empty")))
	h := newTestHandler(t, codec, &stubOIDC{})

	// Encode a state with IssuedAt 1 hour ago — beyond the 10-min window
	old := output.State{
		Redirect:     "/",
		Nonce:        "n",
		Verifier:     "v",
		BrowserNonce: "b",
		IssuedAt:     time.Now().Add(-1 * time.Hour).UTC(),
	}
	wire, _ := codec.Encode(context.Background(), old)

	req := httptest.NewRequestWithContext(context.Background(), "GET", "/oidc/callback?code=c&state="+string(wire), nil)
	// Browser-binding cookie matches so we cleanly hit the freshness gate.
	req.AddCookie(&http.Cookie{Name: oidcStateCookieName, Value: "b"})
	w := httptest.NewRecorder()
	h.handleOIDCCallback(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("status=%d, want 400 (expired)", w.Code)
	}
}

func TestOIDCCallback_ProviderMaxAge_RejectsAgedState(t *testing.T) {
	codec := static.NewStateCodec(static.NewStateCodecConfigProvider([]byte("test-key-anything-non-empty")))
	// Handler configured with a 2-minute state window via the provider — a
	// state issued 5 minutes ago must be rejected at callback. This proves the
	// provider value governs the freshness check, not the old 10m const (which
	// would have let a 5-min-old state through).
	h := newTestHandlerWithStateMaxAge(t, 2*time.Minute, codec, &stubOIDC{})

	old := output.State{
		Redirect:     "/",
		Nonce:        "n",
		Verifier:     "v",
		BrowserNonce: "b",
		IssuedAt:     time.Now().Add(-5 * time.Minute).UTC(),
	}
	wire, _ := codec.Encode(context.Background(), old)

	req := httptest.NewRequestWithContext(context.Background(), "GET", "/oidc/callback?code=c&state="+string(wire), nil)
	// Browser-binding cookie matches so we cleanly hit the freshness gate.
	req.AddCookie(&http.Cookie{Name: oidcStateCookieName, Value: "b"})
	w := httptest.NewRecorder()
	h.handleOIDCCallback(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("status=%d, want 400 (aged beyond provider MaxAge)", w.Code)
	}
	if ct := w.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
		t.Errorf("Content-Type=%q, want text/html (expired error page)", ct)
	}
}

func TestOIDCCallback_ClockSkewFuture_Returns400(t *testing.T) {
	codec := static.NewStateCodec(static.NewStateCodecConfigProvider([]byte("test-key-anything-non-empty")))
	h := newTestHandler(t, codec, &stubOIDC{})

	// IssuedAt 5 minutes in the future — beyond the -1min clock-skew tolerance
	future := output.State{
		Redirect: "/", Nonce: "n", Verifier: "v", BrowserNonce: "b",
		IssuedAt: time.Now().Add(5 * time.Minute).UTC(),
	}
	wire, _ := codec.Encode(context.Background(), future)

	req := httptest.NewRequestWithContext(context.Background(), "GET", "/oidc/callback?code=c&state="+string(wire), nil)
	req.AddCookie(&http.Cookie{Name: oidcStateCookieName, Value: "b"})
	w := httptest.NewRecorder()
	h.handleOIDCCallback(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("status=%d, want 400 (future skew)", w.Code)
	}
}

func TestOIDCCallback_BrowserNonceMismatch_Returns400(t *testing.T) {
	codec := static.NewStateCodec(static.NewStateCodecConfigProvider([]byte("test-key-anything-non-empty")))
	h := newTestHandler(t, codec, &stubOIDC{})

	fresh := output.State{
		Redirect: "/", Nonce: "n", Verifier: "v", BrowserNonce: "b-correct",
		IssuedAt: time.Now().UTC(),
	}
	wire, _ := codec.Encode(context.Background(), fresh)

	req := httptest.NewRequestWithContext(context.Background(), "GET", "/oidc/callback?code=c&state="+string(wire), nil)
	req.AddCookie(&http.Cookie{Name: oidcStateCookieName, Value: "b-wrong"})
	w := httptest.NewRecorder()
	h.handleOIDCCallback(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("status=%d, want 400 (cookie mismatch)", w.Code)
	}
}

func TestOIDCCallback_HappyPath_RoundTrip(t *testing.T) {
	codec := static.NewStateCodec(static.NewStateCodecConfigProvider([]byte("test-key-anything-non-empty")))
	h := newTestHandler(t, codec, &stubOIDC{})

	fresh := output.State{
		Redirect: "/dashboard", Nonce: "n", Verifier: "v", BrowserNonce: "b",
		IssuedAt: time.Now().UTC(),
	}
	wire, _ := codec.Encode(context.Background(), fresh)

	req := httptest.NewRequestWithContext(context.Background(), "GET", "/oidc/callback?code=c&state="+string(wire), nil)
	req.AddCookie(&http.Cookie{Name: oidcStateCookieName, Value: "b"})
	w := httptest.NewRecorder()
	h.handleOIDCCallback(w, req)

	if w.Code != http.StatusSeeOther {
		t.Errorf("status=%d, want 303 (post-login redirect)", w.Code)
	}
	if loc := w.Header().Get("Location"); loc != "/dashboard" {
		t.Errorf("redirect=%q, want /dashboard", loc)
	}
}

func TestOIDCCallback_DecodeFailsBeforeBrowserBinding(t *testing.T) {
	// Failing codec + cookie present must 400 (decode error), NOT pass
	// through to a 500 — proves decode precedes the cookie check.
	codec := &failingCodec{err: errors.New("decode error")}
	h := newTestHandler(t, codec, &stubOIDC{})

	req := httptest.NewRequestWithContext(context.Background(), "GET", "/oidc/callback?code=c&state=anything", nil)
	req.AddCookie(&http.Cookie{Name: oidcStateCookieName, Value: "any"})
	w := httptest.NewRecorder()
	h.handleOIDCCallback(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("status=%d, want 400 (decode order)", w.Code)
	}
}

func TestOIDCCallback_UpstreamUnavailable_Returns500(t *testing.T) {
	codec := static.NewStateCodec(static.NewStateCodecConfigProvider([]byte("test-key-anything-non-empty")))
	// AuthenticateOIDC fails with an infrastructure error (IdP unreachable),
	// tagged with domain.ErrOIDCUnavailable.
	h := newTestHandler(t, codec, &stubOIDC{authErr: errors.Join(domain.ErrOIDCUnavailable, errors.New("idp down"))})

	fresh := output.State{
		Redirect: "/dashboard", Nonce: "n", Verifier: "v", BrowserNonce: "b",
		IssuedAt: time.Now().UTC(),
	}
	wire, _ := codec.Encode(context.Background(), fresh)
	req := httptest.NewRequestWithContext(context.Background(), "GET", "/oidc/callback?code=c&state="+string(wire), nil)
	req.AddCookie(&http.Cookie{Name: oidcStateCookieName, Value: "b"})
	w := httptest.NewRecorder()
	h.handleOIDCCallback(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Errorf("status=%d, want 500 (upstream unavailable is a server error, not a 401)", w.Code)
	}
}

func TestOIDCCallback_AuthFailure_Returns401(t *testing.T) {
	codec := static.NewStateCodec(static.NewStateCodecConfigProvider([]byte("test-key-anything-non-empty")))
	// A genuine authentication failure (not infra) → 401.
	h := newTestHandler(t, codec, &stubOIDC{authErr: domain.ErrOIDCAuthFailed})

	fresh := output.State{
		Redirect: "/dashboard", Nonce: "n", Verifier: "v", BrowserNonce: "b",
		IssuedAt: time.Now().UTC(),
	}
	wire, _ := codec.Encode(context.Background(), fresh)
	req := httptest.NewRequestWithContext(context.Background(), "GET", "/oidc/callback?code=c&state="+string(wire), nil)
	req.AddCookie(&http.Cookie{Name: oidcStateCookieName, Value: "b"})
	w := httptest.NewRecorder()
	h.handleOIDCCallback(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("status=%d, want 401 (genuine auth failure)", w.Code)
	}
}

// findStateCookie returns the OIDC state cookie from a recorder, or nil.
func findStateCookie(rec *httptest.ResponseRecorder) *http.Cookie {
	for _, c := range rec.Result().Cookies() {
		if c.Name == oidcStateCookieName {
			return c
		}
	}
	return nil
}

// mountURLs is a test URLBuilder that resolves paths under a fixed mount prefix
// (no trailing slash), simulating an alternative builder serving under a mount.
// The OSS static default is root-only, so mount scoping is exercised here.
type mountURLs string

func (m mountURLs) Resolve(_ context.Context, p string) (string, error) { return string(m) + p, nil }

// The OIDC state cookie is scoped via the URLBuilder (Resolve), host-only
// (no Domain), and Clear uses the same Path as Set.
func TestOIDCStateCookie_PathScoping(t *testing.T) {
	cases := []struct {
		name     string
		mount    string // "" => root (default builder)
		wantPath string
	}{
		{"root", "", "/"},
		{"reverse-proxy mount", "/api/v2/auth", "/api/v2/auth/"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newTestHandler(t, nil, nil)
			if tc.mount != "" {
				h.urls = mountURLs(tc.mount)
			}

			rec := httptest.NewRecorder()
			h.setOIDCStateCookie(context.Background(), rec, "nonce-123", 10*time.Minute, output.SessionConfig{})
			set := findStateCookie(rec)
			if set == nil {
				t.Fatal("no state cookie set")
			}
			if set.Path != tc.wantPath {
				t.Errorf("set Path = %q, want %q", set.Path, tc.wantPath)
			}
			if set.Domain != "" {
				t.Errorf("set Domain = %q, want empty (host-only)", set.Domain)
			}
			if set.Value != "nonce-123" {
				t.Errorf("set Value = %q, want %q", set.Value, "nonce-123")
			}

			rec2 := httptest.NewRecorder()
			h.clearOIDCStateCookie(context.Background(), rec2)
			clr := findStateCookie(rec2)
			if clr == nil {
				t.Fatal("no state cookie on clear")
			}
			if clr.Path != tc.wantPath {
				t.Errorf("clear Path = %q, want %q (must match set)", clr.Path, tc.wantPath)
			}
			if clr.MaxAge >= 0 {
				t.Errorf("clear MaxAge = %d, want negative (expired)", clr.MaxAge)
			}
		})
	}
}

// errStateCfgProvider always fails to resolve the OIDC state TTL.
type errStateCfgProvider struct{}

func (errStateCfgProvider) Config(context.Context) (output.OIDCStateConfig, error) {
	return output.OIDCStateConfig{}, errors.New("state config backend unreachable")
}

// errSessionCfgProvider always fails to resolve the session-cookie policy.
type errSessionCfgProvider struct{}

func (errSessionCfgProvider) Config(context.Context) (output.SessionConfig, error) {
	return output.SessionConfig{}, errors.New("session policy backend unreachable")
}

// validCallbackRequest builds a callback whose state is fresh and whose
// browser-binding cookie matches, so it passes decode/freshness/binding and
// reaches the state-cookie clear + session set.
func validCallbackRequest(t *testing.T, codec output.StateCodec) *http.Request {
	t.Helper()
	st := output.State{Redirect: "/", Nonce: "n", Verifier: "v", BrowserNonce: "b", IssuedAt: time.Now().UTC()}
	wire, err := codec.Encode(context.Background(), st)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	req := httptest.NewRequestWithContext(context.Background(), "GET", "/oidc/callback?code=c&state="+string(wire), nil)
	req.AddCookie(&http.Cookie{Name: oidcStateCookieName, Value: "b"})
	return req
}

// start: a state-config resolution failure is a 500 (the cookie Max-Age needs it).
func TestOIDCStart_StateConfigError_Returns500(t *testing.T) {
	h := newTestHandler(t, static.NewStateCodec(static.NewStateCodecConfigProvider([]byte("k"))), &stubOIDC{})
	h.stateCfg = errStateCfgProvider{}

	req := httptest.NewRequestWithContext(context.Background(), "GET", "/oidc/start", nil)
	w := httptest.NewRecorder()
	h.handleOIDCStart(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status=%d, want 500", w.Code)
	}
}

// start: a cookie-policy resolution failure is a 500 (the state cookie SET needs
// Secure/SameSite).
func TestOIDCStart_PolicyError_Returns500(t *testing.T) {
	h := newTestHandler(t, static.NewStateCodec(static.NewStateCodecConfigProvider([]byte("k"))), &stubOIDC{})
	h.session = shared.NewSessionMiddleware(static.NewSessionSecretProvider([]byte("test-secret-32-bytes-padding-xxxxx")), errSessionCfgProvider{}, "test_session", false)

	req := httptest.NewRequestWithContext(context.Background(), "GET", "/oidc/start", nil)
	w := httptest.NewRecorder()
	h.handleOIDCStart(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status=%d, want 500", w.Code)
	}
}

// callback: a state-config resolution failure is a 500 — the replay window can't
// be fail-opened.
func TestOIDCCallback_StateConfigError_Returns500(t *testing.T) {
	codec := static.NewStateCodec(static.NewStateCodecConfigProvider([]byte("k")))
	h := newTestHandler(t, codec, &stubOIDC{})
	h.stateCfg = errStateCfgProvider{}

	w := httptest.NewRecorder()
	h.handleOIDCCallback(w, validCallbackRequest(t, codec))

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status=%d, want 500", w.Code)
	}
}

// callback anti-replay invariant: once binding passes the one-time state cookie
// is burned BEFORE the session is set, so even a later 500 (session policy
// unresolvable) cannot leave the (state, nonce) pair replayable. This pins the
// ordering the handler comment asks future readers not to break.
func TestOIDCCallback_SessionSetFails_StateCookieStillBurned(t *testing.T) {
	codec := static.NewStateCodec(static.NewStateCodecConfigProvider([]byte("k")))
	h := newTestHandler(t, codec, &stubOIDC{}) // stub returns a valid user
	// Session policy unresolvable ⇒ SetSessionCookie will 500 AFTER the clear.
	h.session = shared.NewSessionMiddleware(static.NewSessionSecretProvider([]byte("test-secret-32-bytes-padding-xxxxx")), errSessionCfgProvider{}, "test_session", false)

	w := httptest.NewRecorder()
	h.handleOIDCCallback(w, validCallbackRequest(t, codec))

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status=%d, want 500 (session set failed)", w.Code)
	}
	var burned bool
	for _, c := range w.Result().Cookies() {
		if c.Name == oidcStateCookieName && c.MaxAge < 0 {
			burned = true
		}
	}
	if !burned {
		t.Fatal("state cookie was NOT burned before the failed session set — the (state, nonce) pair stays replayable")
	}
}
