package public

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/authplane/authserver/api/shared"
	"github.com/authplane/authserver/internal/adapters/static"
	"github.com/authplane/authserver/internal/config"
	"github.com/authplane/authserver/internal/observability"
	"github.com/authplane/authserver/internal/ports/output"
)

const testOrigin = "https://app.example"

// staticCORS is an output.CORSConfigProvider returning a fixed allowlist.
type staticCORS []string

func (s staticCORS) AllowedOrigins(context.Context) ([]string, error) { return []string(s), nil }

// testChainDeps builds ChainDeps the way NewServer does, with a noop observability
// provider and a CORS middleware over a fixed allowlist.
func testChainDeps() ChainDeps {
	obs := observability.NewNoop()
	return ChainDeps{
		Obs:    obs,
		Secure: true,
		CORS:   shared.CORSMiddleware(staticCORS{testOrigin}, obs.Logger),
	}
}

// corsRequest targets a CORS-eligible endpoint with an allowed Origin, so the
// CORS middleware in the chain has something to emit.
func corsRequest() *http.Request {
	r := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/oauth/token", nil)
	r.Header.Set("Origin", testOrigin)
	return r
}

// assertChainApplied checks the response carries what the chain contributes:
// the security headers and the CORS allow-origin for the request's Origin.
//
// It reads Result().Header, not Header(): the recorder snapshots the header map
// at WriteHeader, so a header set AFTER a short-circuit WriteHeader still shows
// up in Header() while never reaching the wire. Asserting on the snapshot keeps
// these tests honest about what a client would actually receive.
func assertChainApplied(t *testing.T, rec *httptest.ResponseRecorder) {
	t.Helper()
	h := rec.Result().Header //nolint:bodyclose // no body opened by the recorder
	if got := h.Get("X-Content-Type-Options"); got != "nosniff" {
		t.Errorf("X-Content-Type-Options = %q — SecurityHeaders did not run", got)
	}
	if got := h.Get("Strict-Transport-Security"); got == "" {
		t.Error("Strict-Transport-Security missing — SecurityHeaders did not run with Secure")
	}
	if got := h.Get("Access-Control-Allow-Origin"); got != testOrigin {
		t.Errorf("Access-Control-Allow-Origin = %q, want %q — CORS did not run", got, testOrigin)
	}
}

func TestDefaultChain_WrapsInner(t *testing.T) {
	var ran bool
	inner := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		ran = true
		w.WriteHeader(http.StatusOK)
	})

	rec := httptest.NewRecorder()
	DefaultChain(testChainDeps(), inner).ServeHTTP(rec, corsRequest())

	if !ran {
		t.Fatal("inner handler must run")
	}
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	assertChainApplied(t, rec)
}

// Recover wraps everything below it, so a panic in the routed handler becomes a
// 500 rather than escaping to the http.Server.
func TestDefaultChain_RecoversPanicFromInner(t *testing.T) {
	inner := http.HandlerFunc(func(http.ResponseWriter, *http.Request) { panic("boom") })

	rec := httptest.NewRecorder()
	DefaultChain(testChainDeps(), inner).ServeHTTP(rec, corsRequest())

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500 — Recover did not wrap inner", rec.Code)
	}
}

// The reason the seam exists. A distribution composes around DefaultChain, and
// the middleware it injects short-circuits without delegating to next — the shape
// of a policy denial. That response must still carry the chain's contribution,
// because a browser client that receives it without Access-Control-Allow-Origin
// cannot read the body and sees an opaque network error instead.
func TestDefaultChain_InjectedMiddlewareShortCircuitCarriesChain(t *testing.T) {
	var innerRan bool
	inner := http.HandlerFunc(func(http.ResponseWriter, *http.Request) { innerRan = true })

	deny := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusTooManyRequests)
			_, _ = w.Write([]byte(`{"error":"denied"}`))
		})
	}

	// This is the documented composition: around DefaultChain, not restating it.
	var build ChainBuilder = func(c ChainDeps, in http.Handler) http.Handler {
		return DefaultChain(c, deny(in))
	}

	rec := httptest.NewRecorder()
	build(testChainDeps(), inner).ServeHTTP(rec, corsRequest())

	if innerRan {
		t.Fatal("injected middleware short-circuited; inner must not run")
	}
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("status = %d, want 429", rec.Code)
	}
	assertChainApplied(t, rec)
}

// Injected middleware sits below Recover, so its panics are contained too.
func TestDefaultChain_RecoversPanicFromInjectedMiddleware(t *testing.T) {
	boom := func(http.Handler) http.Handler {
		return http.HandlerFunc(func(http.ResponseWriter, *http.Request) { panic("boom") })
	}

	rec := httptest.NewRecorder()
	DefaultChain(testChainDeps(), boom(http.NotFoundHandler())).ServeHTTP(rec, corsRequest())

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500 — injected middleware is not under Recover", rec.Code)
	}
}

// Injected middleware that delegates to next leaves the routed handler reachable:
// the seam adds a layer, it does not replace routing.
func TestDefaultChain_InjectedMiddlewareMayDelegate(t *testing.T) {
	var order []string
	inner := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		order = append(order, "inner")
		w.WriteHeader(http.StatusOK)
	})
	pass := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			order = append(order, "injected")
			next.ServeHTTP(w, r)
		})
	}

	rec := httptest.NewRecorder()
	DefaultChain(testChainDeps(), pass(inner)).ServeHTTP(rec, corsRequest())

	if len(order) != 2 || order[0] != "injected" || order[1] != "inner" {
		t.Fatalf("order = %v, want [injected inner]", order)
	}
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	assertChainApplied(t, rec)
}

// --- the seam's own wiring in NewServer ---

// newTestServerDeps is the minimum Deps NewServer accepts without panicking:
// SessionSecretProvider, URLs and CORSConfigProvider are the three required
// seams. secure drives SessionCookie.Secure, the source of ChainDeps.Secure.
func newTestServerDeps(secure bool, buildChain ChainBuilder) Deps {
	d := Deps{
		SessionSecretProvider: static.NewSessionSecretProvider([]byte("test-secret-32-bytes-long-enough")),
		SessionConfigProvider: static.NewSessionConfigProvider(output.SessionConfig{MaxAge: 24 * time.Hour, SameSite: http.SameSiteLaxMode}),
		URLs:                  static.NewURLBuilder(),
		CORSConfigProvider:    static.NewCORSConfigProvider([]string{testOrigin}),
		BuildChain:            buildChain,
	}
	d.SessionCookie.Secure = secure
	return d
}

func newTestServer(t *testing.T, deps Deps) *Server {
	t.Helper()
	return NewServer(context.Background(), config.ServerConfig{
		Issuer:  "https://auth.example.com",
		Address: ":0",
	}, deps, observability.NewNoop())
}

// A nil BuildChain must resolve to DefaultChain. Without the nil guard in
// NewServer, a default OSS boot would call a nil func and panic at startup —
// and every existing test would still pass, because none of them reach the
// seam. This is that test.
func TestNewServer_NilBuildChainUsesDefaultChain(t *testing.T) {
	srv := newTestServer(t, newTestServerDeps(true, nil))

	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, corsRequest())

	// The routed handler's status is irrelevant here; what matters is that the
	// default chain ran and stamped its headers on the way out.
	assertChainApplied(t, rec)
}

// A supplied builder must actually be invoked, and must receive the chain inputs
// NewServer resolved: a usable observability provider and a non-nil CORS
// middleware (NewServer has already panicked if CORSConfigProvider was nil).
func TestNewServer_BuildChainIsInvokedWithResolvedDeps(t *testing.T) {
	var (
		called   bool
		gotDeps  ChainDeps
		gotInner bool
	)
	build := func(c ChainDeps, inner http.Handler) http.Handler {
		called = true
		gotDeps = c
		gotInner = inner != nil
		return DefaultChain(c, inner)
	}

	srv := newTestServer(t, newTestServerDeps(true, build))

	if !called {
		t.Fatal("Deps.BuildChain was never invoked")
	}
	if !gotInner {
		t.Error("builder received a nil inner handler")
	}
	if gotDeps.Obs == nil {
		t.Error("ChainDeps.Obs is nil")
	}
	if gotDeps.CORS == nil {
		t.Error("ChainDeps.CORS is nil")
	}

	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, corsRequest())
	assertChainApplied(t, rec)
}

// ChainDeps.Secure is plumbed from SessionCookie.Secure, not hardcoded — in both
// directions, so a constant would fail one of the two cases.
func TestNewServer_ChainDepsSecureMirrorsSessionCookie(t *testing.T) {
	for _, secure := range []bool{true, false} {
		var gotSecure bool
		deps := newTestServerDeps(secure, func(c ChainDeps, inner http.Handler) http.Handler {
			gotSecure = c.Secure
			return DefaultChain(c, inner)
		})

		newTestServer(t, deps)

		if gotSecure != secure {
			t.Fatalf("SessionCookie.Secure=%v → ChainDeps.Secure=%v, want %v", secure, gotSecure, secure)
		}
	}
}
