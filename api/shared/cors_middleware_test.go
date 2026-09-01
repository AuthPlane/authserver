package shared

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/authplane/authserver/internal/ports/output"
)

// fakeCORSProvider resolves the allowlist per request. If err is non-nil it
// fails; otherwise it returns origins, or — when perCtx is set — the origins
// keyed off a context value, proving the seam is genuinely per-request.
type fakeCORSProvider struct {
	origins []string
	err     error
	perCtx  map[any][]string
	ctxKey  any
}

func (f fakeCORSProvider) AllowedOrigins(ctx context.Context) ([]string, error) {
	if f.err != nil {
		return nil, f.err
	}
	if f.perCtx != nil {
		if o, ok := f.perCtx[ctx.Value(f.ctxKey)]; ok {
			return o, nil
		}
		return nil, nil
	}
	return f.origins, nil
}

var _ output.CORSConfigProvider = fakeCORSProvider{}

// okHandler is the terminal handler; a 200 lets us assert the middleware called
// through rather than short-circuiting.
var okHandler = http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusOK)
})

func doCORS(t *testing.T, provider output.CORSConfigProvider, method, path, origin string) *httptest.ResponseRecorder {
	t.Helper()
	mw := CORSMiddleware(provider, nil)
	req := httptest.NewRequestWithContext(context.Background(), method, path, nil)
	if origin != "" {
		req.Header.Set("Origin", origin)
	}
	rec := httptest.NewRecorder()
	mw(okHandler).ServeHTTP(rec, req)
	return rec
}

func TestCORSMiddleware_AllowedOrigin_Preflight(t *testing.T) {
	resp := doCORS(t, fakeCORSProvider{origins: []string{"https://app.example.com"}},
		http.MethodOptions, "/oauth/token", "https://app.example.com")
	if resp.Code != http.StatusNoContent {
		t.Fatalf("status: got %d, want 204", resp.Code)
	}
	if v := resp.Header().Get("Access-Control-Allow-Origin"); v != "https://app.example.com" {
		t.Fatalf("ACAO: got %q, want echoed origin", v)
	}
	if v := resp.Header().Get("Vary"); v != "Origin" {
		t.Fatalf("Vary: got %q, want Origin", v)
	}
}

func TestCORSMiddleware_ProviderError_FailsClosed(t *testing.T) {
	// Provider failure must emit NO CORS headers even for an origin that a
	// healthy provider would allow — never a fallback to a stale list.
	resp := doCORS(t, fakeCORSProvider{err: errors.New("resolve failed")},
		http.MethodOptions, "/oauth/token", "https://app.example.com")
	if v := resp.Header().Get("Access-Control-Allow-Origin"); v != "" {
		t.Fatalf("ACAO should be empty on provider error, got %q", v)
	}
	// The request still flows to the next handler (no headers, not a 500).
	if resp.Code != http.StatusOK {
		t.Fatalf("status on provider error: got %d, want 200 (passthrough)", resp.Code)
	}
}

func TestCORSMiddleware_ProviderError_LogsAtError(t *testing.T) {
	// A non-nil logger must record the fail-closed event so a persistently
	// broken provider is not silent; the error must not leak into the response.
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelError}))
	mw := CORSMiddleware(fakeCORSProvider{err: errors.New("resolve failed")}, logger)

	req := httptest.NewRequestWithContext(context.Background(), http.MethodOptions, "/oauth/token", nil)
	req.Header.Set("Origin", "https://app.example.com")
	rec := httptest.NewRecorder()
	mw(okHandler).ServeHTTP(rec, req)

	if v := rec.Header().Get("Access-Control-Allow-Origin"); v != "" {
		t.Fatalf("ACAO should be empty on provider error, got %q", v)
	}
	logged := buf.String()
	if !strings.Contains(logged, "level=ERROR") || !strings.Contains(logged, "failing closed") {
		t.Fatalf("expected an Error log about failing closed, got: %q", logged)
	}
}

func TestCORSMiddleware_PerRequestSubstitution(t *testing.T) {
	// Same middleware instance, two requests whose allowed origin is resolved
	// from the request context — proves resolution is per request, not a boot
	// snapshot.
	type ctxKey struct{}
	provider := fakeCORSProvider{
		ctxKey: ctxKey{},
		perCtx: map[any][]string{
			"site-a": {"https://a.example.com"},
			"site-b": {"https://b.example.com"},
		},
	}
	mw := CORSMiddleware(provider, nil)

	cases := []struct {
		val    string
		origin string
		want   string
	}{
		{"site-a", "https://a.example.com", "https://a.example.com"},
		{"site-a", "https://b.example.com", ""}, // a's origin list rejects b
		{"site-b", "https://b.example.com", "https://b.example.com"},
	}
	for _, tc := range cases {
		ctx := context.WithValue(context.Background(), ctxKey{}, tc.val)
		req := httptest.NewRequestWithContext(ctx, http.MethodOptions, "/oauth/token", nil)
		req.Header.Set("Origin", tc.origin)
		rec := httptest.NewRecorder()
		mw(okHandler).ServeHTTP(rec, req)
		if v := rec.Header().Get("Access-Control-Allow-Origin"); v != tc.want {
			t.Errorf("ctx=%s origin=%s: ACAO got %q, want %q", tc.val, tc.origin, v, tc.want)
		}
	}
}

func TestCORSMiddleware_UnknownOrigin_NoHeaders(t *testing.T) {
	resp := doCORS(t, fakeCORSProvider{origins: []string{"https://app.example.com"}},
		http.MethodOptions, "/oauth/token", "https://evil.example.com")
	if v := resp.Header().Get("Access-Control-Allow-Origin"); v != "" {
		t.Fatalf("ACAO should be empty for unknown origin, got %q", v)
	}
}

func TestCORSMiddleware_Wildcard(t *testing.T) {
	resp := doCORS(t, fakeCORSProvider{origins: []string{"*"}},
		http.MethodGet, "/.well-known/oauth-authorization-server", "https://anything.example.com")
	if v := resp.Header().Get("Access-Control-Allow-Origin"); v != "*" {
		t.Fatalf("ACAO: got %q, want *", v)
	}
	// Wildcard must NOT set Vary: Origin.
	if v := resp.Header().Get("Vary"); v != "" {
		t.Fatalf("Vary should be unset for wildcard, got %q", v)
	}
}

func TestCORSMiddleware_NonCORSEndpoint_NoHeaders(t *testing.T) {
	// /login is not CORS-eligible; even with a matching origin no headers emit,
	// and the provider is never consulted (a failing provider would still 200).
	resp := doCORS(t, fakeCORSProvider{err: errors.New("must not be called")},
		http.MethodGet, "/login", "https://app.example.com")
	if v := resp.Header().Get("Access-Control-Allow-Origin"); v != "" {
		t.Fatalf("ACAO should be empty for non-CORS endpoint, got %q", v)
	}
	if resp.Code != http.StatusOK {
		t.Fatalf("status: got %d, want 200", resp.Code)
	}
}

func TestCORSMiddleware_NoOriginHeader_Passthrough(t *testing.T) {
	resp := doCORS(t, fakeCORSProvider{origins: []string{"https://app.example.com"}},
		http.MethodGet, "/oauth/token", "")
	if v := resp.Header().Get("Access-Control-Allow-Origin"); v != "" {
		t.Fatalf("ACAO should be empty without Origin header, got %q", v)
	}
	if resp.Code != http.StatusOK {
		t.Fatalf("status: got %d, want 200", resp.Code)
	}
}
