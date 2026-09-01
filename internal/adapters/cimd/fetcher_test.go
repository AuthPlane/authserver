//go:build integration

package cimd_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/authplane/authserver/internal/adapters/cimd"
	"github.com/authplane/authserver/internal/domain"
	"github.com/authplane/authserver/internal/observability"
	"github.com/authplane/authserver/internal/ports/output"
)

func testObs() *observability.Provider {
	return observability.NewNoop()
}

// newTestFetcher creates a fetcher with loopback allowed for httptest servers.
// The fetcher holds no policy knobs; callers pass a CIMDFetchConfig per Fetch.
func newTestFetcher() *cimd.Fetcher {
	f := cimd.New(testObs())
	f.SetAllowLoopback(true)
	return f
}

// fetchCfg returns a per-request fetch config with test defaults (1h cache TTL,
// 10s fetch timeout). requireHTTPS varies per test.
func fetchCfg(requireHTTPS bool) output.CIMDFetchConfig {
	return output.CIMDFetchConfig{
		RequireHTTPS: requireHTTPS,
		CacheTTL:     time.Hour,
		FetchTimeout: 10 * time.Second,
	}
}

func serveCIMD(t *testing.T, doc output.CIMDDocument) *httptest.Server {
	t.Helper()
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(doc)
	}))
	t.Cleanup(ts.Close)
	return ts
}

func TestFetch_ValidDocument(t *testing.T) {
	// We need to know the server URL before creating the doc.
	// Use a handler that dynamically sets client_id to the request URL.
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		doc := output.CIMDDocument{
			ClientID:     "http://" + r.Host,
			ClientName:   "Test Client",
			RedirectURIs: []string{"https://app.example.com/callback"},
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(doc)
	}))
	defer ts.Close()

	f := newTestFetcher()
	doc, err := f.Fetch(context.Background(), ts.URL, fetchCfg(false))
	if err != nil {
		t.Fatalf("fetch: %v", err)
	}
	if doc.ClientID != ts.URL {
		t.Errorf("client_id: got %q, want %q", doc.ClientID, ts.URL)
	}
	if doc.ClientName != "Test Client" {
		t.Errorf("client_name: got %q", doc.ClientName)
	}
	if len(doc.RedirectURIs) != 1 {
		t.Errorf("redirect_uris: got %d", len(doc.RedirectURIs))
	}
	// Defaults applied.
	if len(doc.GrantTypes) != 1 || doc.GrantTypes[0] != "authorization_code" {
		t.Errorf("grant_types default: got %v", doc.GrantTypes)
	}
	if doc.TokenEndpointAuthMethod != "none" {
		t.Errorf("auth method default: got %q", doc.TokenEndpointAuthMethod)
	}
}

func TestFetch_HTTPRejectedWhenHTTPSRequired(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(200)
	}))
	defer ts.Close()

	f := newTestFetcher()
	_, err := f.Fetch(context.Background(), ts.URL, fetchCfg(true))
	if err == nil {
		t.Fatal("expected error for HTTP when HTTPS required")
	}
	if !errors.Is(err, domain.ErrCIMDFetchFailed) {
		t.Errorf("expected ErrCIMDFetchFailed, got: %v", err)
	}
}

func TestFetch_ClientIDMismatch(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		doc := output.CIMDDocument{
			ClientID:     "https://wrong.example.com",
			ClientName:   "Wrong Client",
			RedirectURIs: []string{"https://app.example.com/callback"},
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(doc)
	}))
	defer ts.Close()

	f := newTestFetcher()
	_, err := f.Fetch(context.Background(), ts.URL, fetchCfg(false))
	if err == nil {
		t.Fatal("expected error for client_id mismatch")
	}
	if !errors.Is(err, domain.ErrCIMDInvalid) {
		t.Errorf("expected ErrCIMDInvalid, got: %v", err)
	}
}

func TestFetch_MissingRequiredFields(t *testing.T) {
	tests := []struct {
		name string
		doc  output.CIMDDocument
	}{
		{
			name: "missing client_name",
			doc:  output.CIMDDocument{ClientID: "placeholder", RedirectURIs: []string{"https://a.com/cb"}},
		},
		{
			name: "missing redirect_uris",
			doc:  output.CIMDDocument{ClientID: "placeholder", ClientName: "Test"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				doc := tt.doc
				doc.ClientID = "http://" + r.Host
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(doc)
			}))
			defer ts.Close()

			f := newTestFetcher()
			_, err := f.Fetch(context.Background(), ts.URL, fetchCfg(false))
			if err == nil {
				t.Fatal("expected error for missing fields")
			}
			if !errors.Is(err, domain.ErrCIMDInvalid) {
				t.Errorf("expected ErrCIMDInvalid, got: %v", err)
			}
		})
	}
}

func TestFetch_InvalidContentType(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte("<html></html>"))
	}))
	defer ts.Close()

	f := newTestFetcher()
	_, err := f.Fetch(context.Background(), ts.URL, fetchCfg(false))
	if err == nil {
		t.Fatal("expected error for wrong content-type")
	}
	if !errors.Is(err, domain.ErrCIMDInvalid) {
		t.Errorf("expected ErrCIMDInvalid, got: %v", err)
	}
}

func TestFetch_Non200Status(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer ts.Close()

	f := newTestFetcher()
	_, err := f.Fetch(context.Background(), ts.URL, fetchCfg(false))
	if err == nil {
		t.Fatal("expected error for 404")
	}
	if !errors.Is(err, domain.ErrCIMDFetchFailed) {
		t.Errorf("expected ErrCIMDFetchFailed, got: %v", err)
	}
}

func TestFetch_CacheHit(t *testing.T) {
	callCount := 0
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		doc := output.CIMDDocument{
			ClientID:     "http://" + r.Host,
			ClientName:   "Cached Client",
			RedirectURIs: []string{"https://app.example.com/callback"},
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(doc)
	}))
	defer ts.Close()

	f := newTestFetcher()

	// First fetch — hits server.
	_, err := f.Fetch(context.Background(), ts.URL, fetchCfg(false))
	if err != nil {
		t.Fatalf("first fetch: %v", err)
	}
	if callCount != 1 {
		t.Fatalf("expected 1 call, got %d", callCount)
	}

	// Second fetch — cache hit.
	doc, err := f.Fetch(context.Background(), ts.URL, fetchCfg(false))
	if err != nil {
		t.Fatalf("second fetch: %v", err)
	}
	if callCount != 1 {
		t.Errorf("expected 1 call (cache hit), got %d", callCount)
	}
	if doc.ClientName != "Cached Client" {
		t.Errorf("client_name: got %q", doc.ClientName)
	}
}

func TestFetch_NoRedirectsFollowed(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "https://evil.example.com", http.StatusFound)
	}))
	defer ts.Close()

	f := newTestFetcher()
	_, err := f.Fetch(context.Background(), ts.URL, fetchCfg(false))
	if err == nil {
		t.Fatal("expected error when server redirects")
	}
	// Should fail because we get 302 instead of 200.
	if !errors.Is(err, domain.ErrCIMDFetchFailed) {
		t.Errorf("expected ErrCIMDFetchFailed, got: %v", err)
	}
}

func TestFetch_AcceptsClientIDPlusJSON(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		doc := output.CIMDDocument{
			ClientID:     "http://" + r.Host,
			ClientName:   "Draft CT Client",
			RedirectURIs: []string{"https://app.example.com/callback"},
		}
		w.Header().Set("Content-Type", "application/client-id+json")
		json.NewEncoder(w).Encode(doc)
	}))
	defer ts.Close()

	f := newTestFetcher()
	doc, err := f.Fetch(context.Background(), ts.URL, fetchCfg(false))
	if err != nil {
		t.Fatalf("fetch: %v", err)
	}
	if doc.ClientName != "Draft CT Client" {
		t.Errorf("client_name: got %q", doc.ClientName)
	}
}

// Matrix: 3.5 — CIMD fetch timeout must return error
func TestFetch_TimeoutReturnsError(t *testing.T) {
	// Server that never responds (blocks until context is done).
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
	}))
	defer ts.Close()

	f := newTestFetcher()

	start := time.Now()
	// Per-request config with a very short timeout (100ms).
	_, err := f.Fetch(context.Background(), ts.URL, output.CIMDFetchConfig{
		RequireHTTPS: false, CacheTTL: time.Hour, FetchTimeout: 100 * time.Millisecond,
	})
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("expected error when server does not respond within timeout")
	}
	if !errors.Is(err, domain.ErrCIMDFetchFailed) {
		t.Errorf("expected ErrCIMDFetchFailed, got: %v", err)
	}
	// Verify it didn't wait too long (should be close to 100ms, not 10s).
	if elapsed > 2*time.Second {
		t.Errorf("timeout took too long: %v (expected ~100ms)", elapsed)
	}
}

// Matrix: 3.12 — CIMD document with extra/unknown fields must be accepted
func TestFetch_ExtraFieldsAccepted(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Return a valid CIMD doc with additional unknown fields.
		doc := map[string]any{
			"client_id":     "http://" + r.Host,
			"client_name":   "Extra Fields Client",
			"redirect_uris": []string{"https://app.example.com/callback"},
			// Extra fields not in the CIMDDocument struct:
			"logo_uri":     "https://example.com/logo.png",
			"contacts":     []string{"admin@example.com"},
			"tos_uri":      "https://example.com/tos",
			"policy_uri":   "https://example.com/policy",
			"custom_field": "custom_value",
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(doc)
	}))
	defer ts.Close()

	f := newTestFetcher()
	doc, err := f.Fetch(context.Background(), ts.URL, fetchCfg(false))
	if err != nil {
		t.Fatalf("fetch with extra fields should succeed: %v", err)
	}
	if doc.ClientName != "Extra Fields Client" {
		t.Errorf("client_name: got %q", doc.ClientName)
	}
	if len(doc.RedirectURIs) != 1 {
		t.Errorf("redirect_uris: got %d", len(doc.RedirectURIs))
	}
}

// Matrix: 14.11 + 3.11 — SSRF via CIMD: private IP ranges must be rejected
func TestFetch_SSRFPrivateIPRejected(t *testing.T) {
	urls := []string{
		"http://10.0.0.1/.well-known/oauth-client",
		"http://172.16.0.1/.well-known/oauth-client",
		"http://192.168.1.1/.well-known/oauth-client",
		"http://169.254.169.254/.well-known/oauth-client", // AWS metadata
		"http://[fd00::1]/.well-known/oauth-client",       // IPv6 private
	}

	// No SetAllowLoopback: these URLs must be rejected at the URL-safety check.
	f := cimd.New(testObs())
	for _, u := range urls {
		t.Run(u, func(t *testing.T) {
			_, err := f.Fetch(context.Background(), u, fetchCfg(false))
			if err == nil {
				t.Fatalf("expected error for private IP URL %s", u)
			}
			if !errors.Is(err, domain.ErrCIMDFetchFailed) {
				t.Errorf("expected ErrCIMDFetchFailed, got: %v", err)
			}
		})
	}
}

// Matrix: 14.12 — SSRF via CIMD: loopback addresses must be rejected
func TestFetch_SSRFLoopbackRejected(t *testing.T) {
	urls := []string{
		"http://127.0.0.1/.well-known/oauth-client",
		"http://localhost/.well-known/oauth-client",
		"http://[::1]/.well-known/oauth-client",
		"http://0.0.0.0/.well-known/oauth-client",
		"http://127.0.0.2/.well-known/oauth-client", // alternate loopback
	}

	// No SetAllowLoopback: loopback must be rejected at the URL-safety check.
	f := cimd.New(testObs())
	for _, u := range urls {
		t.Run(u, func(t *testing.T) {
			_, err := f.Fetch(context.Background(), u, fetchCfg(false))
			if err == nil {
				t.Fatalf("expected error for loopback URL %s", u)
			}
			if !errors.Is(err, domain.ErrCIMDFetchFailed) {
				t.Errorf("expected ErrCIMDFetchFailed, got: %v", err)
			}
		})
	}
}

// Matrix: 3.6 — upgraded from ⚠️: CIMD invalid JSON must be rejected
func TestFetch_InvalidJSON(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{invalid json`))
	}))
	defer ts.Close()

	f := newTestFetcher()
	_, err := f.Fetch(context.Background(), ts.URL, fetchCfg(false))
	if err == nil {
		t.Fatal("expected error for invalid JSON body")
	}
	if !errors.Is(err, domain.ErrCIMDInvalid) && !errors.Is(err, domain.ErrCIMDFetchFailed) {
		t.Errorf("expected ErrCIMDInvalid or ErrCIMDFetchFailed, got: %v", err)
	}
}

// Matrix: 14.14 — large CIMD response must be rejected
func TestFetch_LargeResponseRejected(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		// Write 10MB of data, far exceeding the 1MB limit.
		chunk := bytes.Repeat([]byte("x"), 64*1024)
		for i := 0; i < 160; i++ {
			w.Write(chunk)
		}
	}))
	defer ts.Close()

	f := newTestFetcher()
	_, err := f.Fetch(context.Background(), ts.URL, fetchCfg(false))
	if err == nil {
		t.Fatal("expected error for oversized response")
	}
	if !errors.Is(err, domain.ErrCIMDFetchFailed) {
		t.Errorf("expected ErrCIMDFetchFailed, got: %v", err)
	}
}

// TestFetch_UnsupportedScheme verifies that ftp:// and other non-http schemes are rejected.
func TestFetch_UnsupportedScheme(t *testing.T) {
	urls := []string{
		"ftp://example.com/.well-known/oauth-client",
		"file:///etc/passwd",
	}
	f := newTestFetcher()
	for _, u := range urls {
		t.Run(u, func(t *testing.T) {
			_, err := f.Fetch(context.Background(), u, fetchCfg(false))
			if err == nil {
				t.Fatalf("expected error for scheme in %s", u)
			}
			if !errors.Is(err, domain.ErrCIMDFetchFailed) {
				t.Errorf("expected ErrCIMDFetchFailed, got: %v", err)
			}
		})
	}
}

// TestFetch_EmptyRedirectURIs verifies that a document with an empty redirect_uris
// array (not missing, but empty) is rejected.
func TestFetch_EmptyRedirectURIs(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		doc := map[string]any{
			"client_id":     "http://" + r.Host,
			"client_name":   "Empty Redirects",
			"redirect_uris": []string{},
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(doc)
	}))
	defer ts.Close()

	f := newTestFetcher()
	_, err := f.Fetch(context.Background(), ts.URL, fetchCfg(false))
	if err == nil {
		t.Fatal("expected error for empty redirect_uris")
	}
	if !errors.Is(err, domain.ErrCIMDInvalid) {
		t.Errorf("expected ErrCIMDInvalid, got: %v", err)
	}
}

// TestFetch_InvalidRedirectURI verifies that a redirect_uri with a fragment is rejected.
func TestFetch_InvalidRedirectURI(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		doc := output.CIMDDocument{
			ClientID:     "http://" + r.Host,
			ClientName:   "Bad Redirect",
			RedirectURIs: []string{"https://app.example.com/callback#fragment"},
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(doc)
	}))
	defer ts.Close()

	f := newTestFetcher()
	_, err := f.Fetch(context.Background(), ts.URL, fetchCfg(false))
	if err == nil {
		t.Fatal("expected error for redirect_uri with fragment")
	}
	if !errors.Is(err, domain.ErrCIMDInvalid) {
		t.Errorf("expected ErrCIMDInvalid, got: %v", err)
	}
}

// TestFetch_MissingClientID verifies that a document with empty client_id is rejected.
func TestFetch_MissingClientID(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		doc := output.CIMDDocument{
			ClientID:     "",
			ClientName:   "No Client ID",
			RedirectURIs: []string{"https://app.example.com/callback"},
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(doc)
	}))
	defer ts.Close()

	f := newTestFetcher()
	_, err := f.Fetch(context.Background(), ts.URL, fetchCfg(false))
	if err == nil {
		t.Fatal("expected error for missing client_id")
	}
	if !errors.Is(err, domain.ErrCIMDInvalid) {
		t.Errorf("expected ErrCIMDInvalid, got: %v", err)
	}
}

// TestFetch_ConcurrentAccess verifies the cache is safe under concurrent access.
func TestFetch_ConcurrentAccess(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		doc := output.CIMDDocument{
			ClientID:     "http://" + r.Host,
			ClientName:   "Concurrent Test",
			RedirectURIs: []string{"https://app.example.com/callback"},
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(doc)
	}))
	defer ts.Close()

	f := newTestFetcher()
	ctx := context.Background()

	errs := make(chan error, 10)
	for i := 0; i < 10; i++ {
		go func() {
			_, err := f.Fetch(ctx, ts.URL, fetchCfg(false))
			errs <- err
		}()
	}
	for i := 0; i < 10; i++ {
		if err := <-errs; err != nil {
			t.Errorf("concurrent fetch error: %v", err)
		}
	}
}

// TestFetch_PerRequestRequireHTTPS proves RequireHTTPS is honored per request on
// a single Fetcher instance: an HTTP URL is accepted when the per-request config
// sets RequireHTTPS=false and rejected when it sets RequireHTTPS=true.
func TestFetch_PerRequestRequireHTTPS(t *testing.T) {
	validDoc := func() *httptest.Server {
		return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			doc := output.CIMDDocument{
				ClientID:     "http://" + r.Host,
				ClientName:   "Per-Request Client",
				RedirectURIs: []string{"https://app.example.com/callback"},
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(doc)
		}))
	}

	f := newTestFetcher()

	// Per-request RequireHTTPS=false ⇒ HTTP allowed.
	ts1 := validDoc()
	defer ts1.Close()
	if _, err := f.Fetch(context.Background(), ts1.URL, output.CIMDFetchConfig{
		RequireHTTPS: false, CacheTTL: time.Hour, FetchTimeout: 10 * time.Second,
	}); err != nil {
		t.Fatalf("HTTP should be allowed with per-request RequireHTTPS=false: %v", err)
	}

	// Per-request RequireHTTPS=true ⇒ same-shaped HTTP URL rejected.
	// Fresh server avoids a cache hit from the prior success.
	ts2 := validDoc()
	defer ts2.Close()
	_, err := f.Fetch(context.Background(), ts2.URL, output.CIMDFetchConfig{
		RequireHTTPS: true, CacheTTL: time.Hour, FetchTimeout: 10 * time.Second,
	})
	if err == nil {
		t.Fatal("HTTP should be rejected with per-request RequireHTTPS=true")
	}
	if !errors.Is(err, domain.ErrCIMDFetchFailed) {
		t.Errorf("expected ErrCIMDFetchFailed, got %v", err)
	}
}

// TestFetch_CacheExpiry verifies that expired cache entries are not returned.
func TestFetch_CacheExpiry(t *testing.T) {
	callCount := 0
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		doc := output.CIMDDocument{
			ClientID:     "http://" + r.Host,
			ClientName:   "Cache Expiry",
			RedirectURIs: []string{"https://app.example.com/callback"},
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(doc)
	}))
	defer ts.Close()

	f := newTestFetcher()
	ctx := context.Background()
	// Per-request config with a very short cache TTL.
	cfg := output.CIMDFetchConfig{RequireHTTPS: false, CacheTTL: time.Millisecond, FetchTimeout: 10 * time.Second}

	// First fetch.
	_, err := f.Fetch(ctx, ts.URL, cfg)
	if err != nil {
		t.Fatalf("first fetch: %v", err)
	}
	if callCount != 1 {
		t.Fatalf("expected 1 server call, got %d", callCount)
	}

	// Wait for cache to expire.
	time.Sleep(5 * time.Millisecond)

	// Second fetch — cache expired, should hit server again.
	_, err = f.Fetch(ctx, ts.URL, cfg)
	if err != nil {
		t.Fatalf("second fetch: %v", err)
	}
	if callCount != 2 {
		t.Errorf("expected 2 server calls after cache expiry, got %d", callCount)
	}
}

// TestFetch_CacheDoesNotBypassScheme verifies the per-request scheme check runs
// BEFORE the cache lookup: a doc cached over http:// (RequireHTTPS=false) must
// not be served to a later RequireHTTPS=true request for the same URL via a
// cache hit that skips the HTTPS scheme check.
func TestFetch_CacheDoesNotBypassScheme(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		doc := output.CIMDDocument{
			ClientID:     "http://" + r.Host,
			ClientName:   "Cache Policy Test",
			RedirectURIs: []string{"https://app.example.com/callback"},
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(doc)
	}))
	defer ts.Close()

	f := newTestFetcher()

	// Seed the cache over http:// with RequireHTTPS=false.
	if _, err := f.Fetch(context.Background(), ts.URL, output.CIMDFetchConfig{
		RequireHTTPS: false, CacheTTL: time.Hour, FetchTimeout: 10 * time.Second,
	}); err != nil {
		t.Fatalf("seed fetch (RequireHTTPS=false): %v", err)
	}

	// Same URL with RequireHTTPS=true must be rejected by the scheme check, not
	// served from cache.
	_, err := f.Fetch(context.Background(), ts.URL, output.CIMDFetchConfig{
		RequireHTTPS: true, CacheTTL: time.Hour, FetchTimeout: 10 * time.Second,
	})
	if err == nil {
		t.Fatal("RequireHTTPS=true must reject the cached http:// URL")
	}
	if !errors.Is(err, domain.ErrCIMDFetchFailed) {
		t.Errorf("expected ErrCIMDFetchFailed (scheme), got %v", err)
	}
}
