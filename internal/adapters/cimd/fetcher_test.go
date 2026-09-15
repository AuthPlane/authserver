//go:build integration

package cimd_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
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

// newTestFetcher creates a fetcher. Address policy is a per-request config knob
// now, so the fetcher itself carries no policy.
func newTestFetcher() *cimd.Fetcher {
	return cimd.New(testObs())
}

// fetchCfg returns a per-request fetch config with test defaults (1h cache TTL,
// 10s fetch timeout) and address filtering off, since tests point at httptest
// servers on loopback. requireHTTPS varies per test.
func fetchCfg(requireHTTPS bool) output.CIMDFetchConfig {
	return output.CIMDFetchConfig{
		RequireHTTPS:          requireHTTPS,
		AllowPrivateAddresses: true,
		CacheTTL:              time.Hour,
		FetchTimeout:          10 * time.Second,
	}
}

// cimdPath is the path component every test CIMD URL carries.
//
// It is not decoration: the MCP 2026-07-28 client-registration spec requires the
// client_id URL to contain a path component, so a bare httptest origin
// (http://127.0.0.1:PORT) is not a legal client_id and the fetcher now rejects
// it before any network call. Appending this keeps every test exercising the
// fetch path it means to exercise rather than tripping the structural gate.
const cimdPath = "/client.json"

// fetchCfgStrict is fetchCfg with address filtering on — for the tests that
// assert loopback and private addresses are refused.
func fetchCfgStrict(requireHTTPS bool) output.CIMDFetchConfig {
	cfg := fetchCfg(requireHTTPS)
	cfg.AllowPrivateAddresses = false
	return cfg
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
			ClientID:     "http://" + r.Host + r.URL.Path,
			ClientName:   "Test Client",
			RedirectURIs: []string{"https://app.example.com/callback"},
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(doc)
	}))
	defer ts.Close()

	f := newTestFetcher()
	doc, err := f.Fetch(context.Background(), ts.URL+cimdPath, fetchCfg(false))
	if err != nil {
		t.Fatalf("fetch: %v", err)
	}
	if doc.ClientID != ts.URL+cimdPath {
		t.Errorf("client_id: got %q, want %q", doc.ClientID, ts.URL+cimdPath)
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
	_, err := f.Fetch(context.Background(), ts.URL+cimdPath, fetchCfg(true))
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
	_, err := f.Fetch(context.Background(), ts.URL+cimdPath, fetchCfg(false))
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
				doc.ClientID = "http://" + r.Host + r.URL.Path
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(doc)
			}))
			defer ts.Close()

			f := newTestFetcher()
			_, err := f.Fetch(context.Background(), ts.URL+cimdPath, fetchCfg(false))
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
	_, err := f.Fetch(context.Background(), ts.URL+cimdPath, fetchCfg(false))
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
	_, err := f.Fetch(context.Background(), ts.URL+cimdPath, fetchCfg(false))
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
			ClientID:     "http://" + r.Host + r.URL.Path,
			ClientName:   "Cached Client",
			RedirectURIs: []string{"https://app.example.com/callback"},
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(doc)
	}))
	defer ts.Close()

	f := newTestFetcher()

	// First fetch — hits server.
	_, err := f.Fetch(context.Background(), ts.URL+cimdPath, fetchCfg(false))
	if err != nil {
		t.Fatalf("first fetch: %v", err)
	}
	if callCount != 1 {
		t.Fatalf("expected 1 call, got %d", callCount)
	}

	// Second fetch — cache hit.
	doc, err := f.Fetch(context.Background(), ts.URL+cimdPath, fetchCfg(false))
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
	_, err := f.Fetch(context.Background(), ts.URL+cimdPath, fetchCfg(false))
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
			ClientID:     "http://" + r.Host + r.URL.Path,
			ClientName:   "Draft CT Client",
			RedirectURIs: []string{"https://app.example.com/callback"},
		}
		w.Header().Set("Content-Type", "application/client-id+json")
		json.NewEncoder(w).Encode(doc)
	}))
	defer ts.Close()

	f := newTestFetcher()
	doc, err := f.Fetch(context.Background(), ts.URL+cimdPath, fetchCfg(false))
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
	_, err := f.Fetch(context.Background(), ts.URL+cimdPath, output.CIMDFetchConfig{
		RequireHTTPS: false, AllowPrivateAddresses: true, CacheTTL: time.Hour, FetchTimeout: 100 * time.Millisecond,
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
			"client_id":     "http://" + r.Host + r.URL.Path,
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
	doc, err := f.Fetch(context.Background(), ts.URL+cimdPath, fetchCfg(false))
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

	// Address filtering on: these URLs must be rejected at the URL-safety check.
	f := cimd.New(testObs())
	for _, u := range urls {
		t.Run(u, func(t *testing.T) {
			_, err := f.Fetch(context.Background(), u, fetchCfgStrict(false))
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

	// Address filtering on: loopback must be rejected at the URL-safety check.
	f := cimd.New(testObs())
	for _, u := range urls {
		t.Run(u, func(t *testing.T) {
			_, err := f.Fetch(context.Background(), u, fetchCfgStrict(false))
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
	_, err := f.Fetch(context.Background(), ts.URL+cimdPath, fetchCfg(false))
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
	_, err := f.Fetch(context.Background(), ts.URL+cimdPath, fetchCfg(false))
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
			"client_id":     "http://" + r.Host + r.URL.Path,
			"client_name":   "Empty Redirects",
			"redirect_uris": []string{},
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(doc)
	}))
	defer ts.Close()

	f := newTestFetcher()
	_, err := f.Fetch(context.Background(), ts.URL+cimdPath, fetchCfg(false))
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
			ClientID:     "http://" + r.Host + r.URL.Path,
			ClientName:   "Bad Redirect",
			RedirectURIs: []string{"https://app.example.com/callback#fragment"},
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(doc)
	}))
	defer ts.Close()

	f := newTestFetcher()
	_, err := f.Fetch(context.Background(), ts.URL+cimdPath, fetchCfg(false))
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
	_, err := f.Fetch(context.Background(), ts.URL+cimdPath, fetchCfg(false))
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
			ClientID:     "http://" + r.Host + r.URL.Path,
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
			_, err := f.Fetch(ctx, ts.URL+cimdPath, fetchCfg(false))
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
				ClientID:     "http://" + r.Host + r.URL.Path,
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
	if _, err := f.Fetch(context.Background(), ts1.URL+cimdPath, output.CIMDFetchConfig{
		RequireHTTPS: false, AllowPrivateAddresses: true, CacheTTL: time.Hour, FetchTimeout: 10 * time.Second,
	}); err != nil {
		t.Fatalf("HTTP should be allowed with per-request RequireHTTPS=false: %v", err)
	}

	// Per-request RequireHTTPS=true ⇒ same-shaped HTTP URL rejected.
	// Fresh server avoids a cache hit from the prior success.
	ts2 := validDoc()
	defer ts2.Close()
	_, err := f.Fetch(context.Background(), ts2.URL+cimdPath, output.CIMDFetchConfig{
		RequireHTTPS: true, AllowPrivateAddresses: true, CacheTTL: time.Hour, FetchTimeout: 10 * time.Second,
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
			ClientID:     "http://" + r.Host + r.URL.Path,
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
	cfg := output.CIMDFetchConfig{RequireHTTPS: false, AllowPrivateAddresses: true, CacheTTL: time.Millisecond, FetchTimeout: 10 * time.Second}

	// First fetch.
	_, err := f.Fetch(ctx, ts.URL+cimdPath, cfg)
	if err != nil {
		t.Fatalf("first fetch: %v", err)
	}
	if callCount != 1 {
		t.Fatalf("expected 1 server call, got %d", callCount)
	}

	// Wait for cache to expire.
	time.Sleep(5 * time.Millisecond)

	// Second fetch — cache expired, should hit server again.
	_, err = f.Fetch(ctx, ts.URL+cimdPath, cfg)
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
			ClientID:     "http://" + r.Host + r.URL.Path,
			ClientName:   "Cache Policy Test",
			RedirectURIs: []string{"https://app.example.com/callback"},
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(doc)
	}))
	defer ts.Close()

	f := newTestFetcher()

	// Seed the cache over http:// with RequireHTTPS=false.
	if _, err := f.Fetch(context.Background(), ts.URL+cimdPath, output.CIMDFetchConfig{
		RequireHTTPS: false, AllowPrivateAddresses: true, CacheTTL: time.Hour, FetchTimeout: 10 * time.Second,
	}); err != nil {
		t.Fatalf("seed fetch (RequireHTTPS=false): %v", err)
	}

	// Same URL with RequireHTTPS=true must be rejected by the scheme check, not
	// served from cache.
	_, err := f.Fetch(context.Background(), ts.URL+cimdPath, output.CIMDFetchConfig{
		RequireHTTPS: true, AllowPrivateAddresses: true, CacheTTL: time.Hour, FetchTimeout: 10 * time.Second,
	})
	if err == nil {
		t.Fatal("RequireHTTPS=true must reject the cached http:// URL")
	}
	if !errors.Is(err, domain.ErrCIMDFetchFailed) {
		t.Errorf("expected ErrCIMDFetchFailed (scheme), got %v", err)
	}
}

// The client_id URL MUST use https and contain a path component
// (MCP 2026-07-28 Client Registration, citing
// draft-ietf-oauth-client-id-metadata-document-00 §"Implementation
// Requirements").
//
// The path half is the security-relevant one. An origin-only client_id
// collapses every client hosted on a domain into one identity: the consent
// record, and the client_name rendered on the consent screen, would be shared
// with any shared-hosting neighbour or subdomain takeover on that origin.
//
// The check must reject BEFORE any network call — a structurally invalid
// identifier should never reach the fetch path, so these cases point at a
// server that would answer if contacted, and assert it never is.
func TestFetch_RejectsClientIDWithoutPathComponent(t *testing.T) {
	var hits int32
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		doc := output.CIMDDocument{
			ClientID:     "http://" + r.Host + r.URL.Path,
			ClientName:   "Test Client",
			RedirectURIs: []string{"https://app.example.com/callback"},
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(doc)
	}))
	defer ts.Close()

	cases := []struct {
		name    string
		url     string
		wantErr bool
	}{
		{"bare origin rejected", ts.URL, true},
		{"origin with root slash rejected", ts.URL + "/", true},
		{"path component accepted", ts.URL + "/client.json", false},
		{"nested path accepted", ts.URL + "/oauth/client-metadata.json", false},
	}

	f := newTestFetcher()
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			before := atomic.LoadInt32(&hits)
			_, err := f.Fetch(context.Background(), tc.url, fetchCfg(false))

			if tc.wantErr {
				if err == nil {
					t.Fatalf("Fetch(%q) succeeded; want rejection for a client_id with no path component", tc.url)
				}
				if !errors.Is(err, domain.ErrCIMDInvalid) {
					t.Errorf("error = %v, want ErrCIMDInvalid", err)
				}
				if got := atomic.LoadInt32(&hits) - before; got != 0 {
					t.Errorf("rejected URL still produced %d request(s); the structural check must run before any network call", got)
				}
				return
			}

			if err != nil {
				t.Fatalf("Fetch(%q): %v", tc.url, err)
			}
		})
	}
}

// Scheme column, address policy held constant: require_https governs http://
// and nothing else touches it.
func TestFetch_SchemeControl_IsIndependent(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		doc := output.CIMDDocument{
			ClientID:     "http://" + r.Host + r.URL.Path,
			ClientName:   "Test Client",
			RedirectURIs: []string{"https://app.example.com/callback"},
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(doc)
	}))
	defer ts.Close()

	f := newTestFetcher()

	// http:// permitted when the scheme control is off.
	if _, err := f.Fetch(context.Background(), ts.URL+cimdPath, fetchCfg(false)); err != nil {
		t.Fatalf("http:// must be permitted with RequireHTTPS=false: %v", err)
	}

	// And rejected when it is on — same address policy in both calls.
	_, err := f.Fetch(context.Background(), "http://example.com/client.json", fetchCfg(true))
	if err == nil {
		t.Fatal("RequireHTTPS=true must reject an http:// URL")
	}
	if !strings.Contains(err.Error(), "HTTPS required") {
		t.Errorf("wrong rejection reason: %v", err)
	}
}

// Address column, scheme policy held constant at its secure default: only
// allow_private_addresses moves it.
//
// This asserts at the URL layer only: 127.0.0.1 is a literal, refused without
// the transport being consulted. Do not read it as coverage of the dial-time
// guarantee — that needs a hostname, and is proven in internal/ssrf by
// TestNewSafeTransport_BlocksHostnamesResolvingToPrivate.
func TestFetch_AddressControl_IsIndependent(t *testing.T) {
	f := newTestFetcher()
	const loopbackHTTPS = "https://127.0.0.1:8443/client.json"

	// Filtering on: a private literal is refused at the URL layer.
	_, err := f.Fetch(context.Background(), loopbackHTTPS, fetchCfgStrict(true))
	if err == nil {
		t.Fatal("AllowPrivateAddresses=false must refuse a loopback URL")
	}
	if !strings.Contains(err.Error(), "loopback address rejected") {
		t.Errorf("wrong rejection reason: %v", err)
	}

	// Filtering off: the URL check no longer refuses it. Nothing is listening,
	// so the fetch still fails — but not for being loopback.
	_, err = f.Fetch(context.Background(), loopbackHTTPS, fetchCfg(true))
	if err != nil && strings.Contains(err.Error(), "loopback address rejected") {
		t.Errorf("AllowPrivateAddresses=true must not refuse by address: %v", err)
	}
}
