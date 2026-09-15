package cimd

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/authplane/authserver/internal/observability"
	"github.com/authplane/authserver/internal/ports/output"
)

// These live in the internal test package because they assert on the cache
// itself — its bound and its bypass — which the external cimd_test package
// cannot see.
//
// Deliberately untagged. The neighboring fetcher_test.go carries
// //go:build integration, but these drive an in-process httptest server and
// touch nothing outside the process, so they are unit tests by any useful
// definition. Tagging them would also put them in front of Gate 0, which reads
// the integration tag as "drives the AS end to end" and requires such tests to
// go through the public HTTP API — a rule that makes no sense for an assertion
// about an unexported map.

func newCacheTestFetcher() *Fetcher {
	return New(observability.NewNoop())
}

func cacheTestCfg() output.CIMDFetchConfig {
	return output.CIMDFetchConfig{
		RequireHTTPS: false,
		// httptest listens on loopback, which the address filter refuses.
		AllowPrivateAddresses: true,
		CacheTTL:              time.Hour,
		FetchTimeout:          10 * time.Second,
	}
}

// The document is served by the client being registered — an untrusted party —
// so what it says about caching has to be honored without letting it control
// our fetch rate or our memory.
func TestFetch_HonorsNoStoreHeader(t *testing.T) {
	var hits int32
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		_ = json.NewEncoder(w).Encode(output.CIMDDocument{
			ClientID:     "http://" + r.Host + r.URL.Path,
			ClientName:   "Test Client",
			RedirectURIs: []string{"https://app.example.com/callback"},
		})
	}))
	defer ts.Close()

	f := newCacheTestFetcher()
	for i := 0; i < 3; i++ {
		if _, err := f.Fetch(context.Background(), ts.URL+"/client.json", cacheTestCfg()); err != nil {
			t.Fatalf("fetch %d: %v", i, err)
		}
	}

	if got := atomic.LoadInt32(&hits); got != 3 {
		t.Errorf("upstream received %d requests, want 3 — no-store must defeat the cache entirely", got)
	}
}

// Without a bound the map only ever grew: entries were overwritten or read past
// expiry, never removed, so a stream of distinct client_id URLs expanded it for
// the process lifetime.
func TestFetch_CacheIsBounded(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(output.CIMDDocument{
			ClientID:     "http://" + r.Host + r.URL.Path,
			ClientName:   "Test Client",
			RedirectURIs: []string{"https://app.example.com/callback"},
		})
	}))
	defer ts.Close()

	f := newCacheTestFetcher()
	for i := 0; i < maxCacheEntries+50; i++ {
		url := fmt.Sprintf("%s/client-%d.json", ts.URL, i)
		if _, err := f.Fetch(context.Background(), url, cacheTestCfg()); err != nil {
			t.Fatalf("fetch %d: %v", i, err)
		}
	}

	f.mu.RLock()
	size := len(f.cache)
	f.mu.RUnlock()

	if size > maxCacheEntries {
		t.Errorf("cache holds %d entries, want at most %d", size, maxCacheEntries)
	}
}
