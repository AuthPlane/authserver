package cimd

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/authplane/authserver/internal/domain"
	"github.com/authplane/authserver/internal/ports/output"
)

// GET /oauth/authorize needs no session and resolves a CIMD client_id by
// fetching the URL it was handed, so an unauthenticated request turns this
// server into an HTTP client aimed wherever the caller likes. These tests pin
// the three controls that bound what that costs. Measured on the code before
// they existed: 50 inbound requests produced 50 outbound requests, 50
// concurrent inbound produced 50 concurrent outbound, and a 1 MB document that
// fails validation was pulled in full on every one of them.
//
// They are untagged in-package tests for the reason given in
// cache_bounds_test.go: they drive an in-process httptest server and assert on
// unexported state.

// failingServer serves a 404 and counts how many requests actually arrived.
func failingServer(t *testing.T) (*httptest.Server, *atomic.Int64) {
	t.Helper()
	var hits atomic.Int64
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusNotFound)
	}))
	t.Cleanup(ts.Close)
	return ts, &hits
}

// blockingServer counts requests and holds each one open until release is
// closed, so a test can observe how many run at once.
func blockingServer(t *testing.T, release <-chan struct{}) (*httptest.Server, *atomic.Int64, *atomic.Int64) {
	t.Helper()
	var hits, peak, inflight atomic.Int64
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		cur := inflight.Add(1)
		for {
			p := peak.Load()
			if cur <= p || peak.CompareAndSwap(p, cur) {
				break
			}
		}
		<-release
		inflight.Add(-1)
		w.WriteHeader(http.StatusNotFound)
	}))
	t.Cleanup(ts.Close)
	return ts, &hits, &peak
}

// A failing target used to be re-fetched on every inbound request, with no
// cache of any kind on the failure path — the property that made the
// amplification sustainable rather than a one-shot.
func TestFetch_NegativeCacheSuppressesRepeatFetch(t *testing.T) {
	ts, hits := failingServer(t)

	f := newCacheTestFetcher()
	const inbound = 50
	for i := 0; i < inbound; i++ {
		if _, err := f.Fetch(context.Background(), ts.URL+"/client.json", cacheTestCfg()); err == nil {
			t.Fatalf("fetch %d: want error from a 404 target", i)
		}
	}

	if got := hits.Load(); got != 1 {
		t.Errorf("%d inbound requests produced %d outbound, want 1", inbound, got)
	}
}

// The negative cache must not turn a transient failure into a lasting one: once
// the entry expires the target is tried again.
func TestFetch_NegativeCacheExpires(t *testing.T) {
	ts, hits := failingServer(t)

	f := newCacheTestFetcher()
	url := ts.URL + "/client.json"
	if _, err := f.Fetch(context.Background(), url, cacheTestCfg()); err == nil {
		t.Fatal("want error from a 404 target")
	}

	f.mu.Lock()
	for _, e := range f.failures {
		e.expiresAt = time.Now().Add(-time.Second)
	}
	f.mu.Unlock()

	if _, err := f.Fetch(context.Background(), url, cacheTestCfg()); err == nil {
		t.Fatal("want error from a 404 target")
	}
	if got := hits.Load(); got != 2 {
		t.Errorf("outbound requests = %d, want 2 — an expired entry must not suppress a retry", got)
	}
}

// A negative entry must never stand in for a document that can be fetched: the
// failure path is the only thing it suppresses.
func TestFetch_NegativeCacheDoesNotBlockRecovery(t *testing.T) {
	var broken atomic.Bool
	broken.Store(true)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if broken.Load() {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(output.CIMDDocument{
			ClientID:     "http://" + r.Host + r.URL.Path,
			ClientName:   "Recovered Client",
			RedirectURIs: []string{"https://app.example.com/callback"},
		})
	}))
	defer ts.Close()

	f := newCacheTestFetcher()
	url := ts.URL + "/client.json"
	if _, err := f.Fetch(context.Background(), url, cacheTestCfg()); err == nil {
		t.Fatal("want error while the target is broken")
	}

	broken.Store(false)
	f.mu.Lock()
	for _, e := range f.failures {
		e.expiresAt = time.Now().Add(-time.Second)
	}
	f.mu.Unlock()

	doc, err := f.Fetch(context.Background(), url, cacheTestCfg())
	if err != nil {
		t.Fatalf("fetch after recovery: %v", err)
	}
	if doc.ClientName != "Recovered Client" {
		t.Errorf("client_name = %q, want %q", doc.ClientName, "Recovered Client")
	}
}

// The failure map is attacker-fed — one distinct URL per request — so it needs
// the same bound the document cache has, and its own, so a flood of failures
// cannot evict the documents of clients that actually registered.
func TestFetch_NegativeCacheIsBounded(t *testing.T) {
	ts, _ := failingServer(t)

	f := newCacheTestFetcher()
	for i := 0; i < maxNegativeCacheEntries+50; i++ {
		url := fmt.Sprintf("%s/client-%d.json", ts.URL, i)
		if _, err := f.Fetch(context.Background(), url, cacheTestCfg()); err == nil {
			t.Fatalf("fetch %d: want error from a 404 target", i)
		}
	}

	f.mu.RLock()
	size := len(f.failures)
	f.mu.RUnlock()

	if size > maxNegativeCacheEntries {
		t.Errorf("negative cache holds %d entries, want at most %d", size, maxNegativeCacheEntries)
	}
}

// Concurrent requests for one URL are the cheapest way to multiply outbound
// traffic, since each one used to make its own call.
func TestFetch_SingleFlightCollapsesConcurrentFetches(t *testing.T) {
	release := make(chan struct{})
	ts, hits, peak := blockingServer(t, release)

	f := newCacheTestFetcher()
	const inbound = 50
	var wg sync.WaitGroup
	for i := 0; i < inbound; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _ = f.Fetch(context.Background(), ts.URL+"/client.json", cacheTestCfg())
		}()
	}
	time.Sleep(300 * time.Millisecond)
	gotPeak := peak.Load()
	close(release)
	wg.Wait()

	if got := hits.Load(); got != 1 {
		t.Errorf("%d concurrent inbound produced %d outbound, want 1", inbound, got)
	}
	if gotPeak > 1 {
		t.Errorf("peak concurrent outbound = %d, want 1", gotPeak)
	}
}

// Distinct URLs are what single-flight cannot collapse, so the global
// semaphore is the only thing bounding them. This is the control that caps
// both the memory held in read buffers and the bandwidth aimed at a third
// party, regardless of inbound rate.
func TestFetch_OutboundConcurrencyIsBounded(t *testing.T) {
	release := make(chan struct{})
	ts, _, peak := blockingServer(t, release)

	f := newCacheTestFetcher()
	const inbound = 50
	var wg sync.WaitGroup
	for i := 0; i < inbound; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, _ = f.Fetch(context.Background(), fmt.Sprintf("%s/client-%d.json", ts.URL, i), cacheTestCfg())
		}(i)
	}
	time.Sleep(500 * time.Millisecond)
	gotPeak := peak.Load()
	close(release)
	wg.Wait()

	if gotPeak > maxConcurrentFetches {
		t.Errorf("peak concurrent outbound = %d, want at most %d", gotPeak, maxConcurrentFetches)
	}
	if gotPeak == 0 {
		t.Fatal("no outbound request observed — the test did not exercise the fetch path")
	}
}

// The whole body is read before the document is validated, so an invalid
// document costs as much bandwidth as a valid one. Suppressing the repeat is
// what turns that from a per-request cost into a one-off.
func TestFetch_OversizeInvalidDocumentIsPulledOnlyOnce(t *testing.T) {
	doc := output.CIMDDocument{
		ClientID:     "https://not-the-fetch-url.example/c.json", // will not match
		ClientName:   strings.Repeat("A", 1<<20-200),
		RedirectURIs: []string{"https://app.example.com/callback"},
	}
	body, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	var served atomic.Int64
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		n, _ := w.Write(body)
		served.Add(int64(n))
	}))
	defer ts.Close()

	f := newCacheTestFetcher()
	const inbound = 5
	for i := 0; i < inbound; i++ {
		if _, err := f.Fetch(context.Background(), ts.URL+"/client.json", cacheTestCfg()); err == nil {
			t.Fatalf("fetch %d: want validation failure", i)
		}
	}

	if got, max := served.Load(), int64(len(body)); got > max {
		t.Errorf("pulled %d bytes over %d inbound requests, want at most %d (one document)", got, inbound, max)
	}
}

// The flight is owned by the group, not by the caller that started it: a client
// that disconnects mid-fetch must not fail the fetch for everyone else riding
// the same flight.
func TestFetch_LeaderCancellationDoesNotKillFlight(t *testing.T) {
	entered := make(chan struct{}, 1)
	release := make(chan struct{})
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case entered <- struct{}{}:
		default:
		}
		<-release
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(output.CIMDDocument{
			ClientID:     "http://" + r.Host + r.URL.Path,
			ClientName:   "Shared Flight",
			RedirectURIs: []string{"https://app.example.com/callback"},
		})
	}))
	defer ts.Close()

	f := newCacheTestFetcher()
	url := ts.URL + "/client.json"

	leaderCtx, cancelLeader := context.WithCancel(context.Background())
	defer cancelLeader()

	leaderDone := make(chan error, 1)
	go func() {
		_, err := f.Fetch(leaderCtx, url, cacheTestCfg())
		leaderDone <- err
	}()

	<-entered // the outbound request is in progress

	waiterDone := make(chan *output.CIMDDocument, 1)
	waiterErr := make(chan error, 1)
	go func() {
		doc, err := f.Fetch(context.Background(), url, cacheTestCfg())
		waiterDone <- doc
		waiterErr <- err
	}()
	time.Sleep(200 * time.Millisecond) // let the waiter join the flight

	cancelLeader()
	if err := <-leaderDone; err == nil {
		t.Error("leader should observe its own cancellation")
	}

	close(release)
	if err := <-waiterErr; err != nil {
		t.Fatalf("waiter inherited the leader's cancellation: %v", err)
	}
	if doc := <-waiterDone; doc == nil || doc.ClientName != "Shared Flight" {
		t.Errorf("waiter got %+v, want the fetched document", doc)
	}
}

// Shedding for capacity says nothing about the target, so caching it would let
// a burst lock out a client whose document is fine.
func TestShouldNegativeCache(t *testing.T) {
	capacityErr := fmt.Errorf("%w: %w", domain.ErrCIMDFetchFailed, errFetchCapacity)
	if shouldNegativeCache(capacityErr) {
		t.Error("a capacity shed must not be negative-cached")
	}
	if !errors.Is(capacityErr, domain.ErrCIMDFetchFailed) {
		t.Error("a capacity shed must still read as a CIMD fetch failure to callers")
	}

	targetErr := fmt.Errorf("%w: HTTP 404", domain.ErrCIMDFetchFailed)
	if !shouldNegativeCache(targetErr) {
		t.Error("a failure describing the target must be negative-cached")
	}
}

// A fetch shed for want of a slot never reached the target, so it says nothing
// about the target. Caching it would let a burst lock out a client whose
// document is fine — and because a FetchTimeout shorter than maxAcquireWait
// makes the caller's own deadline the usual way a queued fetch is dropped,
// that path has to carry the same meaning as the maxAcquireWait one.
func TestFetch_CapacityShedIsNotNegativeCached(t *testing.T) {
	ts, hits := failingServer(t)

	f := newCacheTestFetcher()
	for i := 0; i < maxConcurrentFetches; i++ {
		f.sem <- struct{}{} // hold every slot
	}
	defer func() {
		for i := 0; i < maxConcurrentFetches; i++ {
			<-f.sem
		}
	}()

	cfg := cacheTestCfg()
	cfg.FetchTimeout = 100 * time.Millisecond // expires well before maxAcquireWait

	_, err := f.Fetch(context.Background(), ts.URL+"/client.json", cfg)
	if err == nil {
		t.Fatal("want an error when every slot is held")
	}
	if !errors.Is(err, errFetchCapacity) {
		t.Errorf("error = %v, want it to read as a capacity shed", err)
	}
	if !errors.Is(err, domain.ErrCIMDFetchFailed) {
		t.Errorf("error = %v, want it to read as a CIMD fetch failure to callers", err)
	}

	f.mu.RLock()
	failures := len(f.failures)
	f.mu.RUnlock()
	if failures != 0 {
		t.Errorf("negative cache holds %d entries, want 0 — a capacity shed must not poison a URL", failures)
	}
	if got := hits.Load(); got != 0 {
		t.Errorf("target received %d requests, want 0 — the fetch never got a slot", got)
	}
}
