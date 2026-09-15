// Package cimd provides an HTTP-based Client ID Metadata Document fetcher.
package cimd

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	otelmetric "go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/trace"
	"golang.org/x/sync/singleflight"

	"github.com/authplane/authserver/internal/domain"
	"github.com/authplane/authserver/internal/domain/client"
	"github.com/authplane/authserver/internal/observability"
	"github.com/authplane/authserver/internal/ports/output"
)

const maxCIMDBodySize = 1 << 20 // 1MB

// minCacheTTL floors any lifetime derived from a response's cache headers.
//
// The MCP client-registration spec asks authorization servers to cache metadata
// "respecting HTTP cache headers", but a document we fetch is served by the
// client being registered — an untrusted party. The floor stops a small
// max-age from shortening the cache lifetime arbitrarily.
//
// It is NOT a bound on our outbound fetch rate, despite the obvious reading.
// A client that sends Cache-Control: no-store is not cached at all, and a fetch
// that fails validation is never cached either, so both bypass the floor
// entirely and re-fetch on every request. Rate-limiting outbound CIMD fetches
// needs a negative cache, single-flight and an in-flight cap — none of which
// exist yet; the floor only shapes the lifetime of documents we do keep.
const minCacheTTL = time.Minute

// maxCacheEntries bounds the in-memory document cache.
//
// The map was previously unbounded: entries were only ever overwritten or read
// past expiry, never removed, so a stream of distinct client_id URLs grew it
// without limit for the process lifetime. Every URL that reaches the cache has
// already passed the scheme, path and SSRF gates, but "valid" is not "few".
const maxCacheEntries = 1024

// The CIMD fetch path is reachable from an unauthenticated
// GET /oauth/authorize carrying an attacker-chosen client_id URL, and every
// failure mode used to return without caching anything — so one inbound
// request produced one outbound request, forever, with no bound on how many
// ran at once. Measured on the unfixed code: 50 inbound requests produced 50
// outbound requests, 50 concurrent inbound produced 50 concurrent outbound,
// and a 1 MB document that fails validation is read in full every time.
//
// The three constants below bound that. They are deliberately not operator
// config: a CIMD document is fetched once per client, on its first
// authorization, and never refreshed afterwards (a successful registration
// stores the client, so the fetcher is not reached again), so steady-state
// demand for outbound fetches is close to zero and there is nothing to tune.
const (
	// negativeCacheTTL is how long a failed fetch suppresses re-fetching the
	// same URL. Short enough that a client fixing a broken document is not
	// locked out for long, long enough that a hostile URL cannot be re-driven
	// at request rate.
	negativeCacheTTL = 30 * time.Second

	// maxNegativeCacheEntries bounds the failure map. It is separate from
	// maxCacheEntries so a flood of failing URLs cannot evict the documents of
	// clients that actually registered.
	maxNegativeCacheEntries = 1024

	// maxConcurrentFetches caps outbound CIMD requests in flight across the
	// whole process, which is what bounds both the memory held in read buffers
	// (up to maxCIMDBodySize each) and the bandwidth aimed at any third party.
	maxConcurrentFetches = 16

	// maxAcquireWait is how long a fetch waits for a slot before being shed.
	// A short wait absorbs a legitimate burst of first-time registrations; a
	// long one would just move the pile-up from sockets to goroutines.
	maxAcquireWait = 2 * time.Second
)

// errFetchCapacity marks a fetch shed because maxConcurrentFetches was full.
// It is a property of this instance's load, not of the target, which is why
// shouldNegativeCache refuses to cache it — a burst must not be able to poison
// a legitimate client's entry.
var errFetchCapacity = errors.New("cimd fetch concurrency limit reached")

var _ output.CIMDFetcher = (*Fetcher)(nil)

// Fetcher fetches and caches CIMD documents. It holds no policy config of its
// own: RequireHTTPS, AllowPrivateAddresses, CacheTTL and FetchTimeout arrive
// per request via the CIMDFetchConfig passed to Fetch (the service resolves
// them from the per-request CIMDConfigProvider, the single source of truth).
type Fetcher struct {
	// client is a single immutable client whose dispatchTransport routes each
	// request to the filtering or non-filtering transport based on the
	// per-request AllowPrivateAddresses carried in the request context.
	client *http.Client

	logger  *slog.Logger
	tracer  trace.Tracer
	metrics *observability.Metrics

	// sf collapses concurrent fetches of the same key into one outbound call.
	// singleflight removes a key when its flight ends, so an attacker-chosen
	// key space leaves no residue.
	sf singleflight.Group

	// sem bounds outbound fetches in flight process-wide. Only the goroutine
	// executing a flight takes a slot; callers waiting on a flight do not.
	sem chan struct{}

	mu sync.RWMutex
	// cache holds documents that were fetched and validated successfully.
	cache map[string]*cacheEntry
	// failures holds recent fetch failures, keyed by fetchKey, so a target that
	// fails is not re-fetched on every inbound request.
	failures map[string]*failureEntry
}

type cacheEntry struct {
	doc       *output.CIMDDocument
	expiresAt time.Time
}

// failureEntry is a negative-cache record: the error a fetch produced, and how
// long that answer stands in for a repeat of the same fetch.
type failureEntry struct {
	err       error
	expiresAt time.Time
}

// New creates a CIMD fetcher. It takes no policy knobs: a single HTTP client is
// built up front whose dispatchTransport selects the filtering or
// non-filtering transport per request from the AllowPrivateAddresses value
// carried in the request context. The per-request timeout is applied via the
// request context, so the client leaves http.Client.Timeout unset.
func New(obs *observability.Provider) *Fetcher {
	return &Fetcher{
		client: &http.Client{
			CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
				// Per spec: do NOT follow redirects.
				return http.ErrUseLastResponse
			},
			Transport: newDispatchTransport(),
		},
		logger:   obs.Logger,
		tracer:   obs.Tracer,
		metrics:  obs.Metrics,
		sem:      make(chan struct{}, maxConcurrentFetches),
		cache:    make(map[string]*cacheEntry),
		failures: make(map[string]*failureEntry),
	}
}

// Fetch retrieves a CIMD from the given URL using the per-request cfg.
func (f *Fetcher) Fetch(ctx context.Context, docURL string, cfg output.CIMDFetchConfig) (*output.CIMDDocument, error) {
	ctx, span := f.tracer.Start(ctx, "CIMD.Fetch")
	defer span.End()

	// Validate URL scheme. This is a per-request policy gate on the URL (does
	// THIS request's RequireHTTPS allow THIS scheme?), and it MUST run before
	// the cache lookup. RequireHTTPS is deliberately absent from the cache key,
	// so this check running first is the only thing keeping a doc cached under a
	// permissive RequireHTTPS=false request from reaching a stricter
	// RequireHTTPS=true one: the stricter request is refused on the URL before
	// it can hit. It reads nothing but the URL, which the key does carry.
	parsed, err := url.Parse(docURL)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return nil, fmt.Errorf("%w: %v", domain.ErrCIMDFetchFailed, err)
	}
	if cfg.RequireHTTPS && parsed.Scheme != "https" {
		schemeErr := fmt.Errorf("%w: HTTPS required, got %s", domain.ErrCIMDFetchFailed, parsed.Scheme)
		span.RecordError(schemeErr)
		span.SetStatus(codes.Error, schemeErr.Error())
		return nil, schemeErr
	}
	if parsed.Scheme != "https" && parsed.Scheme != "http" {
		schemeErr := fmt.Errorf("%w: unsupported scheme %s", domain.ErrCIMDFetchFailed, parsed.Scheme)
		span.RecordError(schemeErr)
		span.SetStatus(codes.Error, schemeErr.Error())
		return nil, schemeErr
	}

	// The client_id URL MUST contain a path component (MCP 2026-07-28, Client
	// Registration §"Implementation Requirements", citing
	// draft-ietf-oauth-client-id-metadata-document-00). Structural, so it runs
	// before the cache lookup and before any network I/O — a malformed
	// identifier should never reach the fetch path at all.
	//
	// The reason this is a MUST and not cosmetics: an origin-only client_id
	// collapses every client hosted on a domain into a single identity. The
	// consent record and the client_name rendered on the consent screen would be
	// shared by any shared-hosting neighbor or subdomain-takeover on that origin.
	// Requiring a path makes the identifier as specific as the document it names.
	if !hasMeaningfulPath(parsed.Path) {
		pathErr := fmt.Errorf("%w: client_id URL must contain a path component (e.g. https://example.com/client.json), got %q", domain.ErrCIMDInvalid, docURL)
		span.RecordError(pathErr)
		span.SetStatus(codes.Error, pathErr.Error())
		return nil, pathErr
	}

	// SSRF protection: reject private, loopback, and link-local addresses.
	if safeErr := validateURLSafety(parsed, cfg.AllowPrivateAddresses); safeErr != nil {
		span.RecordError(safeErr)
		span.SetStatus(codes.Error, safeErr.Error())
		return nil, safeErr
	}

	// One key identifies this target under this request's address policy, and
	// everything keyed below uses it: the document cache, the failure cache and
	// the single-flight group. Cache lookup runs after the per-request gates
	// above. The key carries the address policy because for a hostname the
	// URL-level check defers to the dial (which a hit, or a shared flight,
	// skips), so a document fetched with filtering off must not be reused by a
	// request that has it on.
	key := fetchKey(docURL, cfg.AllowPrivateAddresses)
	if doc := f.getCached(key); doc != nil {
		f.logger.DebugContext(ctx, "cimd cache hit", "url", docURL)
		return doc, nil
	}

	// Everything past this point can reach the network, from a request that
	// needed no session. Three controls bound what an attacker-chosen URL can
	// cost: a negative cache so a failing target is not re-fetched on every
	// request, single-flight so concurrent requests for one URL make one
	// outbound call, and a global semaphore so total outbound concurrency is
	// bounded regardless of inbound rate.
	if cachedErr := f.getCachedFailure(key); cachedErr != nil {
		f.metrics.CIMDFetchSuppressed.Add(ctx, 1, otelmetric.WithAttributes(
			attribute.String("reason", "negative_cache"),
		))
		f.logger.DebugContext(ctx, "cimd negative cache hit", "url", docURL, "error", cachedErr)
		span.RecordError(cachedErr)
		span.SetStatus(codes.Error, cachedErr.Error())
		return nil, cachedErr
	}

	// The flight belongs to the group, not to whichever caller happened to
	// start it. The outbound request runs on a context detached from that
	// caller's cancellation and bounded by FetchTimeout alone, so one client
	// disconnecting cannot fail the fetch for everyone waiting on it — and,
	// because no caller can cancel the shared work, a context error from
	// doFetch can only be the fetch timeout, which is a fact about the target.
	// Callers wait on DoChan and select on their own ctx, so a caller that goes
	// away releases its goroutine without disturbing the flight.
	executed := false
	ch := f.sf.DoChan(key, func() (any, error) {
		executed = true

		// Re-check both caches: this flight may have queued behind one that
		// just populated them.
		if doc := f.getCached(key); doc != nil {
			return doc, nil
		}
		if cachedErr := f.getCachedFailure(key); cachedErr != nil {
			return nil, cachedErr
		}

		fetchCtx := context.WithoutCancel(ctx)
		if cfg.FetchTimeout > 0 {
			var cancel context.CancelFunc
			fetchCtx, cancel = context.WithTimeout(fetchCtx, cfg.FetchTimeout)
			defer cancel()
		}

		doc, err := f.doFetch(fetchCtx, docURL, cfg)
		if err != nil {
			if shouldNegativeCache(err) {
				f.putFailure(key, err)
			}
			return nil, err
		}
		return doc, nil
	})

	select {
	case <-ctx.Done():
		// This caller gave up; the flight continues for whoever is still
		// waiting on it.
		err := fmt.Errorf("%w: %w", domain.ErrCIMDFetchFailed, ctx.Err())
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	case res := <-ch:
		if !executed {
			// This caller's closure never ran, so it rode a flight started by
			// someone else: one outbound request that did not happen.
			f.metrics.CIMDFetchSuppressed.Add(ctx, 1, otelmetric.WithAttributes(
				attribute.String("reason", "single_flight"),
			))
		}
		if res.Err != nil {
			span.RecordError(res.Err)
			span.SetStatus(codes.Error, res.Err.Error())
			return nil, res.Err
		}
		doc, ok := res.Val.(*output.CIMDDocument)
		if !ok || doc == nil {
			err := fmt.Errorf("%w: internal: empty document", domain.ErrCIMDFetchFailed)
			span.RecordError(err)
			span.SetStatus(codes.Error, err.Error())
			return nil, err
		}
		return doc, nil
	}
}

// doFetch performs the outbound request and validates the document. It runs
// inside the single-flight group, so at most one call per key is in progress,
// and it holds a semaphore slot for the whole of its network I/O.
//
// ctx carries the fetch timeout and is detached from any individual caller.
func (f *Fetcher) doFetch(ctx context.Context, docURL string, cfg output.CIMDFetchConfig) (*output.CIMDDocument, error) {
	if err := f.acquire(ctx); err != nil {
		return nil, err
	}
	defer f.release()

	// Carry the per-request address policy in the context so dispatchTransport
	// routes to the filtering or non-filtering transport. Both knobs live on
	// the request context — the shared client is never mutated.
	reqCtx := withAllowPrivate(ctx, cfg.AllowPrivateAddresses)
	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, docURL, http.NoBody)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", domain.ErrCIMDFetchFailed, err)
	}
	req.Header.Set("Accept", "application/json")

	start := time.Now()
	resp, err := f.client.Do(req)
	f.metrics.CIMDFetchDuration.Record(ctx, time.Since(start).Seconds())

	if err != nil {
		return nil, fmt.Errorf("%w: %v", domain.ErrCIMDFetchFailed, err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%w: HTTP %d from %s", domain.ErrCIMDFetchFailed, resp.StatusCode, docURL)
	}

	// Validate Content-Type.
	ct := resp.Header.Get("Content-Type")
	if !isJSONContentType(ct) {
		return nil, fmt.Errorf("%w: expected JSON content-type, got %q", domain.ErrCIMDInvalid, ct)
	}

	// Parse body (enforce max size).
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxCIMDBodySize+1))
	if err != nil {
		return nil, fmt.Errorf("%w: read body: %v", domain.ErrCIMDFetchFailed, err)
	}
	if len(body) > maxCIMDBodySize {
		return nil, fmt.Errorf("%w: response body exceeds maximum size (%d bytes)", domain.ErrCIMDFetchFailed, maxCIMDBodySize)
	}

	var doc output.CIMDDocument
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, fmt.Errorf("%w: invalid JSON: %v", domain.ErrCIMDInvalid, err)
	}

	// Validate required fields.
	if err := validateDocument(&doc, docURL); err != nil {
		return nil, err
	}

	// Apply defaults.
	if len(doc.GrantTypes) == 0 {
		doc.GrantTypes = []string{"authorization_code"}
	}
	if len(doc.ResponseTypes) == 0 {
		doc.ResponseTypes = []string{"code"}
	}
	if doc.TokenEndpointAuthMethod == "" {
		doc.TokenEndpointAuthMethod = "none"
	}

	// Cache the result for as long as the document's own headers allow, bounded
	// by the operator's configured ceiling. Keyed the same way the lookup in
	// Fetch is: the key recomputed here rather than threaded through so
	// doFetch's signature stays as it was.
	if ttl, cacheable := cacheLifetime(resp.Header, cfg.CacheTTL); cacheable {
		f.putCache(fetchKey(docURL, cfg.AllowPrivateAddresses), &doc, ttl)
	}

	f.logger.InfoContext(ctx, "fetched cimd document", "url", docURL, "client_name", doc.ClientName)
	return &doc, nil
}

// acquire takes a slot in the global in-flight limit, or sheds the fetch.
//
// Both shed paths wrap errFetchCapacity, including the one where the caller's
// own deadline arrives first (a FetchTimeout shorter than maxAcquireWait makes
// that the usual one). Either way the request never reached the target, so the
// error says nothing about it — and negative-caching it would let a burst lock
// out a URL whose document is perfectly good.
func (f *Fetcher) acquire(ctx context.Context) error {
	select {
	case f.sem <- struct{}{}:
		return nil
	default:
	}

	timer := time.NewTimer(maxAcquireWait)
	defer timer.Stop()
	select {
	case f.sem <- struct{}{}:
		return nil
	case <-timer.C:
		return f.shed(ctx, errFetchCapacity)
	case <-ctx.Done():
		return f.shed(ctx, fmt.Errorf("%w: %v", errFetchCapacity, ctx.Err()))
	}
}

// shed reports a fetch dropped for want of a slot.
func (f *Fetcher) shed(ctx context.Context, cause error) error {
	f.metrics.CIMDFetchSuppressed.Add(ctx, 1, otelmetric.WithAttributes(
		attribute.String("reason", "capacity"),
	))
	return fmt.Errorf("%w: %w", domain.ErrCIMDFetchFailed, cause)
}

func (f *Fetcher) release() { <-f.sem }

// shouldNegativeCache reports whether an error describes the target, and so
// answers a repeat of the same fetch, rather than describing this instance.
func shouldNegativeCache(err error) bool {
	return !errors.Is(err, errFetchCapacity)
}

// fetchKey identifies one fetch target under one address policy. It keys the
// document cache, the negative cache and the single-flight group.
//
// The address policy is the dimension because for a hostname the URL-level
// check defers to the dial — and a cache hit or a shared flight is exactly
// what skips the dial. For a name resolving to a private address: the request
// with filtering off dials and stores the document under "unfiltered"; the one
// with filtering on passes the same URL check, since there is no literal to
// reject, so under "filtered" it misses, reaches the dial, and is refused
// there. One key for both would have answered it from that entry — and the
// guard, which only runs at the dial, never would.
//
// Nothing else that varies per request belongs here: the scheme check runs
// before all three and reads only the URL, which is already in the key.
//
// Neither prefix is a prefix of the other, so no URL can produce the key of
// the opposite policy.
func fetchKey(docURL string, allowPrivateAddresses bool) string {
	if allowPrivateAddresses {
		return "unfiltered" + docURL
	}
	return "filtered" + docURL
}

// hasMeaningfulPath reports whether a client_id URL carries a path component
// that actually identifies a document, rather than one that resolves back to
// the origin.
//
// Checking `path != "" && path != "/"` is not enough. url.Parse leaves "//"
// as-is, and an origin server that merges duplicate slashes — nginx does by
// default — serves the root document for https://host//. The same holds for
// "/." and "/..", which resolve to the origin under RFC 3986 §5.2.4 dot-segment
// removal that a server or proxy may apply. Each of those is exactly the
// origin-only identifier this gate exists to reject: one that collapses every
// client on a domain into a single consent record and display name.
//
// url.Parse has already percent-decoded Path, so "/%2e" arrives here as "/."
// and needs no separate case.
func hasMeaningfulPath(path string) bool {
	if path == "" {
		return false
	}
	// Strip the leading slash, then require at least one segment that is not
	// empty and not a dot-segment. "/a//b" is fine — it names a document.
	// "//", "/.", "/./", "/..", "/../" are not.
	for _, seg := range strings.Split(strings.TrimPrefix(path, "/"), "/") {
		switch seg {
		case "", ".", "..":
			continue
		default:
			return true
		}
	}
	return false
}

func validateDocument(doc *output.CIMDDocument, fetchURL string) error {
	if doc.ClientID == "" {
		return fmt.Errorf("%w: missing client_id", domain.ErrCIMDInvalid)
	}
	// client_id in document MUST match the fetch URL.
	if doc.ClientID != fetchURL {
		return fmt.Errorf("%w: client_id %q does not match fetch URL %q", domain.ErrCIMDInvalid, doc.ClientID, fetchURL)
	}
	if doc.ClientName == "" {
		return fmt.Errorf("%w: missing client_name", domain.ErrCIMDInvalid)
	}
	if len(doc.RedirectURIs) == 0 {
		return fmt.Errorf("%w: missing redirect_uris", domain.ErrCIMDInvalid)
	}
	for _, uri := range doc.RedirectURIs {
		if err := client.ValidateRedirectURI(uri); err != nil {
			return fmt.Errorf("%w: invalid redirect_uri %q: %v", domain.ErrCIMDInvalid, uri, err)
		}
	}
	return nil
}

func isJSONContentType(ct string) bool {
	ct = strings.ToLower(strings.TrimSpace(ct))
	// Accept application/json or application/client-id+json (per draft spec).
	return strings.HasPrefix(ct, "application/json") ||
		strings.HasPrefix(ct, "application/client-id+json")
}

// validateURLSafety rejects URLs pointing to private, loopback, link-local,
// or unspecified addresses to prevent SSRF attacks. It sees only what the URL
// states: an IP literal, or "localhost". A hostname is left to the transport,
// which validates every resolved address at dial time.
//
// allowPrivate turns this check off wholesale, as the same setting turns off
// the dial-time one: the two are one control applied at two layers.
func validateURLSafety(parsed *url.URL, allowPrivate bool) error {
	if allowPrivate {
		return nil
	}

	host := parsed.Hostname()

	// Reject known dangerous hostnames.
	if strings.EqualFold(host, "localhost") {
		return fmt.Errorf("%w: loopback address rejected: %s", domain.ErrCIMDFetchFailed, host)
	}

	ip := net.ParseIP(host)
	if ip == nil {
		// Not an IP literal — the transport validates every address this
		// hostname resolves to before connecting.
		return nil
	}

	if ip.IsLoopback() {
		return fmt.Errorf("%w: loopback address rejected: %s", domain.ErrCIMDFetchFailed, host)
	}
	if ip.IsPrivate() {
		return fmt.Errorf("%w: private network address rejected: %s", domain.ErrCIMDFetchFailed, host)
	}
	if ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
		return fmt.Errorf("%w: link-local address rejected: %s", domain.ErrCIMDFetchFailed, host)
	}
	if ip.IsUnspecified() {
		return fmt.Errorf("%w: unspecified address rejected: %s", domain.ErrCIMDFetchFailed, host)
	}

	return nil
}

func (f *Fetcher) getCached(key string) *output.CIMDDocument {
	f.mu.RLock()
	defer f.mu.RUnlock()
	entry, ok := f.cache[key]
	if !ok || time.Now().After(entry.expiresAt) {
		return nil
	}
	return entry.doc
}

func (f *Fetcher) putCache(key string, doc *output.CIMDDocument, ttl time.Duration) {
	f.mu.Lock()
	defer f.mu.Unlock()

	if _, replacing := f.cache[key]; !replacing && len(f.cache) >= maxCacheEntries {
		f.evictLocked()
	}

	f.cache[key] = &cacheEntry{
		doc:       doc,
		expiresAt: time.Now().Add(ttl),
	}
}

// getCachedFailure returns the recent failure recorded for key, or nil if
// there is none or it has expired.
func (f *Fetcher) getCachedFailure(key string) error {
	f.mu.RLock()
	defer f.mu.RUnlock()
	entry, ok := f.failures[key]
	if !ok || time.Now().After(entry.expiresAt) {
		return nil
	}
	return entry.err
}

// putFailure records a failed fetch so the same fetch is not repeated for
// negativeCacheTTL. The stored error is returned verbatim to later callers, so
// a suppressed request is indistinguishable from a fresh one to the client —
// only the outbound request is skipped.
func (f *Fetcher) putFailure(key string, err error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	if _, replacing := f.failures[key]; !replacing && len(f.failures) >= maxNegativeCacheEntries {
		evictOneLocked(f.failures, func(e *failureEntry) time.Time { return e.expiresAt })
	}

	f.failures[key] = &failureEntry{
		err:       err,
		expiresAt: time.Now().Add(negativeCacheTTL),
	}
}

// evictLocked makes room for one entry. The caller must hold f.mu.
func (f *Fetcher) evictLocked() {
	evictOneLocked(f.cache, func(e *cacheEntry) time.Time { return e.expiresAt })
}

// evictOneLocked removes exactly one entry from m. The caller must hold f.mu.
//
// Expired entries go first — they are dead weight a lookup would refuse
// anyway. Only if none are expired does it drop the entry closest to expiring,
// which is the one whose loss costs the least: it was about to be re-fetched.
func evictOneLocked[V any](m map[string]V, expiresAt func(V) time.Time) {
	var soonest string
	var soonestAt time.Time
	var found bool

	now := time.Now()
	for k, e := range m {
		exp := expiresAt(e)
		if now.After(exp) {
			delete(m, k)
			return
		}
		if !found || exp.Before(soonestAt) {
			soonest, soonestAt, found = k, exp, true
		}
	}
	if found {
		delete(m, soonest)
	}
}

// cacheLifetime derives how long a fetched document may be cached from its own
// HTTP response headers, bounded by the operator's configured ceiling.
//
// Returns cacheable=false when the response forbids storage. Precedence follows
// RFC 9111: Cache-Control wins over Expires, and max-age wins over both.
func cacheLifetime(h http.Header, configTTL time.Duration) (time.Duration, bool) {
	clamp := func(d time.Duration) (time.Duration, bool) {
		// Floor first, ceiling second, and the order matters. The floor exists
		// to bound our outbound fetch rate; the ceiling is the operator's
		// explicit setting. Applying the floor last would let it raise a
		// lifetime above a configured TTL shorter than a minute, silently
		// overriding the operator to protect against a client — exactly
		// backwards.
		if d < minCacheTTL {
			d = minCacheTTL
		}
		if d > configTTL {
			d = configTTL
		}
		return d, true
	}

	directives := splitCacheControl(h.Get("Cache-Control"))

	// Prohibitions are scanned across the whole field before any lifetime is
	// derived. RFC 9111 makes no-store an absolute bar on storage regardless of
	// what else the field says, and directive order carries no meaning — so
	// "max-age=300, no-store" must not be cached. Returning on the first
	// directive that matched would have stored it.
	for _, d := range directives {
		if d == "no-store" || d == "no-cache" {
			// no-cache technically permits storage with revalidation, but we
			// have no conditional-request path yet, so treating it as no-store
			// is the honest reading: we cannot revalidate, so we must re-fetch.
			return 0, false
		}
	}

	for _, d := range directives {
		if !strings.HasPrefix(d, "max-age=") {
			continue
		}
		secs, err := strconv.Atoi(strings.TrimPrefix(d, "max-age="))
		if err != nil || secs < 0 {
			continue // malformed; ignore it rather than trust it
		}
		if secs == 0 {
			return 0, false
		}
		return clamp(time.Duration(secs) * time.Second)
	}

	if exp := h.Get("Expires"); exp != "" {
		t, err := http.ParseTime(exp)
		if err != nil {
			// RFC 9111 treats an unparseable Expires as already expired.
			return 0, false
		}
		d := time.Until(t)
		if d <= 0 {
			return 0, false
		}
		return clamp(d)
	}

	// No cache headers at all: fall back to the operator's configured TTL,
	// which is the behavior every deployment had before this.
	return configTTL, true
}

// splitCacheControl lowercases and trims a Cache-Control field into its
// individual directives.
func splitCacheControl(v string) []string {
	if v == "" {
		return nil
	}
	parts := strings.Split(strings.ToLower(v), ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}
