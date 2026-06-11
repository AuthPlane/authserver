// Package cimd provides an HTTP-based Client ID Metadata Document fetcher.
package cimd

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"

	"github.com/authplane/authserver/internal/domain"
	"github.com/authplane/authserver/internal/domain/client"
	"github.com/authplane/authserver/internal/observability"
	"github.com/authplane/authserver/internal/ports/output"
	"github.com/authplane/authserver/internal/ssrf"
)

const maxCIMDBodySize = 1 << 20 // 1MB

var _ output.CIMDFetcher = (*Fetcher)(nil)

// Fetcher fetches and caches CIMD documents over HTTPS.
type Fetcher struct {
	client        *http.Client
	requireHTTPS  bool
	allowLoopback bool
	cacheTTL      time.Duration
	logger        *slog.Logger
	tracer        trace.Tracer
	metrics       *observability.Metrics

	mu    sync.RWMutex
	cache map[string]*cacheEntry
}

// SetAllowLoopback enables loopback addresses (127.0.0.1, ::1, localhost)
// for testing with httptest servers. MUST NOT be called in production.
func (f *Fetcher) SetAllowLoopback(allow bool) {
	f.allowLoopback = allow
}

type cacheEntry struct {
	doc       *output.CIMDDocument
	expiresAt time.Time
}

// New creates a CIMD fetcher.
// When requireHTTPS is true (production), the HTTP client uses an SSRF-safe
// transport that blocks connections to private/reserved IP addresses.
// When requireHTTPS is false (dev/test), the default transport is used to
// allow loopback connections.
func New(requireHTTPS bool, cacheTTL, fetchTimeout time.Duration, obs *observability.Provider) *Fetcher {
	httpClient := &http.Client{
		Timeout: fetchTimeout,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			// Per spec: do NOT follow redirects.
			return http.ErrUseLastResponse
		},
	}
	if requireHTTPS {
		httpClient.Transport = ssrf.NewSafeTransport()
	}

	return &Fetcher{
		client:       httpClient,
		requireHTTPS: requireHTTPS,
		cacheTTL:     cacheTTL,
		logger:       obs.Logger,
		tracer:       obs.Tracer,
		metrics:      obs.Metrics,
		cache:        make(map[string]*cacheEntry),
	}
}

// Fetch retrieves a CIMD from the given URL.
func (f *Fetcher) Fetch(ctx context.Context, docURL string) (*output.CIMDDocument, error) {
	ctx, span := f.tracer.Start(ctx, "CIMD.Fetch")
	defer span.End()

	// Check cache first.
	if doc := f.getCached(docURL); doc != nil {
		f.logger.DebugContext(ctx, "cimd cache hit", "url", docURL)
		return doc, nil
	}

	// Validate URL scheme.
	parsed, err := url.Parse(docURL)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return nil, fmt.Errorf("%w: %v", domain.ErrCIMDFetchFailed, err)
	}
	if f.requireHTTPS && parsed.Scheme != "https" {
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

	// SSRF protection: reject private, loopback, and link-local addresses.
	if safeErr := f.validateURLSafety(parsed); safeErr != nil {
		span.RecordError(safeErr)
		span.SetStatus(codes.Error, safeErr.Error())
		return nil, safeErr
	}

	// Fetch the document.
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, docURL, http.NoBody)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return nil, fmt.Errorf("%w: %v", domain.ErrCIMDFetchFailed, err)
	}
	req.Header.Set("Accept", "application/json")

	start := time.Now()
	resp, err := f.client.Do(req)
	f.metrics.CIMDFetchDuration.Record(ctx, time.Since(start).Seconds())

	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return nil, fmt.Errorf("%w: %v", domain.ErrCIMDFetchFailed, err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		statusErr := fmt.Errorf("%w: HTTP %d from %s", domain.ErrCIMDFetchFailed, resp.StatusCode, docURL)
		span.RecordError(statusErr)
		span.SetStatus(codes.Error, statusErr.Error())
		return nil, statusErr
	}

	// Validate Content-Type.
	ct := resp.Header.Get("Content-Type")
	if !isJSONContentType(ct) {
		ctErr := fmt.Errorf("%w: expected JSON content-type, got %q", domain.ErrCIMDInvalid, ct)
		span.RecordError(ctErr)
		span.SetStatus(codes.Error, ctErr.Error())
		return nil, ctErr
	}

	// Parse body (enforce max size).
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxCIMDBodySize+1))
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return nil, fmt.Errorf("%w: read body: %v", domain.ErrCIMDFetchFailed, err)
	}
	if len(body) > maxCIMDBodySize {
		err := fmt.Errorf("%w: response body exceeds maximum size (%d bytes)", domain.ErrCIMDFetchFailed, maxCIMDBodySize)
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}

	var doc output.CIMDDocument
	if err := json.Unmarshal(body, &doc); err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return nil, fmt.Errorf("%w: invalid JSON: %v", domain.ErrCIMDInvalid, err)
	}

	// Validate required fields.
	if err := validateDocument(&doc, docURL); err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
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

	// Cache the result.
	f.putCache(docURL, &doc)

	f.logger.InfoContext(ctx, "fetched cimd document", "url", docURL, "client_name", doc.ClientName)
	return &doc, nil
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
// or unspecified addresses to prevent SSRF attacks.
func (f *Fetcher) validateURLSafety(parsed *url.URL) error {
	host := parsed.Hostname()

	// Reject known dangerous hostnames.
	if strings.EqualFold(host, "localhost") {
		if f.allowLoopback {
			return nil
		}
		return fmt.Errorf("%w: loopback address rejected: %s", domain.ErrCIMDFetchFailed, host)
	}

	ip := net.ParseIP(host)
	if ip == nil {
		// Not an IP literal — hostname will be resolved by the HTTP client.
		// URL-level check can only catch literals and "localhost".
		return nil
	}

	if ip.IsLoopback() {
		if f.allowLoopback {
			return nil
		}
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

func (f *Fetcher) putCache(key string, doc *output.CIMDDocument) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.cache[key] = &cacheEntry{
		doc:       doc,
		expiresAt: time.Now().Add(f.cacheTTL),
	}
}
