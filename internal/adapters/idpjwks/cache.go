// Package idpjwks provides a JWKS fetcher and cache for trusted IdP issuers.
package idpjwks

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"syscall"
	"time"

	"github.com/go-jose/go-jose/v4"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"

	"github.com/authplane/authserver/internal/observability"
	"github.com/authplane/authserver/internal/ports/output"
	"github.com/authplane/authserver/internal/ssrf"
)

var _ output.IDPJWKSCache = (*Cache)(nil)

// Entry is a cached JWKS together with the instant it goes stale. It is the
// value type the injected cache stores; callers construct that cache as
// cache.NewMemory[*idpjwks.Entry](). Its fields are internal — the cache only
// stores and returns whole entries.
type Entry struct {
	keys      *jose.JSONWebKeySet
	expiresAt time.Time
}

// Cache fronts an injected output.Cache with SSRF-protected JWKS fetching.
//
// Freshness and resilience are owned here, not by the injected cache (which is
// a plain keyed store that never auto-expires): an entry is served while fresh
// (within TTL); on a fetch failure the last entry is served as a bounded
// stale-while-revalidate fallback while it is no more than MaxStale past expiry,
// so a transient IdP outage does not break token validation.
type Cache struct {
	cache    output.Cache[*Entry]
	idpStore output.IDPStore // resolve issuer → jwks_uri
	client   *http.Client
	ttl      time.Duration
	maxStale time.Duration
	now      func() time.Time
	logger   *slog.Logger
	tracer   trace.Tracer
}

// CacheConfig holds configuration for the JWKS cache.
type CacheConfig struct {
	TTL          time.Duration // freshness window (default: 1h)
	MaxStale     time.Duration // how long past expiry a stale entry may be served on fetch failure (default: 24h)
	FetchTimeout time.Duration // HTTP fetch timeout (default: 10s)
}

// New creates a JWKS cache with SSRF protections. cache is required (e.g.
// cache.NewMemory[*Entry]() for the in-memory default, or a partition-aware
// implementation); freshness and bounded stale-while-revalidate are applied by
// this type regardless of the injected store.
func New(idpStore output.IDPStore, cache output.Cache[*Entry], cfg CacheConfig, obs *observability.Provider, opts ...Option) *Cache {
	if cfg.TTL == 0 {
		cfg.TTL = 1 * time.Hour
	}
	if cfg.MaxStale == 0 {
		cfg.MaxStale = 24 * time.Hour
	}
	if cfg.FetchTimeout == 0 {
		cfg.FetchTimeout = 10 * time.Second
	}

	c := &Cache{
		cache:    cache,
		idpStore: idpStore,
		client:   ssrfSafeClient(cfg.FetchTimeout),
		ttl:      cfg.TTL,
		maxStale: cfg.MaxStale,
		now:      time.Now,
		logger:   obs.Logger.With("component", "idp-jwks-cache"),
		tracer:   obs.Tracer,
	}
	for _, opt := range opts {
		opt(c)
	}
	return c
}

// Option configures a Cache at construction.
type Option func(*Cache)

// WithHTTPClient replaces the SSRF-protected HTTP client that New builds.
//
// TEST ONLY. The replacement client has NO SSRF protection: it will happily
// fetch a JWKS from loopback, RFC 1918 space, or CGNAT. Production wiring must
// never use it — enforced by scripts/ssrflint rule R1, which fails the build on
// any call outside a _test.go file, a testdata directory, or a file that
// requires the //go:build e2e tag. R1 matches calls, not every mention of the
// symbol, so it is a guard against wiring this up by accident rather than a
// boundary anything hostile would respect.
func WithHTTPClient(client *http.Client) Option {
	return func(c *Cache) { c.client = client }
}

// GetKeys returns the JWKS for an IdP issuer, fetching and caching as needed.
func (c *Cache) GetKeys(ctx context.Context, issuer string) (*jose.JSONWebKeySet, error) {
	ctx, span := c.tracer.Start(ctx, "IDPJWKSCache.GetKeys")
	defer span.End()

	// Fast path: serve the entry while it is fresh.
	entry, _ := c.cache.Load(ctx, issuer)
	now := c.now()
	if entry != nil && now.Before(entry.expiresAt) {
		return entry.keys, nil
	}

	// Resolve jwks_uri from IdP store.
	idp, err := c.idpStore.GetByIssuer(ctx, issuer)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return nil, fmt.Errorf("resolve IdP for issuer %q: %w", issuer, err)
	}

	jwksURI := idp.JWKSUri

	// Fetch JWKS from the IdP.
	keys, err := c.fetchJWKS(ctx, jwksURI)
	if err != nil {
		// Bounded stale-while-revalidate: on fetch failure serve the last known
		// entry while it is within MaxStale of its expiry, so a transient IdP
		// outage doesn't break token validation.
		if entry != nil && now.Before(entry.expiresAt.Add(c.maxStale)) {
			c.logger.WarnContext(ctx, "JWKS fetch failed, serving stale cache",
				"issuer", issuer, "error", err,
				"stale_since", entry.expiresAt.Format("2006-01-02T15:04:05Z"),
			)
			return entry.keys, nil
		}
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return nil, fmt.Errorf("fetch JWKS from %q: %w", jwksURI, err)
	}

	// Cache the result.
	_ = c.cache.Store(ctx, issuer, &Entry{keys: keys, expiresAt: now.Add(c.ttl)})
	c.logger.InfoContext(ctx, "cached IdP JWKS", "issuer", issuer)
	return keys, nil
}

// InvalidateCache forces re-fetch on next GetKeys call for the given issuer.
func (c *Cache) InvalidateCache(ctx context.Context, issuer string) error {
	return c.cache.Invalidate(ctx, issuer)
}

// fetchJWKS fetches a JWKS from the given URI with SSRF protections.
func (c *Cache) fetchJWKS(ctx context.Context, jwksURI string) (*jose.JSONWebKeySet, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, jwksURI, http.NoBody)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Accept", "application/json")

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("http get: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status %d from %s", resp.StatusCode, jwksURI)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 512*1024)) // 512KB limit
	if err != nil {
		return nil, fmt.Errorf("read response body: %w", err)
	}

	var jwks jose.JSONWebKeySet
	if err := json.Unmarshal(body, &jwks); err != nil {
		return nil, fmt.Errorf("parse JWKS: %w", err)
	}

	return &jwks, nil
}

// ssrfSafeDialer returns a dialer whose Control hook re-checks the concrete
// resolved IP immediately before connect(2).
//
// This is what closes the DNS-rebinding window: ssrfSafeClient's DialContext
// validates the addresses the resolver returned, but then dials the *hostname*,
// which Go's resolver, inside net.Dialer, resolves a second time. An attacker
// controlling the authoritative DNS can answer differently on that second
// lookup. The hook sees the address that will actually be connected to.
//
// Deleting the hook reopens the window — TestSSRFSafeDialer_RefusesLiveLoopbackListener
// is there to make that a runtime test failure rather than a silent regression.
func ssrfSafeDialer(timeout time.Duration) *net.Dialer {
	return &net.Dialer{
		Timeout: timeout,
		Control: func(network, address string, _ syscall.RawConn) error {
			host, _, err := net.SplitHostPort(address)
			if err != nil {
				return fmt.Errorf("invalid address %q: %w", address, err)
			}
			ip := net.ParseIP(host)
			if ip == nil {
				return fmt.Errorf("SSRF protection: refusing connection to unparseable host %q", host)
			}
			if ssrf.IsPrivateIP(ip) {
				return fmt.Errorf("SSRF protection: refusing connection to private IP %s (post-connect check)", ip)
			}
			return nil
		},
	}
}

// ssrfSafeClient creates an HTTP client that refuses connections to private/loopback IPs.
// It validates IPs both at DNS resolution time and after TCP connection to prevent
// DNS rebinding attacks.
func ssrfSafeClient(timeout time.Duration) *http.Client {
	// dialer must be built by ssrfSafeDialer, never by a bare &net.Dialer{}.
	// Its Control hook is the DNS-rebinding guard described on that function's
	// doc comment above. No test on this branch can tell the two apart: the
	// pre-resolution sweep just below already validates every address an
	// IP-literal host would ever present to the hook, so a substitution here
	// fails silently — the suite stays green and the rebinding window quietly
	// reopens.
	dialer := ssrfSafeDialer(timeout)

	transport := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			host, _, err := net.SplitHostPort(addr)
			if err != nil {
				return nil, fmt.Errorf("invalid address %q: %w", addr, err)
			}

			ips, err := (&net.Resolver{}).LookupIPAddr(ctx, host)
			if err != nil {
				return nil, fmt.Errorf("dns lookup %q: %w", host, err)
			}

			for _, ipAddr := range ips {
				if ssrf.IsPrivateIP(ipAddr.IP) {
					return nil, fmt.Errorf("SSRF protection: refusing connection to private IP %s for host %s", ipAddr.IP, host)
				}
			}

			return dialer.DialContext(ctx, network, addr)
		},
		TLSHandshakeTimeout: timeout,
	}

	return &http.Client{
		Transport: transport,
		Timeout:   timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse // no redirects
		},
	}
}
