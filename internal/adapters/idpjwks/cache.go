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
	"sync"
	"syscall"
	"time"

	"github.com/go-jose/go-jose/v4"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"

	"github.com/authplane/authserver/internal/observability"
	"github.com/authplane/authserver/internal/ports/output"
)

var _ output.IDPJWKSCache = (*Cache)(nil)

// cacheEntry holds a cached JWKS and its expiry.
type cacheEntry struct {
	keys      *jose.JSONWebKeySet
	expiresAt time.Time
}

// Cache is an in-memory JWKS cache with SSRF-protected HTTP fetching.
type Cache struct {
	mu      sync.RWMutex
	entries map[string]*cacheEntry // keyed by issuer

	idpStore output.IDPStore // resolve issuer → jwks_uri
	client   *http.Client
	ttl      time.Duration
	logger   *slog.Logger
	tracer   trace.Tracer
}

// CacheConfig holds configuration for the JWKS cache.
type CacheConfig struct {
	TTL          time.Duration // Cache TTL (default: 1 hour)
	FetchTimeout time.Duration // HTTP fetch timeout (default: 10s)
}

// New creates a JWKS cache with SSRF protections.
func New(idpStore output.IDPStore, cfg CacheConfig, obs *observability.Provider) *Cache {
	if cfg.TTL == 0 {
		cfg.TTL = 1 * time.Hour
	}
	if cfg.FetchTimeout == 0 {
		cfg.FetchTimeout = 10 * time.Second
	}

	return &Cache{
		entries:  make(map[string]*cacheEntry),
		idpStore: idpStore,
		client:   ssrfSafeClient(cfg.FetchTimeout),
		ttl:      cfg.TTL,
		logger:   obs.Logger.With("component", "idp-jwks-cache"),
		tracer:   obs.Tracer,
	}
}

// WithHTTPClient replaces the default SSRF-protected HTTP client.
// This is useful for testing where JWKS endpoints run on localhost.
func (c *Cache) WithHTTPClient(client *http.Client) {
	c.client = client
}

// GetKeys returns the JWKS for an IdP issuer, fetching and caching as needed.
func (c *Cache) GetKeys(ctx context.Context, issuer string) (*jose.JSONWebKeySet, error) {
	ctx, span := c.tracer.Start(ctx, "IDPJWKSCache.GetKeys")
	defer span.End()

	// Check cache first.
	c.mu.RLock()
	entry, ok := c.entries[issuer]
	c.mu.RUnlock()

	if ok && time.Now().Before(entry.expiresAt) {
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
		// Stale-while-revalidate: serve expired cache entry on fetch failure.
		if ok && entry != nil {
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
	c.mu.Lock()
	c.entries[issuer] = &cacheEntry{
		keys:      keys,
		expiresAt: time.Now().Add(c.ttl),
	}
	c.mu.Unlock()

	c.logger.InfoContext(ctx, "cached IdP JWKS", "issuer", issuer)
	return keys, nil
}

// InvalidateCache forces re-fetch on next GetKeys call for the given issuer.
func (c *Cache) InvalidateCache(ctx context.Context, issuer string) error {
	c.mu.Lock()
	delete(c.entries, issuer)
	c.mu.Unlock()
	c.logger.InfoContext(ctx, "invalidated JWKS cache", "issuer", issuer)
	return nil
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

// ssrfSafeClient creates an HTTP client that refuses connections to private/loopback IPs.
// It validates IPs both at DNS resolution time and after TCP connection to prevent
// DNS rebinding attacks.
func ssrfSafeClient(timeout time.Duration) *http.Client {
	dialer := &net.Dialer{
		Timeout: timeout,
		Control: func(network, address string, conn syscall.RawConn) error {
			host, _, err := net.SplitHostPort(address)
			if err != nil {
				return fmt.Errorf("invalid address %q: %w", address, err)
			}
			ip := net.ParseIP(host)
			if ip != nil && isPrivateIP(ip) {
				return fmt.Errorf("SSRF protection: refusing connection to private IP %s (post-connect check)", ip)
			}
			return nil
		},
	}

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
				if isPrivateIP(ipAddr.IP) {
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

// isPrivateIP returns true if the IP is loopback, link-local, or private (RFC 1918, RFC 4193).
func isPrivateIP(ip net.IP) bool {
	return ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsUnspecified()
}
