// Package oidc implements upstream OIDC federation using net/http + go-jose/v4.
package oidc

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v4"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
	"golang.org/x/sync/singleflight"

	"github.com/authplane/authserver/internal/domain"
	"github.com/authplane/authserver/internal/observability"
	"github.com/authplane/authserver/internal/ports/output"
)

var _ output.OIDCProvider = (*Provider)(nil)

// DiscoveryDoc holds the relevant fields from /.well-known/openid-configuration.
type DiscoveryDoc struct {
	Issuer                string   `json:"issuer"`
	AuthorizationEndpoint string   `json:"authorization_endpoint"`
	TokenEndpoint         string   `json:"token_endpoint"`
	JWKSURI               string   `json:"jwks_uri"`
	UserInfoEndpoint      string   `json:"userinfo_endpoint"`
	ScopesSupported       []string `json:"scopes_supported"`
}

const (
	defaultDiscoveryTTL = time.Hour        // discovery documents are very stable
	defaultJWKSTTL      = 15 * time.Minute // keys rotate; a kid miss forces a refresh anyway

	// Stale caps bound how long a fetch failure may keep serving an expired
	// entry. Discovery carries no security material, so it tolerates a long
	// outage; JWKS is capped tighter to bound the window in which a key revoked
	// during an outage could still verify a token.
	defaultDiscoveryMaxStale = 24 * time.Hour
	defaultJWKSMaxStale      = time.Hour
)

// Provider implements output.OIDCProvider. It resolves the upstream OIDC
// configuration for each call from an injected OIDCConfigProvider, then talks
// to the resolved issuer. The configuration source is per-call, but the
// protocol machinery it drives — the discovery document and JWKS — is cached
// keyed by issuer / jwks_uri, so the upstream IdP is not hit on every request.
//
// The client secret is resolved JIT at exchangeCode via the injected
// secretResolver; other operations (AuthorizationURL, GetUserInfo, Validate)
// do not touch the secret.
type Provider struct {
	config         output.OIDCConfigProvider
	secretResolver output.SecretResolver

	httpClient *http.Client
	logger     *slog.Logger
	tracer     trace.Tracer
	metrics    *observability.Metrics

	disco Cache[DiscoveryDoc]
	jwks  Cache[*jose.JSONWebKeySet]

	// jwksRefresh collapses concurrent kid-miss JWKS refreshes for the same
	// jwks_uri into a single fetch (the cache's own singleflight only covers
	// the freshness-respecting Load path, which a kid miss deliberately bypasses).
	jwksRefresh singleflight.Group
}

// Option configures the Provider.
type Option func(*Provider)

// WithHTTPClient overrides the default SSRF-safe HTTP client.
// Primarily used in tests where httptest.NewServer binds to 127.0.0.1.
func WithHTTPClient(c *http.Client) Option {
	return func(p *Provider) {
		p.httpClient = c
	}
}

// New creates an OIDC Provider. It performs no network I/O at construction;
// the per-call configuration is supplied by config, and discovery / JWKS are
// fetched lazily and cached keyed by issuer. The client secret is resolved JIT
// at exchangeCode via the injected resolver. Call Validate to validate the
// upstream configuration (and warm the cache) at startup.
func New(config output.OIDCConfigProvider, resolver output.SecretResolver, obs *observability.Provider, opts ...Option) *Provider {
	p := &Provider{
		config:         config,
		secretResolver: resolver,
		httpClient: &http.Client{
			Timeout:   15 * time.Second,
			Transport: newSSRFSafeTransport(),
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
		logger:  obs.Logger,
		tracer:  obs.Tracer,
		metrics: obs.Metrics,
		disco:   newTTLCache[DiscoveryDoc](defaultDiscoveryTTL, defaultDiscoveryMaxStale),
		jwks:    newTTLCache[*jose.JSONWebKeySet](defaultJWKSTTL, defaultJWKSMaxStale),
	}
	for _, opt := range opts {
		opt(p)
	}
	return p
}

// WithCacheTTL sets the discovery / JWKS cache TTLs by replacing the default
// in-memory cache for each non-zero duration (a zero value leaves that cache
// untouched). Options apply in the order given, so if WithCacheTTL is combined
// with WithDiscoveryCache / WithJWKSCache, whichever comes last for a given
// cache wins.
func WithCacheTTL(discovery, jwks time.Duration) Option {
	return func(p *Provider) {
		if discovery > 0 {
			p.disco = newTTLCache[DiscoveryDoc](discovery, defaultDiscoveryMaxStale)
		}
		if jwks > 0 {
			p.jwks = newTTLCache[*jose.JSONWebKeySet](jwks, defaultJWKSMaxStale)
		}
	}
}

// WithDiscoveryCache replaces the discovery-document cache. The default is an
// in-memory TTL cache; an alternate implementation (e.g. a cache shared across
// instances) can be supplied here.
func WithDiscoveryCache(c Cache[DiscoveryDoc]) Option {
	return func(p *Provider) {
		if c != nil {
			p.disco = c
		}
	}
}

// WithJWKSCache replaces the JWKS cache. The default is an in-memory TTL cache;
// an alternate implementation can be supplied here.
func WithJWKSCache(c Cache[*jose.JSONWebKeySet]) Option {
	return func(p *Provider) {
		if c != nil {
			p.jwks = c
		}
	}
}

// Validate resolves the configuration and performs discovery + JWKS resolution
// once, returning an error if the upstream OIDC configuration is unreachable or
// invalid. Callers use it at startup to fail fast on misconfiguration (a bad
// issuer or a broken jwks_uri) rather than surfacing it as a 500 on the first
// login; it also warms the discovery and JWKS caches.
func (p *Provider) Validate(ctx context.Context) error {
	cfg, err := p.resolveConfig(ctx)
	if err != nil {
		return err
	}
	doc, err := p.discover(ctx, cfg.Issuer)
	if err != nil {
		return err
	}
	if _, err := p.resolveJWKS(ctx, cfg, doc); err != nil {
		return err
	}
	return nil
}

// AuthorizationURL builds the URL to redirect the user to the upstream IdP.
// It resolves the configuration for the request and discovers the
// authorization endpoint against the resolved issuer.
func (p *Provider) AuthorizationURL(ctx context.Context, state, nonce, codeChallenge string) (string, error) {
	cfg, err := p.resolveConfig(ctx)
	if err != nil {
		return "", err
	}
	doc, err := p.discover(ctx, cfg.Issuer)
	if err != nil {
		return "", err
	}

	scopes := effectiveScopes(cfg, doc)
	v := url.Values{
		"response_type": {"code"},
		"client_id":     {cfg.ClientID},
		"redirect_uri":  {cfg.RedirectURI},
		"scope":         {strings.Join(scopes, " ")},
		"state":         {state},
		"nonce":         {nonce},
	}
	if codeChallenge != "" {
		v.Set("code_challenge", codeChallenge)
		v.Set("code_challenge_method", "S256")
	}
	if cfg.ConnectorID != "" {
		v.Set("connector_id", cfg.ConnectorID)
	}
	return doc.AuthorizationEndpoint + "?" + v.Encode(), nil
}

// ExchangeCode exchanges an authorization code for tokens and verifies the ID token.
func (p *Provider) ExchangeCode(ctx context.Context, code, nonce, codeVerifier string) (*output.OIDCTokenResult, error) {
	ctx, span := p.tracer.Start(ctx, "OIDC.ExchangeCode")
	defer span.End()

	start := time.Now()
	defer func() {
		p.metrics.OIDCExchangeDuration.Record(ctx, time.Since(start).Seconds())
	}()

	// Config / discovery / JWKS resolution failures are infrastructure problems
	// (config source down, IdP unreachable), already tagged with
	// domain.ErrOIDCUnavailable by the helpers so the callback handler maps them
	// to a 500 instead of a 401.
	cfg, err := p.resolveConfig(ctx)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}
	doc, err := p.discover(ctx, cfg.Issuer)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}
	jwks, err := p.resolveJWKS(ctx, cfg, doc)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}

	tokenResp, err := p.exchangeCode(ctx, doc.TokenEndpoint, cfg, code, codeVerifier)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return nil, fmt.Errorf("code exchange: %w", err)
	}

	result, err := p.verifyIDToken(ctx, cfg, doc, jwks, tokenResp.IDToken, nonce)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return nil, fmt.Errorf("ID token verification: %w", err)
	}

	span.SetAttributes(
		attribute.String("oidc.subject", result.Subject),
		attribute.String("oidc.email", result.Email),
	)
	p.logger.InfoContext(ctx, "OIDC code exchange succeeded",
		"subject", result.Subject,
		"email", result.Email,
	)
	return result, nil
}

// GetUserInfo calls the upstream UserInfo endpoint with the given access token.
// Returns nil, nil if the upstream does not expose a userinfo_endpoint.
func (p *Provider) GetUserInfo(ctx context.Context, accessToken string) (*output.OIDCUserInfo, error) {
	cfg, err := p.resolveConfig(ctx)
	if err != nil {
		return nil, err
	}
	doc, err := p.discover(ctx, cfg.Issuer)
	if err != nil {
		return nil, err
	}
	if doc.UserInfoEndpoint == "" {
		return nil, nil
	}

	ctx, span := p.tracer.Start(ctx, "OIDC.GetUserInfo")
	defer span.End()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, doc.UserInfoEndpoint, http.NoBody)
	if err != nil {
		return nil, fmt.Errorf("build userinfo request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)

	resp, err := p.httpClient.Do(req)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return nil, fmt.Errorf("userinfo request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("userinfo returned status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("read userinfo body: %w", err)
	}

	var claims struct {
		Subject string   `json:"sub"`
		Email   string   `json:"email"`
		Name    string   `json:"name"`
		Groups  []string `json:"groups"`
	}
	if err := json.Unmarshal(body, &claims); err != nil {
		return nil, fmt.Errorf("parse userinfo response: %w", err)
	}

	return &output.OIDCUserInfo{
		Subject: claims.Subject,
		Email:   claims.Email,
		Name:    claims.Name,
		Groups:  claims.Groups,
	}, nil
}

// effectiveScopes returns the scopes to use in authorization requests.
// If cfg.IncludeGroupsScope is true and the upstream supports "groups", it is
// auto-added.
func effectiveScopes(cfg output.OIDCConfig, doc DiscoveryDoc) []string {
	scopes := make([]string, 0, len(cfg.Scopes)+1)
	scopes = append(scopes, cfg.Scopes...)
	if len(scopes) == 0 {
		scopes = []string{"openid", "email", "profile"}
	}

	if !cfg.IncludeGroupsScope || !upstreamSupportsScope(doc, "groups") {
		return scopes
	}
	for _, s := range scopes {
		if s == "groups" {
			return scopes
		}
	}
	return append(scopes, "groups")
}

func upstreamSupportsScope(doc DiscoveryDoc, scope string) bool {
	for _, s := range doc.ScopesSupported {
		if s == scope {
			return true
		}
	}
	return false
}

// --- internal helpers ---

// resolveConfig resolves the upstream configuration for the request. A failure
// is tagged with domain.ErrOIDCUnavailable so callers — and ultimately the
// callback handler — treat a config-source outage as a 500, not a 401.
func (p *Provider) resolveConfig(ctx context.Context) (output.OIDCConfig, error) {
	cfg, err := p.config.Config(ctx)
	if err != nil {
		return output.OIDCConfig{}, errors.Join(domain.ErrOIDCUnavailable, fmt.Errorf("resolve OIDC config: %w", err))
	}
	return cfg, nil
}

// discover returns the issuer's discovery document, cached with a TTL and
// keyed by issuer. If a refetch fails while a previous copy exists and is still
// within the stale cap, the stale copy is served (the discovery doc is stable,
// so this keeps logins alive through an IdP-metadata outage rather than failing
// them all). Past the cap, the failure surfaces.
func (p *Provider) discover(ctx context.Context, issuer string) (DiscoveryDoc, error) {
	doc, err := p.disco.Load(ctx, issuer, func() (DiscoveryDoc, error) {
		return p.fetchDiscovery(ctx, issuer)
	})
	if err != nil {
		if stale, ok := p.disco.Peek(ctx, issuer); ok {
			p.logger.WarnContext(ctx, "OIDC discovery fetch failed; serving stale",
				"issuer", issuer, "error", err)
			return stale, nil
		}
		return DiscoveryDoc{}, errors.Join(domain.ErrOIDCUnavailable, fmt.Errorf("OIDC discovery: %w", err))
	}
	return doc, nil
}

// fetchDiscovery performs the network fetch + validation of the discovery
// document. It holds no state — caching is the caller's (discover) job.
func (p *Provider) fetchDiscovery(ctx context.Context, issuer string) (DiscoveryDoc, error) {
	ctx, span := p.tracer.Start(ctx, "OIDC.discover")
	defer span.End()

	discoveryURL := strings.TrimRight(issuer, "/") + "/.well-known/openid-configuration"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, discoveryURL, http.NoBody)
	if err != nil {
		return DiscoveryDoc{}, fmt.Errorf("build discovery request: %w", err)
	}

	resp, err := p.httpClient.Do(req)
	if err != nil {
		return DiscoveryDoc{}, fmt.Errorf("fetch discovery document: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return DiscoveryDoc{}, fmt.Errorf("discovery returned status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return DiscoveryDoc{}, fmt.Errorf("read discovery body: %w", err)
	}

	var doc DiscoveryDoc
	if err := json.Unmarshal(body, &doc); err != nil {
		return DiscoveryDoc{}, fmt.Errorf("parse discovery document: %w", err)
	}

	if doc.Issuer == "" {
		return DiscoveryDoc{}, fmt.Errorf("discovery document missing issuer")
	}
	if doc.Issuer != issuer {
		return DiscoveryDoc{}, fmt.Errorf("discovery issuer %q does not match configured issuer %q", doc.Issuer, issuer)
	}
	if doc.AuthorizationEndpoint == "" {
		return DiscoveryDoc{}, fmt.Errorf("discovery document missing authorization_endpoint")
	}
	if doc.TokenEndpoint == "" {
		return DiscoveryDoc{}, fmt.Errorf("discovery document missing token_endpoint")
	}
	if doc.JWKSURI == "" {
		return DiscoveryDoc{}, fmt.Errorf("discovery document missing jwks_uri")
	}

	p.logger.DebugContext(ctx, "OIDC discovery completed",
		"jwks_uri", doc.JWKSURI,
		"userinfo_endpoint", doc.UserInfoEndpoint,
	)
	return doc, nil
}

// resolveJWKS returns the key set for verification. Configured JWKS bytes are
// authoritative and bypass the network entirely (a pinned-keys override).
// Otherwise the set is fetched from the discovered jwks_uri, cached keyed by
// jwks_uri, with a stale fallback if a refetch fails. The cache hit/miss
// counters reflect whether this call went to the network.
func (p *Provider) resolveJWKS(ctx context.Context, cfg output.OIDCConfig, doc DiscoveryDoc) (*jose.JSONWebKeySet, error) {
	if len(cfg.JWKS) > 0 {
		var ks jose.JSONWebKeySet
		if err := json.Unmarshal(cfg.JWKS, &ks); err != nil {
			return nil, errors.Join(domain.ErrOIDCUnavailable, fmt.Errorf("parse configured JWKS: %w", err))
		}
		return &ks, nil
	}

	if _, ok := p.jwks.Fresh(ctx, doc.JWKSURI); ok {
		p.metrics.OIDCJWKSCacheHits.Add(ctx, 1)
	} else {
		p.metrics.OIDCJWKSCacheMisses.Add(ctx, 1)
	}

	ks, err := p.jwks.Load(ctx, doc.JWKSURI, func() (*jose.JSONWebKeySet, error) {
		return p.fetchJWKS(ctx, doc.JWKSURI)
	})
	if err != nil {
		if stale, ok := p.jwks.Peek(ctx, doc.JWKSURI); ok {
			p.logger.WarnContext(ctx, "JWKS fetch failed; serving stale",
				"jwks_uri", doc.JWKSURI, "error", err)
			return stale, nil
		}
		return nil, errors.Join(domain.ErrOIDCUnavailable, fmt.Errorf("resolve JWKS: %w", err))
	}
	return ks, nil
}

// refreshJWKS forces a fresh fetch on a kid miss (key rotation), bypassing the
// cache, and updates the cache for concurrent verifiers. Pinned keys cannot be
// refreshed — there is nowhere to fetch them from — so they are returned as is.
func (p *Provider) refreshJWKS(ctx context.Context, cfg output.OIDCConfig, doc DiscoveryDoc) (*jose.JSONWebKeySet, error) {
	if len(cfg.JWKS) > 0 {
		return p.resolveJWKS(ctx, cfg, doc)
	}
	// Collapse concurrent refreshes for the same jwks_uri into one fetch, so a
	// burst of callbacks during a key rotation does not stampede the IdP.
	v, err, _ := p.jwksRefresh.Do(doc.JWKSURI, func() (any, error) {
		ks, ferr := p.fetchJWKS(ctx, doc.JWKSURI)
		if ferr != nil {
			return nil, ferr
		}
		p.jwks.Store(ctx, doc.JWKSURI, ks)
		return ks, nil
	})
	if err != nil {
		return nil, errors.Join(domain.ErrOIDCUnavailable, fmt.Errorf("refresh JWKS: %w", err))
	}
	return v.(*jose.JSONWebKeySet), nil
}

func (p *Provider) fetchJWKS(ctx context.Context, jwksURI string) (*jose.JSONWebKeySet, error) {
	ctx, span := p.tracer.Start(ctx, "OIDC.fetchJWKS")
	defer span.End()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, jwksURI, http.NoBody)
	if err != nil {
		return nil, fmt.Errorf("build JWKS request: %w", err)
	}

	resp, err := p.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch JWKS: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("JWKS returned status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("read JWKS body: %w", err)
	}

	var jwks jose.JSONWebKeySet
	if err := json.Unmarshal(body, &jwks); err != nil {
		return nil, fmt.Errorf("parse JWKS: %w", err)
	}

	p.logger.DebugContext(ctx, "OIDC JWKS fetched", "key_count", len(jwks.Keys))
	return &jwks, nil
}

type tokenResponse struct {
	IDToken     string `json:"id_token"`
	AccessToken string `json:"access_token"`
}

func (p *Provider) exchangeCode(ctx context.Context, tokenEndpoint string, cfg output.OIDCConfig, code, codeVerifier string) (*tokenResponse, error) {
	ctx, span := p.tracer.Start(ctx, "OIDC.exchangeCode")
	defer span.End()

	data := url.Values{
		"grant_type":   {"authorization_code"},
		"code":         {code},
		"redirect_uri": {cfg.RedirectURI},
		"client_id":    {cfg.ClientID},
	}
	if codeVerifier != "" {
		data.Set("code_verifier", codeVerifier)
	}

	// Resolve the client secret JIT: the DTO carries exactly one of an env-var
	// ref (cfg.ClientSecretRef) or the inline secret's at-rest bytes
	// (cfg.ClientSecret). The default wired backend is inline-tolerant with no
	// encryptor, so it returns the inline bytes as plaintext or resolves the ref
	// via env lookup — it never decrypts. The Owner scopes the secret to this
	// connector for a deployment that swaps in an encrypted store (decrypt
	// under the Owner-derived ownerContext).
	secret, err := p.secretResolver.Resolve(ctx, output.GetSecretSourceForOIDC(cfg))
	if err != nil {
		return nil, fmt.Errorf("resolve oidc client secret: %w", err)
	}
	// Fail closed locally: an empty resolved secret (e.g. an env var present but
	// blank) must not turn into SetBasicAuth(clientID, "") — mirrors the broker
	// adapters' empty-result guard rather than relying solely on validate.go +
	// the boot probe staying in sync.
	if secret == "" {
		return nil, fmt.Errorf("oidc client secret resolved to empty")
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenEndpoint, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, fmt.Errorf("build token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(cfg.ClientID, secret)

	resp, err := p.httpClient.Do(req)
	if err != nil {
		// Reaching the token endpoint failed (transport) — an infra problem,
		// not bad credentials. In a typical callback discovery + JWKS are served
		// from cache, so this POST is often the only live call to the IdP, which
		// makes correct classification here the common case.
		return nil, errors.Join(domain.ErrOIDCUnavailable, fmt.Errorf("token endpoint request: %w", err))
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, errors.Join(domain.ErrOIDCUnavailable, fmt.Errorf("read token response: %w", err))
	}

	if resp.StatusCode != http.StatusOK {
		p.logger.WarnContext(ctx, "OIDC token endpoint error",
			"status", resp.StatusCode,
		)
		statusErr := fmt.Errorf("token endpoint returned status %d", resp.StatusCode)
		if resp.StatusCode >= 500 {
			// 5xx is the IdP being unavailable, not an auth failure → 500.
			return nil, errors.Join(domain.ErrOIDCUnavailable, statusErr)
		}
		// 4xx (invalid_grant, invalid_client, …) is a genuine credential/auth
		// failure → leave untagged so the handler renders 401.
		return nil, statusErr
	}

	var tr tokenResponse
	if err := json.Unmarshal(body, &tr); err != nil {
		return nil, fmt.Errorf("parse token response: %w", err)
	}
	if tr.IDToken == "" {
		return nil, fmt.Errorf("token response missing id_token")
	}
	return &tr, nil
}

// idTokenClaims, verifyIDToken, and getKeys are in verify.go.
