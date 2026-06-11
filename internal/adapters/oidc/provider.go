// Package oidc implements upstream OIDC federation using net/http + go-jose/v4.
package oidc

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/go-jose/go-jose/v4"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"

	"github.com/authplane/authserver/internal/observability"
	"github.com/authplane/authserver/internal/ports/output"
)

var _ output.OIDCProvider = (*Provider)(nil)

// discoveryDoc holds the relevant fields from /.well-known/openid-configuration.
type discoveryDoc struct {
	Issuer                string   `json:"issuer"`
	AuthorizationEndpoint string   `json:"authorization_endpoint"`
	TokenEndpoint         string   `json:"token_endpoint"`
	JWKSURI               string   `json:"jwks_uri"`
	UserInfoEndpoint      string   `json:"userinfo_endpoint"`
	ScopesSupported       []string `json:"scopes_supported"`
}

// Provider implements output.OIDCProvider for a single upstream OIDC IdP.
type Provider struct {
	issuer             string
	clientID           string
	clientSecret       string
	scopes             []string
	includeGroupsScope bool
	connectorID        string

	discovery discoveryDoc

	mu   sync.RWMutex
	jwks *jose.JSONWebKeySet

	httpClient *http.Client
	logger     *slog.Logger
	tracer     trace.Tracer
	metrics    *observability.Metrics
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

// New creates an OIDC Provider by performing discovery against the upstream issuer.
// It fetches the OIDC discovery document and initial JWKS at startup.
// Returns an error if discovery fails (prevents server from starting with bad config).
func New(
	ctx context.Context,
	issuer, clientID, clientSecret string,
	scopes []string,
	includeGroupsScope bool,
	connectorID string,
	obs *observability.Provider,
	opts ...Option,
) (*Provider, error) {
	ctx, span := obs.Tracer.Start(ctx, "OIDC.New")
	defer span.End()
	span.SetAttributes(attribute.String("oidc.issuer", issuer))

	if len(scopes) == 0 {
		scopes = []string{"openid", "email", "profile"}
	}

	p := &Provider{
		issuer:             issuer,
		clientID:           clientID,
		clientSecret:       clientSecret,
		scopes:             scopes,
		includeGroupsScope: includeGroupsScope,
		connectorID:        connectorID,
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
	}

	// Apply options (e.g. WithHTTPClient for tests).
	for _, opt := range opts {
		opt(p)
	}

	if err := p.discover(ctx); err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return nil, fmt.Errorf("OIDC discovery: %w", err)
	}

	if err := p.fetchJWKS(ctx); err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return nil, fmt.Errorf("OIDC JWKS fetch: %w", err)
	}

	obs.Logger.InfoContext(ctx, "OIDC provider initialized",
		"issuer", issuer,
		"authorization_endpoint", p.discovery.AuthorizationEndpoint,
		"token_endpoint", p.discovery.TokenEndpoint,
		"userinfo_endpoint", p.discovery.UserInfoEndpoint,
		"scopes_supported", p.discovery.ScopesSupported,
	)

	return p, nil
}

// AuthorizationURL builds the URL to redirect the user to the upstream IdP.
func (p *Provider) AuthorizationURL(state, nonce, codeChallenge, redirectURI string) string {
	scopes := p.effectiveScopes()
	v := url.Values{
		"response_type": {"code"},
		"client_id":     {p.clientID},
		"redirect_uri":  {redirectURI},
		"scope":         {strings.Join(scopes, " ")},
		"state":         {state},
		"nonce":         {nonce},
	}
	if codeChallenge != "" {
		v.Set("code_challenge", codeChallenge)
		v.Set("code_challenge_method", "S256")
	}
	if p.connectorID != "" {
		v.Set("connector_id", p.connectorID)
	}
	return p.discovery.AuthorizationEndpoint + "?" + v.Encode()
}

// ExchangeCode exchanges an authorization code for tokens and verifies the ID token.
func (p *Provider) ExchangeCode(ctx context.Context, code, nonce, codeVerifier, redirectURI string) (*output.OIDCTokenResult, error) {
	ctx, span := p.tracer.Start(ctx, "OIDC.ExchangeCode")
	defer span.End()

	start := time.Now()
	defer func() {
		p.metrics.OIDCExchangeDuration.Record(ctx, time.Since(start).Seconds())
	}()

	// 1. Exchange code for tokens.
	tokenResp, err := p.exchangeCode(ctx, code, codeVerifier, redirectURI)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return nil, fmt.Errorf("code exchange: %w", err)
	}

	// 2. Parse and verify the ID token.
	result, err := p.verifyIDToken(ctx, tokenResp.IDToken, nonce)
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
	if p.discovery.UserInfoEndpoint == "" {
		return nil, nil
	}

	ctx, span := p.tracer.Start(ctx, "OIDC.GetUserInfo")
	defer span.End()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, p.discovery.UserInfoEndpoint, http.NoBody)
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
// If includeGroupsScope is true and the upstream supports "groups", it is auto-added.
func (p *Provider) effectiveScopes() []string {
	scopes := make([]string, 0, len(p.scopes)+1)
	scopes = append(scopes, p.scopes...)

	if !p.includeGroupsScope {
		return scopes
	}

	// Check if upstream supports "groups" scope.
	if !p.upstreamSupportsScope("groups") {
		return scopes
	}

	// Check if "groups" is already in the configured scopes.
	for _, s := range scopes {
		if s == "groups" {
			return scopes
		}
	}

	return append(scopes, "groups")
}

func (p *Provider) upstreamSupportsScope(scope string) bool {
	for _, s := range p.discovery.ScopesSupported {
		if s == scope {
			return true
		}
	}
	return false
}

// --- internal helpers ---

func (p *Provider) discover(ctx context.Context) error {
	ctx, span := p.tracer.Start(ctx, "OIDC.discover")
	defer span.End()

	discoveryURL := strings.TrimRight(p.issuer, "/") + "/.well-known/openid-configuration"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, discoveryURL, http.NoBody)
	if err != nil {
		return fmt.Errorf("build discovery request: %w", err)
	}

	resp, err := p.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("fetch discovery document: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("discovery returned status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20)) // 1 MB limit
	if err != nil {
		return fmt.Errorf("read discovery body: %w", err)
	}

	var doc discoveryDoc
	if err := json.Unmarshal(body, &doc); err != nil {
		return fmt.Errorf("parse discovery document: %w", err)
	}

	// Validate required fields.
	if doc.Issuer == "" {
		return fmt.Errorf("discovery document missing issuer")
	}
	if doc.Issuer != p.issuer {
		return fmt.Errorf("discovery issuer %q does not match configured issuer %q", doc.Issuer, p.issuer)
	}
	if doc.AuthorizationEndpoint == "" {
		return fmt.Errorf("discovery document missing authorization_endpoint")
	}
	if doc.TokenEndpoint == "" {
		return fmt.Errorf("discovery document missing token_endpoint")
	}
	if doc.JWKSURI == "" {
		return fmt.Errorf("discovery document missing jwks_uri")
	}

	p.discovery = doc
	p.logger.DebugContext(ctx, "OIDC discovery completed",
		"jwks_uri", doc.JWKSURI,
		"userinfo_endpoint", doc.UserInfoEndpoint,
	)
	return nil
}

func (p *Provider) fetchJWKS(ctx context.Context) error {
	ctx, span := p.tracer.Start(ctx, "OIDC.fetchJWKS")
	defer span.End()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, p.discovery.JWKSURI, http.NoBody)
	if err != nil {
		return fmt.Errorf("build JWKS request: %w", err)
	}

	resp, err := p.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("fetch JWKS: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("JWKS returned status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return fmt.Errorf("read JWKS body: %w", err)
	}

	var jwks jose.JSONWebKeySet
	if err := json.Unmarshal(body, &jwks); err != nil {
		return fmt.Errorf("parse JWKS: %w", err)
	}

	p.mu.Lock()
	p.jwks = &jwks
	p.mu.Unlock()

	p.logger.DebugContext(ctx, "OIDC JWKS fetched", "key_count", len(jwks.Keys))
	return nil
}

type tokenResponse struct {
	IDToken     string `json:"id_token"`
	AccessToken string `json:"access_token"`
}

func (p *Provider) exchangeCode(ctx context.Context, code, codeVerifier, redirectURI string) (*tokenResponse, error) {
	ctx, span := p.tracer.Start(ctx, "OIDC.exchangeCode")
	defer span.End()

	data := url.Values{
		"grant_type":   {"authorization_code"},
		"code":         {code},
		"redirect_uri": {redirectURI},
		"client_id":    {p.clientID},
	}
	if codeVerifier != "" {
		data.Set("code_verifier", codeVerifier)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.discovery.TokenEndpoint, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, fmt.Errorf("build token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(p.clientID, p.clientSecret)

	resp, err := p.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("token endpoint request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("read token response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		p.logger.WarnContext(ctx, "OIDC token endpoint error",
			"status", resp.StatusCode,
		)
		return nil, fmt.Errorf("token endpoint returned status %d", resp.StatusCode)
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
