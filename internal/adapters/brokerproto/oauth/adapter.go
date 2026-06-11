// Package oauth implements the BrokerProtocol port for upstream OAuth 2.0
// providers — the upstream-facing OAuth dance (authorize URL + code
// exchange) plus refresh-token vending.
// Per the resource-unification design and the architecture doc, all
// protocol-specific knowledge — wire shape, scope translation, error
// mapping — lives behind this single adapter.
package oauth

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/authplane/authserver/internal/brokerproto"
	"github.com/authplane/authserver/internal/crypto"
	"github.com/authplane/authserver/internal/domain/resource"
	"github.com/authplane/authserver/internal/ports/output"
	"github.com/authplane/authserver/internal/ssrf"
)

// connectStateTTL is how long a ConnectPendingState remains valid before the
// callback handler must reject it. Matches the authorization-code window in
// RFC 6749 §4.1.2 ("10 minutes is recommended").
const connectStateTTL = 10 * time.Minute

// maxResponseBodySize bounds upstream response reads to avoid memory
// exhaustion from a hostile or buggy provider. 1 MiB is comfortably above
// any legitimate token-endpoint response. Mirrors the cap in the legacy
// connector adapter.
const maxResponseBodySize = 1 << 20

// SecretResolver resolves an environment-variable name (as configured in
// configData.ClientSecretEnv) to the plaintext client secret. The
// implementation must reject names that fall outside the
// connector.ValidEnvVarName allowlist to prevent enumeration of arbitrary
// process env vars. Wired in the cmd/ layer.
type SecretResolver interface {
	Resolve(envVarName string) (string, error)
}

// Adapter implements output.BrokerProtocol for upstream providers that speak
// OAuth 2.0 authorization-code-with-PKCE plus refresh tokens (RFC 6749
// §4.1, RFC 7636). One adapter instance handles every BrokerProvider whose
// Protocol is "oauth"; per-provider state lives in BrokerProvider.ConfigData.
type Adapter struct {
	httpClient     *http.Client
	secretResolver SecretResolver
	callbackURL    string
	allowLoopback  bool
}

// Option configures an Adapter at construction. The functional-options
// form keeps the BrokerProtocol port's required New(httpClient, sr)
// shape while letting wiring and tests supply additional knobs without
// breaking callers.
type Option func(*Adapter)

// WithCallbackURL sets the OAuth redirect_uri the adapter emits in the
// authorize URL. Empty (the default) omits redirect_uri, leaving the
// upstream to fall back to whatever it has registered for the client
// credentials. Wired by cmd/authserver/serve.go.
func WithCallbackURL(u string) Option {
	return func(a *Adapter) { a.callbackURL = u }
}

// WithAllowLoopback enables 127.0.0.1 / ::1 token URLs for tests that point
// the adapter at httptest.NewServer. MUST NOT be used in production —
// production binaries leave it false so SSRF protection rejects loopback.
func WithAllowLoopback(allow bool) Option {
	return func(a *Adapter) { a.allowLoopback = allow }
}

// New builds an Adapter with the given HTTP client and secret resolver.
// The HTTP client should set conservative timeouts and disable redirect
// following on POST flows; the wiring layer is responsible for that.
func New(httpClient *http.Client, sr SecretResolver, opts ...Option) *Adapter {
	a := &Adapter{
		httpClient:     httpClient,
		secretResolver: sr,
	}
	for _, opt := range opts {
		opt(a)
	}
	return a
}

// Static interface assertion — fails to compile if the port surface drifts.
var _ output.BrokerProtocol = (*Adapter)(nil)

// Name returns the protocol identifier matching broker_providers.protocol
// values whose dispatch lands on this adapter.
func (a *Adapter) Name() string { return "oauth" }

// BuildConnectURL constructs the upstream authorize URL and the pending
// state to persist for the eventual callback.
func (a *Adapter) BuildConnectURL(
	ctx context.Context,
	p *resource.BrokerProvider,
	r *resource.Resource,
	userID, returnURL, callbackURL string,
	requestedScopes []string,
) (string, *resource.ConnectPendingState, error) {
	if p == nil || r == nil {
		return "", nil, fmt.Errorf("oauth: BuildConnectURL requires provider and resource")
	}
	cfg, err := parseConfigData(p.ConfigData)
	if err != nil {
		return "", nil, err
	}

	upstreamScopes := mapScopes(r, requestedScopes)

	verifier := crypto.GenerateVerifier()
	challenge := crypto.ComputeS256Challenge(verifier)

	// Per-call callbackURL takes precedence over the instance-level default
	// set via WithCallbackURL. The orchestration layer (ConnectService) now
	// owns callback derivation and passes a per-provider URL on every call.
	effectiveCallback := callbackURL
	if effectiveCallback == "" {
		effectiveCallback = a.callbackURL
	}

	pending := &resource.ConnectPendingState{
		ID:           crypto.GenerateRandomString(32),
		UserID:       userID,
		ProviderID:   p.ID,
		ResourceID:   r.ID,
		CodeVerifier: verifier,
		ReturnURL:    returnURL,
		Scopes:       requestedScopes,
		ExpiresAt:    time.Now().UTC().Add(connectStateTTL),
	}

	authURL, err := buildAuthorizeURL(cfg, upstreamScopes, challenge, pending.ID, effectiveCallback)
	if err != nil {
		return "", nil, err
	}
	return authURL, pending, nil
}

// HandleCallback exchanges the authorization code for tokens, returning the
// credential bytes to persist (the encryption layer owns at-rest encryption
// — ) and the upstream-format scopes the user actually granted.
func (a *Adapter) HandleCallback(
	ctx context.Context,
	p *resource.BrokerProvider,
	r *resource.Resource,
	code, callbackURL string,
	pending *resource.ConnectPendingState,
) ([]byte, []string, error) {
	if p == nil || pending == nil {
		return nil, nil, fmt.Errorf("oauth: HandleCallback requires provider and pending state")
	}
	cfg, err := parseConfigData(p.ConfigData)
	if err != nil {
		return nil, nil, err
	}
	secret, err := a.resolveSecret(cfg.ClientSecretEnv)
	if err != nil {
		return nil, nil, err
	}

	// RFC 6749 §4.1.3: redirect_uri at the token endpoint MUST equal the one
	// at the authorize endpoint. Per-call value takes precedence over the
	// instance default for the same reason as BuildConnectURL.
	effectiveCallback := callbackURL
	if effectiveCallback == "" {
		effectiveCallback = a.callbackURL
	}

	form := url.Values{
		"grant_type":    {"authorization_code"},
		"client_id":     {cfg.ClientID},
		"client_secret": {secret},
		"code":          {code},
		"code_verifier": {pending.CodeVerifier},
	}
	if effectiveCallback != "" {
		form.Set("redirect_uri", effectiveCallback)
	}

	resp, err := a.postToken(ctx, cfg, form)
	if err != nil {
		return nil, nil, err
	}
	if resp.AccessToken == "" {
		return nil, nil, errUpstreamMissingAccessToken
	}
	if resp.RefreshToken == "" {
		// Some upstreams omit refresh tokens unless extra_auth_params
		// requests them (Google: access_type=offline). Surface explicitly
		// rather than persisting a credential we can't refresh.
		return nil, nil, fmt.Errorf("oauth upstream did not return a refresh_token")
	}

	credBytes, err := marshalCredential(resp.RefreshToken)
	if err != nil {
		return nil, nil, fmt.Errorf("oauth: marshal credential: %w", err)
	}
	return credBytes, splitScopes(resp.Scope), nil
}

// Vend exchanges the persisted refresh token for a fresh access token,
// narrowing scopes per Resource. Returns updatedCredential = nil unless the
// upstream rotated the refresh token, in which case BrokerIssuer
// re-encrypts and persists with the optimistic-lock UPDATE.
func (a *Adapter) Vend(
	ctx context.Context,
	p *resource.BrokerProvider,
	r *resource.Resource,
	credential []byte,
	requestedScopes []string,
) (string, int, []byte, error) {
	if p == nil {
		return "", 0, nil, fmt.Errorf("oauth: Vend requires provider")
	}
	cfg, err := parseConfigData(p.ConfigData)
	if err != nil {
		return "", 0, nil, err
	}
	cred, err := parseCredential(credential)
	if err != nil {
		return "", 0, nil, err
	}
	secret, err := a.resolveSecret(cfg.ClientSecretEnv)
	if err != nil {
		return "", 0, nil, err
	}

	upstreamScopes := mapScopes(r, requestedScopes)

	form := url.Values{
		"grant_type":    {"refresh_token"},
		"client_id":     {cfg.ClientID},
		"client_secret": {secret},
		"refresh_token": {cred.RefreshToken},
	}
	if len(upstreamScopes) > 0 {
		form.Set("scope", strings.Join(upstreamScopes, " "))
	}

	resp, err := a.postToken(ctx, cfg, form)
	if err != nil {
		return "", 0, nil, err
	}
	if resp.AccessToken == "" {
		return "", 0, nil, errUpstreamMissingAccessToken
	}

	// detect upstream silently narrowing scope. If resp.Scope doesn't
	// cover the upstream-mapped scopes we requested, surface as a typed
	// sentinel so BrokerIssuer can re-emit consent_required.
	//
	// RFC 6749 §5.1: the scope field is OPTIONAL when identical to the
	// requested scope. An absent or empty scope means "unchanged", not
	// "narrowed" — skip the downgrade check in that case so IdPs that omit
	// scope on refresh (e.g. Google) are not mistakenly treated as downgraders.
	if len(upstreamScopes) > 0 && resp.Scope != "" {
		returnedScopes := strings.Fields(resp.Scope)
		if !scopesCover(returnedScopes, upstreamScopes) {
			return "", 0, nil, fmt.Errorf("%w: granted=%q requested=%q",
				output.ErrUpstreamScopeDowngrade, resp.Scope, strings.Join(upstreamScopes, " "))
		}
	}

	var updated []byte
	if resp.RefreshToken != "" && resp.RefreshToken != cred.RefreshToken {
		updated, err = marshalCredential(resp.RefreshToken)
		if err != nil {
			return "", 0, nil, fmt.Errorf("oauth: marshal rotated credential: %w", err)
		}
	}
	return resp.AccessToken, resp.ExpiresIn, updated, nil
}

// Revoke best-effort calls the upstream's RFC 7009 revocation endpoint when
// configured. A missing or non-2xx response never fails the local
// revocation — that's design doc §4.4.
func (a *Adapter) Revoke(ctx context.Context, p *resource.BrokerProvider, credential []byte) error {
	if p == nil {
		return fmt.Errorf("oauth: Revoke requires provider")
	}
	cfg, err := parseConfigData(p.ConfigData)
	if err != nil {
		return err
	}
	if cfg.RevokeURL == "" {
		return nil
	}
	cred, err := parseCredential(credential)
	if err != nil {
		return nil
	}
	secret, err := a.resolveSecret(cfg.ClientSecretEnv)
	if err != nil {
		return nil
	}
	if validateExternalURL(cfg.RevokeURL, a.allowLoopback) != nil {
		return nil
	}

	form := url.Values{
		"token":         {cred.RefreshToken},
		"client_id":     {cfg.ClientID},
		"client_secret": {secret},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, cfg.RevokeURL,
		strings.NewReader(form.Encode()))
	if err != nil {
		return nil
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := a.httpClient.Do(req)
	if err != nil {
		return nil
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxResponseBodySize))
	return nil
}

// resolveSecret runs the configured env-var lookup with the connector
// domain's existing pattern check. Uses the ValidEnvVarName allowlist as
// defense-in-depth even if the SecretResolver also checks.
func (a *Adapter) resolveSecret(envVarName string) (string, error) {
	if envVarName == "" {
		return "", fmt.Errorf("%w: client_secret_env is empty", errSecretLookup)
	}
	if !brokerproto.ValidEnvVarName(envVarName) {
		return "", fmt.Errorf("%w: invalid env var name %q", errSecretLookup, envVarName)
	}
	if a.secretResolver == nil {
		return "", fmt.Errorf("%w: no secret resolver configured", errSecretLookup)
	}
	secret, err := a.secretResolver.Resolve(envVarName)
	if err != nil {
		return "", fmt.Errorf("%w: %v", errSecretLookup, err)
	}
	if secret == "" {
		return "", fmt.Errorf("%w: env var %q not set", errSecretLookup, envVarName)
	}
	return secret, nil
}

// tokenResponse is the canonical post-parse shape — both the JSON
// "standard" parser and the "form" urlencoded parser produce one of these.
type tokenResponse struct {
	AccessToken  string
	RefreshToken string
	ExpiresIn    int
	Scope        string
}

func (a *Adapter) postToken(ctx context.Context, cfg configData, form url.Values) (tokenResponse, error) {
	if err := validateExternalURL(cfg.TokenURL, a.allowLoopback); err != nil {
		return tokenResponse{}, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, cfg.TokenURL,
		strings.NewReader(form.Encode()))
	if err != nil {
		return tokenResponse{}, fmt.Errorf("oauth: build token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := a.httpClient.Do(req)
	if err != nil {
		return tokenResponse{}, fmt.Errorf("oauth: token request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBodySize))
	if err != nil {
		return tokenResponse{}, fmt.Errorf("oauth: read token response: %w", err)
	}
	if resp.StatusCode >= 500 {
		return tokenResponse{}, fmt.Errorf("%w: status=%d", output.ErrUpstreamUnavailable, resp.StatusCode)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		// Try to classify as RFC 6749 §5.2 invalid_grant before falling back.
		var oauthErr struct {
			Error string `json:"error"`
		}
		if jsonErr := json.Unmarshal(body, &oauthErr); jsonErr == nil && oauthErr.Error == "invalid_grant" {
			return tokenResponse{}, fmt.Errorf("%w: %s", output.ErrUpstreamInvalidGrant, truncate(string(body), 200))
		}
		return tokenResponse{}, fmt.Errorf("%w: status=%d body=%s",
			errUpstreamHTTP, resp.StatusCode, truncate(string(body), 200))
	}

	switch cfg.ResponseFormat {
	case responseFormatForm:
		return parseFormResponse(body)
	default:
		return parseStandardResponse(body)
	}
}

// parseStandardResponse handles the OAuth 2.0 JSON token response shape
// per RFC 6749 §5.1. The same shape covers the refresh-token response.
func parseStandardResponse(body []byte) (tokenResponse, error) {
	var raw struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		ExpiresIn    int    `json:"expires_in"`
		Scope        string `json:"scope"`
	}
	if err := json.Unmarshal(body, &raw); err != nil {
		return tokenResponse{}, fmt.Errorf("oauth: parse JSON token response: %w", err)
	}
	return tokenResponse(raw), nil
}

// parseFormResponse handles application/x-www-form-urlencoded token
// responses (e.g. GitHub's /login/oauth/access_token without an
// Accept: application/json hint).
func parseFormResponse(body []byte) (tokenResponse, error) {
	values, err := url.ParseQuery(string(body))
	if err != nil {
		return tokenResponse{}, fmt.Errorf("oauth: parse form token response: %w", err)
	}
	resp := tokenResponse{
		AccessToken:  values.Get("access_token"),
		RefreshToken: values.Get("refresh_token"),
		Scope:        values.Get("scope"),
	}
	if v := values.Get("expires_in"); v != "" {
		// Best-effort parse; some upstreams omit it. A failed parse leaves
		// ExpiresIn at zero, which BrokerIssuer treats as "no AS-known
		// lifetime" — caller reads upstream's Authorization header next time.
		var n int
		if _, err := fmt.Sscanf(v, "%d", &n); err == nil {
			resp.ExpiresIn = n
		}
	}
	return resp, nil
}

// splitScopes takes the upstream's space-separated scope string from a
// token response and returns it as a slice. Empty input returns nil so
// callers can skip persisting an empty []string{}.
func splitScopes(scope string) []string {
	if scope == "" {
		return nil
	}
	return strings.Fields(scope)
}

// buildAuthorizeURL composes the upstream authorize URL with PKCE,
// reserved-key filtering on extra_auth_params, and an optional redirect_uri.
func buildAuthorizeURL(cfg configData, upstreamScopes []string, challenge, state, callbackURL string) (string, error) {
	if _, err := url.Parse(cfg.AuthorizeURL); err != nil {
		return "", fmt.Errorf("oauth: invalid authorize_url: %w", err)
	}
	q := url.Values{
		"client_id":             {cfg.ClientID},
		"response_type":         {"code"},
		"state":                 {state},
		"code_challenge":        {challenge},
		"code_challenge_method": {"S256"},
	}
	if callbackURL != "" {
		q.Set("redirect_uri", callbackURL)
	}
	if len(upstreamScopes) > 0 {
		q.Set("scope", strings.Join(upstreamScopes, " "))
	}
	for k, v := range cfg.ExtraAuthParams {
		if _, reserved := brokerproto.ReservedAuthParams[k]; reserved {
			continue
		}
		q.Set(k, v)
	}
	sep := "?"
	if strings.Contains(cfg.AuthorizeURL, "?") {
		sep = "&"
	}
	return cfg.AuthorizeURL + sep + q.Encode(), nil
}

// validateExternalURL rejects token/revoke endpoints whose hostname is an IP
// literal in a private, loopback, link-local, or unspecified range. This is
// the cheap pre-flight guard against admin-configured upstreams that name
// internal addresses directly; the hostname-to-private-IP / DNS-rebinding
// case is covered by the SSRF-safe http.Transport wired in
// cmd/authserver/serve.go, which resolves at dial time and refuses the
// connection. allowLoopback is set only by tests pointing at httptest.
func validateExternalURL(rawURL string, allowLoopback bool) error {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("oauth: invalid URL: %w", err)
	}
	host := parsed.Hostname()
	ip := net.ParseIP(host)
	if ip == nil {
		return nil
	}
	if ip.IsLoopback() && allowLoopback {
		return nil
	}
	// Delegate to ssrf.IsPrivateIP so the adapter pre-flight stays in sync
	// with the dial-time check in NewSafeTransport. stdlib's IsPrivate /
	// IsLinkLocal* predicates miss CGNAT, TEST-NETs, RFC 2544 benchmark,
	// IPv6 documentation, and multicast — see ssrf.privateNetworks.
	if ssrf.IsPrivateIP(ip) {
		return fmt.Errorf("oauth: URL points to a non-routable address: %s", host)
	}
	return nil
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

// scopesCover reports whether have covers every element in want,
// using set semantics on a list of scopes.
func scopesCover(have, want []string) bool {
	set := make(map[string]struct{}, len(have))
	for _, s := range have {
		set[s] = struct{}{}
	}
	for _, s := range want {
		if _, ok := set[s]; !ok {
			return false
		}
	}
	return true
}
