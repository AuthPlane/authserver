// Package serviceaccount implements the BrokerProtocol port for upstream
// providers where the AS holds a service-account private key and
// impersonates a specific user via an outbound RFC 7521 §4.2 / RFC 7523
// §2.1 JWT bearer assertion (e.g. Google Workspace domain-wide delegation,
// Atlassian Forge service accounts). Per the resource-unification design
// §4.4 / §5.3 and the architecture doc, there is no per-user upstream
// consent: the operator configures the SA at the broker provider level
// and per-user authorization is operator policy, not user-driven.
//
// BuildConnectURL and HandleCallback return output.ErrNoConnectStep so the
// orchestration layer skips the OAuth redirect dance. Vend signs
// a fresh assertion every call and POSTs it to the upstream's token
// endpoint. Revoke is a no-op — server-issued upstream tokens expire
// naturally; the AS does not rotate the SA private key.
//
// This adapter is *outbound*: the AS produces the assertion. It is
// functionally distinct from internal/services/jwt_bearer.go which is
// *inbound*: the AS consumes assertions presented at /oauth/token via
// RFC 7523 grant_type. The two paths never meet — see design doc §1.
package serviceaccount

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

	"github.com/authplane/authserver/internal/crypto"
	"github.com/authplane/authserver/internal/domain/resource"
	"github.com/authplane/authserver/internal/ports/output"
	"github.com/authplane/authserver/internal/ssrf"
)

// jwtBearerGrantType is the RFC 7523 §2.1 grant_type value the AS sends to
// the upstream token endpoint to redeem a signed JWT assertion.
//
//nolint:gosec // G101: this is a public OAuth grant_type identifier, not a credential.
const jwtBearerGrantType = "urn:ietf:params:oauth:grant-type:jwt-bearer"

// maxResponseBodySize bounds upstream response reads to avoid memory
// exhaustion from a hostile or buggy provider. Mirrors the cap in the
// sibling oauth adapter.
const maxResponseBodySize = 1 << 20

// Adapter implements output.BrokerProtocol for the service_account
// protocol. One adapter instance handles every BrokerProvider whose
// Protocol is "service_account"; per-provider state lives in
// BrokerProvider.ConfigData and per-user impersonation state lives in
// broker_grants.credential_data.
type Adapter struct {
	httpClient     *http.Client
	secretResolver output.SecretResolver
	allowLoopback  bool
}

// Option configures an Adapter at construction. The functional-options
// form keeps the BrokerProtocol port's required New(httpClient, sr)
// shape while letting tests supply additional knobs without breaking
// callers.
type Option func(*Adapter)

// WithAllowLoopback enables 127.0.0.1 / ::1 token URLs for tests that
// point the adapter at httptest.NewServer. MUST NOT be used in
// production — production binaries leave it false so SSRF protection
// rejects loopback. Mirrors the oauth adapter's option.
func WithAllowLoopback(allow bool) Option {
	return func(a *Adapter) { a.allowLoopback = allow }
}

// New builds an Adapter with the given HTTP client and secret resolver.
// The HTTP client should set conservative timeouts and disable redirect
// following on POST flows; the wiring layer is responsible for that.
func New(httpClient *http.Client, sr output.SecretResolver, opts ...Option) *Adapter {
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
func (a *Adapter) Name() string { return "service_account" }

// BuildConnectURL returns ErrNoConnectStep — the service_account protocol
// has no per-user upstream consent flow. The orchestration layer treats
// this as a signal to skip the OAuth redirect.
func (a *Adapter) BuildConnectURL(
	_ context.Context,
	_ *resource.BrokerProvider,
	_ *resource.Resource,
	_, _, _ string,
	_ []string,
) (string, *resource.ConnectPendingState, error) {
	return "", nil, output.ErrNoConnectStep
}

// HandleCallback returns ErrNoConnectStep — see BuildConnectURL.
func (a *Adapter) HandleCallback(
	_ context.Context,
	_ *resource.BrokerProvider,
	_ *resource.Resource,
	_, _ string,
	_ *resource.ConnectPendingState,
) ([]byte, []string, error) {
	return nil, nil, output.ErrNoConnectStep
}

// Vend signs an outbound JWT bearer assertion impersonating cred.ImpersonateSub
// and exchanges it at cfg.TokenURL for a fresh upstream access token. The
// assertion's `scope` claim carries the upstream-format narrowing for this
// Resource — a Resource scoped to calendar.readonly never produces
// an assertion with calendar.events.
//
// updatedCredential is always nil — service accounts do not rotate the SA
// key from upstream; the AS rotates by replacing the env var.
func (a *Adapter) Vend(
	ctx context.Context,
	p *resource.BrokerProvider,
	r *resource.Resource,
	credential []byte,
	requestedScopes []string,
) (string, int, []byte, error) {
	if p == nil {
		return "", 0, nil, fmt.Errorf("service_account: Vend requires provider")
	}
	cfg, err := parseConfigData(p.ConfigData)
	if err != nil {
		return "", 0, nil, err
	}
	cred, err := parseCredential(credential)
	if err != nil {
		return "", 0, nil, err
	}
	keyPEM, err := a.resolveSAKey(ctx, p, cfg.SAKeyRef)
	if err != nil {
		return "", 0, nil, err
	}
	priv, err := parsePrivateKey([]byte(keyPEM))
	if err != nil {
		return "", 0, nil, err
	}

	upstreamScopes := mapScopes(r, requestedScopes)
	now := time.Now().UTC()
	claims := assertionClaims{
		Issuer:   cfg.SAEmail,
		Subject:  cred.ImpersonateSub,
		Audience: cfg.TokenURL,
		IssuedAt: now.Unix(),
		Expiry:   now.Add(time.Duration(cfg.TokenTTLSeconds) * time.Second).Unix(),
		JTI:      crypto.GenerateRandomString(32),
		Scope:    strings.Join(upstreamScopes, " "),
	}

	assertion, err := signAssertion(cfg.Algorithm, priv, claims)
	if err != nil {
		return "", 0, nil, err
	}

	form := url.Values{
		"grant_type": {jwtBearerGrantType},
		"assertion":  {assertion},
	}
	resp, err := a.postToken(ctx, cfg, form)
	if err != nil {
		return "", 0, nil, err
	}
	if resp.AccessToken == "" {
		return "", 0, nil, errUpstreamMissingAccessToken
	}
	return resp.AccessToken, resp.ExpiresIn, nil, nil
}

// Revoke returns nil — the AS holds no per-user upstream credential to
// invalidate. Server-issued access tokens expire on their natural
// upstream-defined lifetime; rotating the SA key is an operator action
// outside the AS surface. Mirrors design doc §4.4 "Best-effort; failure
// does not block the local revocation."
func (a *Adapter) Revoke(_ context.Context, _ *resource.BrokerProvider, _ []byte) error {
	return nil
}

// resolveSAKey runs the configured secret lookup through the wired
// SecretResolver, building a SecretSource from the provider's encrypted-column
// value (if any) and the config_data env reference. Resolution order is owned
// by the resolver: Data (decrypted under the provider's ownerContext) →
// Ref (env var). The empty-result guard stays as defense-in-depth; the
// empty-reference guard only fires when there is also no ciphertext to fall
// back on (env-only path). Mirrors the oauth adapter.
func (a *Adapter) resolveSAKey(ctx context.Context, p *resource.BrokerProvider, ref string) (string, error) {
	if ref == "" && len(p.EncSecretData) == 0 {
		return "", fmt.Errorf("%w: sa_key_ref is empty", errSAKeyLookup)
	}
	pemBytes, err := a.secretResolver.Resolve(ctx, output.GetSecretSourceForBrokerProvider(p, ref))
	if err != nil {
		return "", fmt.Errorf("%w: %v", errSAKeyLookup, err)
	}
	if pemBytes == "" {
		return "", fmt.Errorf("%w: reference %q resolved to empty", errSAKeyLookup, ref)
	}
	return pemBytes, nil
}

// tokenResponse is the canonical post-parse shape of the upstream
// token-endpoint response per RFC 6749 §5.1.
type tokenResponse struct {
	AccessToken string
	ExpiresIn   int
	Scope       string
}

func (a *Adapter) postToken(ctx context.Context, cfg configData, form url.Values) (tokenResponse, error) {
	if err := validateExternalURL(cfg.TokenURL, a.allowLoopback); err != nil {
		return tokenResponse{}, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, cfg.TokenURL,
		strings.NewReader(form.Encode()))
	if err != nil {
		return tokenResponse{}, fmt.Errorf("service_account: build token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := a.httpClient.Do(req)
	if err != nil {
		return tokenResponse{}, fmt.Errorf("service_account: token request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBodySize))
	if err != nil {
		return tokenResponse{}, fmt.Errorf("service_account: read token response: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return tokenResponse{}, fmt.Errorf("%w: status=%d body=%s",
			errUpstreamHTTP, resp.StatusCode, truncate(string(body), 200))
	}
	return parseTokenResponse(body)
}

// parseTokenResponse handles the OAuth 2.0 JSON token response shape per
// RFC 6749 §5.1. Service-account upstreams (Google, Atlassian) speak this
// shape; the form-encoded variant the oauth adapter handles is not seen
// in the SA path.
func parseTokenResponse(body []byte) (tokenResponse, error) {
	var raw struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
		Scope       string `json:"scope"`
	}
	if err := json.Unmarshal(body, &raw); err != nil {
		return tokenResponse{}, fmt.Errorf("service_account: parse token response: %w", err)
	}
	return tokenResponse(raw), nil
}

// validateExternalURL rejects token endpoints whose hostname is an IP
// literal in a private, loopback, link-local, or unspecified range. This is
// the cheap pre-flight guard against admin-configured upstreams that name
// internal addresses directly; the hostname-to-private-IP / DNS-rebinding
// case is covered by the SSRF-safe http.Transport wired in
// cmd/authserver/serve.go, which resolves at dial time and refuses the
// connection. allowLoopback is set only by tests pointing at httptest.
func validateExternalURL(rawURL string, allowLoopback bool) error {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("service_account: invalid URL: %w", err)
	}
	host := parsed.Hostname()
	ip := net.ParseIP(host)
	if ip == nil {
		return nil
	}
	if ip.IsLoopback() && allowLoopback {
		return nil
	}
	// See sibling oauth adapter — delegating to ssrf.IsPrivateIP keeps the
	// pre-flight and the dial-time block in lockstep on the IANA special-use
	// registries (RFC 6598, 5737, 2544, 3849, 4291, etc.).
	if ssrf.IsPrivateIP(ip) {
		return fmt.Errorf("service_account: URL points to a non-routable address: %s", host)
	}
	return nil
}

// mapScopes translates fine scope names (as advertised in
// resource.Scopes[].Name) into the upstream wire-format scope strings the
// upstream provider expects. Mirrors the oauth adapter's mapScopes:
//
//   - if r.Scopes[i].Name == fine and r.Scopes[i].Upstream != "", emit Upstream
//   - if r.Scopes[i].Name == fine and r.Scopes[i].Upstream == "", emit fine
//   - if fine is not registered on r at all, drop it silently
//
// Order is preserved; duplicates are preserved. the assertion's
// `scope` claim is the upstream-format narrowed list — a Resource scoped
// to calendar.readonly never produces an assertion with calendar.events
// even if the SA itself is authorized at the workspace for both.
func mapScopes(r *resource.Resource, requested []string) []string {
	if r == nil || len(requested) == 0 {
		return nil
	}
	index := make(map[string]string, len(r.Scopes))
	for _, s := range r.Scopes {
		index[s.Name] = s.Upstream
	}
	out := make([]string, 0, len(requested))
	for _, fine := range requested {
		upstream, ok := index[fine]
		if !ok {
			continue
		}
		if upstream == "" {
			out = append(out, fine)
			continue
		}
		out = append(out, upstream)
	}
	return out
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
