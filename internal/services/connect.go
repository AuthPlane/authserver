package services

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"strings"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	otelmetric "go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/trace"

	"github.com/authplane/authserver/internal/brokerproto"
	"github.com/authplane/authserver/internal/crypto"
	"github.com/authplane/authserver/internal/domain"
	"github.com/authplane/authserver/internal/domain/audit"
	"github.com/authplane/authserver/internal/domain/resource"
	"github.com/authplane/authserver/internal/observability"
	"github.com/authplane/authserver/internal/ports/input"
	"github.com/authplane/authserver/internal/ports/output"
)

// stateExpiry is how long a pending Broker connect state token is valid.
const stateExpiry = 10 * time.Minute

// ConnectionMeta is re-exported from internal/ports/input for caller
// convenience; the canonical declaration lives there so api/public/connection
// can consume the same type without crossing the hexagonal boundary.
type ConnectionMeta = input.ConnectionMeta

// CompleteConnectResult is re-exported from internal/ports/input for caller
// convenience.
type CompleteConnectResult = input.CompleteConnectResult

// ConnectService orchestrates the upstream-Broker connect/disconnect lifecycle
// over the unified BrokerProvider + BrokerGrant + ConnectPendingState trio.
// It dispatches per-protocol via brokerproto.Registry; any provider whose
// matching adapter returns output.ErrNoConnectStep (api_key, service_account)
// is rejected at StartConnect with a typed error — those protocols have no
// per-user connect dance.
type ConnectService struct {
	registry       *ResourceRegistry
	resources      output.ResourceStore
	providers      output.BrokerProviderStore
	grants         output.BrokerGrantStore
	pending        output.ConnectPendingStateStore
	adapters       *brokerproto.Registry
	encryptor      output.DataEncryptor
	stateConfig    output.ConnectStateConfigProvider
	issuerProvider output.IssuerProvider
	connectConfig  output.ConnectConfigProvider
	audit          AuditRecorder
	logger         *slog.Logger
	tracer         trace.Tracer
	metrics        *observability.Metrics
}

// NewConnectService constructs the unified ConnectService.
func NewConnectService(
	registry *ResourceRegistry,
	resources output.ResourceStore,
	providers output.BrokerProviderStore,
	grants output.BrokerGrantStore,
	pending output.ConnectPendingStateStore,
	adapters *brokerproto.Registry,
	encryptor output.DataEncryptor,
	stateConfig output.ConnectStateConfigProvider,
	issuerProvider output.IssuerProvider,
	connectConfig output.ConnectConfigProvider,
	obs *observability.Provider,
	auditor AuditRecorder,
) *ConnectService {
	if issuerProvider == nil {
		panic("services.NewConnectService: issuerProvider is required")
	}
	if connectConfig == nil {
		panic("NewConnectService: connectConfig must not be nil")
	}
	if stateConfig == nil {
		panic("NewConnectService: stateConfig must not be nil")
	}
	s := &ConnectService{
		registry:       registry,
		resources:      resources,
		providers:      providers,
		grants:         grants,
		pending:        pending,
		adapters:       adapters,
		encryptor:      encryptor,
		stateConfig:    stateConfig,
		issuerProvider: issuerProvider,
		connectConfig:  connectConfig,
		audit:          auditor,
		logger:         obs.Logger.With("component", "connect"),
		tracer:         obs.Tracer,
		metrics:        obs.Metrics,
	}

	return s
}

// StartConnect resolves the BrokerProvider by slug, validates return_url
// against the union of the per-resource AllowedReturnURLs and the global
// allowlist, and dispatches to the matching brokerproto adapter to
// build the upstream authorize URL. The pending state is persisted with the
// upstream's PKCE verifier; the caller (handler) redirects the user to the
// returned URL.
//
// resourceSlug may be empty: operator-app-driven flows that don't carry an
// originating resource hint anchor on any Broker resource bound to the
// provider (FK requirement). Either way the global allowedReturnURLs list is
// always consulted as a fallback.
func (s *ConnectService) StartConnect(
	ctx context.Context,
	userID, providerSlug, resourceSlug, returnURL string,
) (string, error) {
	ctx, span := s.tracer.Start(ctx, "ConnectService.StartConnect")
	defer span.End()
	span.SetAttributes(
		attribute.String("user_id", userID),
		attribute.String("provider_slug", providerSlug),
		attribute.String("resource_slug", resourceSlug),
	)

	provider, err := s.providers.GetBySlug(ctx, providerSlug)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		if errors.Is(err, domain.ErrResourceNotFound) {
			return "", domain.ErrServiceNotFound
		}
		return "", err
	}

	var target *resource.Resource
	if resourceSlug != "" {
		target, err = s.registry.Resolve(ctx, resourceSlug)
		if err != nil {
			span.RecordError(err)
			span.SetStatus(codes.Error, err.Error())
			return "", err
		}
		if !target.IsBroker() {
			span.SetStatus(codes.Error, "originating resource is not broker-backed")
			return "", fmt.Errorf("%w: resource %q is not broker-backed", domain.ErrInvalidTarget, resourceSlug)
		}
	} else {
		// connect_pending_states.resource_id is a NOT NULL FK to resources(id).
		// When the caller didn't supply ?resource=, fall through to the
		// single Broker resource that references this provider — but only
		// if the choice is unambiguous. with ≥2 Broker resources
		// the picked target governs the return-URL allowlist AND the
		// upstream scope catalog, so guessing silently issues the wrong
		// scopes or allows the wrong return URL. Reject ambiguity here so
		// callers either fix their /connect URL or land in the explicit-
		// resource branch above.
		anchor, lookupErr := s.singleBrokerResourceForProvider(ctx, provider.ID)
		if lookupErr != nil {
			span.RecordError(lookupErr)
			span.SetStatus(codes.Error, lookupErr.Error())
			return "", lookupErr
		}
		target = anchor
	}

	connectCfg, err := s.connectConfig.Config(ctx)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return "", fmt.Errorf("resolve connect config: %w", err)
	}
	redirectBase := strings.TrimRight(connectCfg.RedirectBaseURL, "/")

	returnURLAllowed := s.isReturnURLAllowed(ctx, redirectBase, returnURL, connectCfg.AllowedReturnURLs, target)
	if !returnURLAllowed {
		span.RecordError(domain.ErrInvalidReturnURL)
		span.SetStatus(codes.Error, "return URL not allowed")
		return "", domain.ErrInvalidReturnURL
	}

	adapter, err := s.adapters.Lookup(string(provider.Protocol))
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return "", fmt.Errorf("lookup brokerproto adapter %q: %w", provider.Protocol, err)
	}

	stateToken, err := s.generateStateToken(ctx, userID, providerSlug, returnURL)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return "", fmt.Errorf("generate state token: %w", err)
	}

	res := target
	if res == nil {
		res = &resource.Resource{}
	}

	// Default to requesting the resource's full scope catalog upstream when
	// the caller did not narrow it. Without this the authorize URL is built
	// with scope="" and providers that require a scope (Google, GitHub,
	// Microsoft) reject the request before the user reaches the consent
	// screen. Operators who want to narrow can override later via a
	// ?scope=<space-separated> query param (TODO: wire from handler).
	requestedScopes := make([]string, 0, len(res.Scopes))
	for _, sc := range res.Scopes {
		requestedScopes = append(requestedScopes, sc.Name)
	}

	callbackURL := s.callbackURL(ctx, redirectBase, providerSlug)
	upstreamURL, pendingState, err := adapter.BuildConnectURL(ctx, provider, res, userID, returnURL, callbackURL, requestedScopes)
	if err != nil {
		if errors.Is(err, output.ErrNoConnectStep) {
			span.SetStatus(codes.Error, "protocol has no connect step")
			return "", fmt.Errorf("%w: provider %q (protocol %s) has no per-user connect step", domain.ErrInvalidTarget, providerSlug, provider.Protocol)
		}
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return "", fmt.Errorf("build connect url: %w", err)
	}
	if pendingState == nil {
		span.SetStatus(codes.Error, "adapter returned nil pending state")
		return "", fmt.Errorf("brokerproto adapter %q returned nil pending state", provider.Protocol)
	}

	pendingState.ID = stateToken
	pendingState.UserID = userID
	pendingState.ProviderID = provider.ID
	if target != nil {
		pendingState.ResourceID = target.ID
	}
	pendingState.ReturnURL = returnURL
	if pendingState.ExpiresAt.IsZero() {
		pendingState.ExpiresAt = time.Now().UTC().Add(stateExpiry)
	}

	if insertErr := s.pending.Insert(ctx, pendingState); insertErr != nil {
		span.RecordError(insertErr)
		span.SetStatus(codes.Error, insertErr.Error())
		return "", fmt.Errorf("insert pending state: %w", insertErr)
	}

	upstreamURL = rebindStateInURL(upstreamURL, stateToken)

	s.logger.InfoContext(ctx, "broker connect started",
		"user_id", userID,
		"provider_slug", providerSlug,
		"resource_slug", resourceSlug,
	)

	return upstreamURL, nil
}

// CompleteConnect consumes the pending state, dispatches HandleCallback on the
// matching adapter, encrypts the returned credential, and upserts the
// BrokerGrant keyed on (user_id, broker_provider_id). The single Upsert call
// covers all three re-connect scenarios — first connect, re-connect over an
// active grant, and re-connect after a soft-delete revoke — without ever
// hitting the UNIQUE constraint. The previous lookup-then-revoke-
// then-create pattern 500'd on the second connect because Revoke is a soft-
// delete that does NOT free the unique slot.
func (s *ConnectService) CompleteConnect(
	ctx context.Context,
	userID, stateToken, code string,
) (CompleteConnectResult, error) {
	ctx, span := s.tracer.Start(ctx, "ConnectService.CompleteConnect")
	defer span.End()
	span.SetAttributes(attribute.String("user_id", userID))

	pendingState, err := s.pending.Consume(ctx, stateToken)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		if errors.Is(err, domain.ErrPendingStateNotFound) {
			return CompleteConnectResult{}, domain.ErrStateNotFound
		}
		return CompleteConnectResult{}, err
	}

	if pendingState.UserID != userID {
		span.RecordError(domain.ErrStateForeignUser)
		span.SetStatus(codes.Error, "pending state belongs to different user")
		return CompleteConnectResult{}, domain.ErrStateForeignUser
	}

	provider, err := s.providers.GetByID(ctx, pendingState.ProviderID)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return CompleteConnectResult{}, fmt.Errorf("lookup broker provider: %w", err)
	}

	stateOK, err := s.verifyStateToken(ctx, stateToken, userID, provider.Slug, pendingState.ReturnURL)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return CompleteConnectResult{}, err
	}
	if !stateOK {
		span.RecordError(domain.ErrInvalidState)
		span.SetStatus(codes.Error, "tampered state token")
		return CompleteConnectResult{}, domain.ErrInvalidState
	}

	adapter, err := s.adapters.Lookup(string(provider.Protocol))
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return CompleteConnectResult{}, fmt.Errorf("lookup brokerproto adapter %q: %w", provider.Protocol, err)
	}

	var res *resource.Resource
	if pendingState.ResourceID != "" {
		res, _, err = s.registry.GetWithProvider(ctx, pendingState.ResourceID)
		if err != nil {
			span.RecordError(err)
			span.SetStatus(codes.Error, err.Error())
			return CompleteConnectResult{}, fmt.Errorf("resolve originating resource: %w", err)
		}
	}
	if res == nil {
		res = &resource.Resource{}
	}

	connectCfg, err := s.connectConfig.Config(ctx)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return CompleteConnectResult{}, fmt.Errorf("resolve connect config: %w", err)
	}
	redirectBase := strings.TrimRight(connectCfg.RedirectBaseURL, "/")

	callbackURL := s.callbackURL(ctx, redirectBase, provider.Slug)
	credPlain, scopesGranted, err := adapter.HandleCallback(ctx, provider, res, code, callbackURL, pendingState)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return CompleteConnectResult{}, fmt.Errorf("handle callback: %w", err)
	}

	ownerCtx := fmt.Sprintf("broker:%s:%s", userID, provider.ID)
	credEnc, err := s.encryptor.Encrypt(ctx, credPlain, ownerCtx)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return CompleteConnectResult{}, fmt.Errorf("encrypt broker credential: %w", err)
	}

	now := time.Now().UTC()
	// Upsert ignores g.ID on the update path (the existing row's id is
	// preserved); we still supply a fresh id for the insert path so the
	// row gets a stable identifier the audit log can reference. The
	// returned grant carries the canonical post-mutation state — use
	// THAT for the audit row + log line, not the value we passed in.
	desired := &resource.BrokerGrant{
		ID:               crypto.GenerateRandomString(16),
		UserID:           userID,
		BrokerProviderID: provider.ID,
		CredentialData:   credEnc,
		ScopesGranted:    scopesGranted,
		EncBackend:       s.encryptor.DriverName(),
		CreatedAt:        now,
		UpdatedAt:        now,
	}
	grant, err := s.grants.Upsert(ctx, desired)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return CompleteConnectResult{}, fmt.Errorf("upsert broker grant: %w", err)
	}

	s.metrics.ConnectionConnectTotal.Add(ctx, 1, otelmetric.WithAttributes(
		attribute.String("provider", provider.Slug),
	))

	s.logger.InfoContext(ctx, "broker grant upserted",
		"user_id", userID,
		"provider_slug", provider.Slug,
		"grant_id", grant.ID,
		"version", grant.Version,
	)

	if s.audit != nil {
		s.audit.Record(ctx, audit.NewEvent(
			audit.ActionBrokerGrantCreated,
			userID, "", "",
			fmt.Sprintf("provider=%s grant_id=%s version=%d", provider.Slug, grant.ID, grant.Version),
		))
	}

	return CompleteConnectResult{
		Meta: ConnectionMeta{
			Provider:      provider.Slug,
			ScopesGranted: grant.ScopesGranted,
			CreatedAt:     grant.CreatedAt,
			UpdatedAt:     grant.UpdatedAt,
		},
		ReturnURL: pendingState.ReturnURL,
	}, nil
}

// Disconnect revokes the active BrokerGrant for (user, providerSlug). The
// adapter's Revoke is best-effort; failures are logged but do not block.
func (s *ConnectService) Disconnect(ctx context.Context, userID, providerSlug string) error {
	ctx, span := s.tracer.Start(ctx, "ConnectService.Disconnect")
	defer span.End()
	span.SetAttributes(
		attribute.String("user_id", userID),
		attribute.String("provider_slug", providerSlug),
	)

	provider, err := s.providers.GetBySlug(ctx, providerSlug)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		if errors.Is(err, domain.ErrResourceNotFound) {
			return domain.ErrConnectionNotFound
		}
		return err
	}

	grant, err := s.grants.Get(ctx, userID, provider.ID)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return err
	}
	if grant == nil {
		return domain.ErrConnectionNotFound
	}

	if revokeErr := s.grants.Revoke(ctx, grant.ID); revokeErr != nil {
		span.RecordError(revokeErr)
		span.SetStatus(codes.Error, revokeErr.Error())
		return fmt.Errorf("revoke broker grant: %w", revokeErr)
	}

	if adapter, lookupErr := s.adapters.Lookup(string(provider.Protocol)); lookupErr == nil {
		ownerCtx := fmt.Sprintf("broker:%s:%s", userID, provider.ID)
		if credPlain, decErr := s.encryptor.Decrypt(ctx, grant.CredentialData, ownerCtx); decErr == nil {
			if revErr := adapter.Revoke(ctx, provider, credPlain); revErr != nil {
				s.logger.WarnContext(ctx, "upstream revoke failed (best-effort)",
					"provider_slug", provider.Slug,
					"error", revErr,
				)
			}
		} else {
			s.logger.WarnContext(ctx, "decrypt for upstream revoke failed (best-effort)",
				"provider_slug", provider.Slug,
				"error", decErr,
			)
		}
	}

	s.metrics.ConnectionDisconnectTotal.Add(ctx, 1, otelmetric.WithAttributes(
		attribute.String("provider", provider.Slug),
	))

	s.logger.InfoContext(ctx, "broker grant revoked",
		"user_id", userID,
		"provider_slug", provider.Slug,
		"grant_id", grant.ID,
	)

	if s.audit != nil {
		s.audit.Record(ctx, audit.NewEvent(
			audit.ActionBrokerGrantRevoked,
			userID, "", "",
			fmt.Sprintf("provider=%s grant_id=%s", provider.Slug, grant.ID),
		))
	}

	return nil
}

// ListConnections returns the user's active BrokerGrants as ConnectionMeta
// projections, never including the encrypted credential.
func (s *ConnectService) ListConnections(ctx context.Context, userID string) ([]ConnectionMeta, error) {
	ctx, span := s.tracer.Start(ctx, "ConnectService.ListConnections")
	defer span.End()
	span.SetAttributes(attribute.String("user_id", userID))

	grants, err := s.grants.ListForUser(ctx, userID)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return nil, fmt.Errorf("list broker grants: %w", err)
	}

	metas := make([]ConnectionMeta, 0, len(grants))
	for _, g := range grants {
		if g.IsRevoked() {
			continue
		}
		provider, lookupErr := s.providers.GetByID(ctx, g.BrokerProviderID)
		if lookupErr != nil {
			s.logger.WarnContext(ctx, "list connections: provider lookup failed; skipping row",
				"grant_id", g.ID,
				"broker_provider_id", g.BrokerProviderID,
				"error", lookupErr,
			)
			continue
		}
		metas = append(metas, ConnectionMeta{
			Provider:      provider.Slug,
			ScopesGranted: g.ScopesGranted,
			CreatedAt:     g.CreatedAt,
			UpdatedAt:     g.UpdatedAt,
		})
	}
	return metas, nil
}

// --- helpers ---

// isReturnURLAllowed implements the always-consult-fallback policy.
// The effective allowlist is the UNION of the per-resource list and the global
// list, so the global env-var allowlist is honored regardless of whether a
// per-resource policy is in play. The AS-self /connections page is always
// permitted because the consent_url synthesizer redirects users back to the
// AS itself, not to a third-party app.
//
// Pre- behavior: when target was non-nil the global list was silently
// ignored, which made AUTHPLANE_CONNECT_ALLOWED_RETURN_URLS dead config in any
// deployment with a Broker resource — the FK-anchor lookup in StartConnect
// always populates target before this check runs. See ticket.
func (s *ConnectService) isReturnURLAllowed(ctx context.Context, redirectBaseURL, returnURL string, allowedReturnURLs []string, target *resource.Resource) bool {
	if returnURL == "" {
		return false
	}
	if s.matchesASelf(ctx, redirectBaseURL, returnURL) {
		return true
	}
	if target != nil {
		for _, allowed := range target.Policy.Connect.AllowedReturnURLs {
			if matchReturnURL(allowed, returnURL) {
				return true
			}
		}
	}
	for _, allowed := range allowedReturnURLs {
		if matchReturnURL(allowed, returnURL) {
			return true
		}
	}
	return false
}

// matchReturnURL returns true when returnURL satisfies an allowlist entry.
// It supports two forms:
//
// 1. Exact string equality (back-compat with pre- behavior).
//  2. Loopback-port wildcards: `http://localhost:*`, `http://127.0.0.1:*`,
//     and the `https://` variants. The `*` stands in for any non-empty
//     numeric port and is followed by an optional `/...` path. Anything
//     else after the host:port (credentials, missing port, non-digit port)
//     is rejected.
//
// Glob support is intentionally limited to loopback-with-port. Broader globs
// in a return-URL allowlist are a footgun, and this scope matches both the
// shipped compose default (AUTHPLANE_CONNECT_ALLOWED_RETURN_URLS=
// http://localhost:*,http://127.0.0.1:*) and the operator-facing
// validateReturnURL gate in resource_admin.go.
func matchReturnURL(pattern, returnURL string) bool {
	if pattern == returnURL {
		return true
	}
	prefix, ok := loopbackWildcardPrefix(pattern)
	if !ok {
		return false
	}
	if !strings.HasPrefix(returnURL, prefix) {
		return false
	}
	rest := returnURL[len(prefix):]
	// Must start with at least one digit (the port); then either end of
	// string or transition into a `/...` path. Empty port, non-digit, or
	// extra junk between host and path is rejected.
	if rest == "" {
		return false
	}
	i := 0
	for i < len(rest) && rest[i] >= '0' && rest[i] <= '9' {
		i++
	}
	if i == 0 {
		return false
	}
	if i == len(rest) {
		return true
	}
	return rest[i] == '/'
}

// loopbackWildcardPrefix maps a supported loopback-wildcard allowlist entry
// to the literal scheme+host+":" prefix that matchReturnURL should expect at
// the start of a candidate URL. Returns ok=false for non-wildcard entries.
func loopbackWildcardPrefix(pattern string) (string, bool) {
	switch pattern {
	case "http://localhost:*":
		return "http://localhost:", true
	case "https://localhost:*":
		return "https://localhost:", true
	case "http://127.0.0.1:*":
		return "http://127.0.0.1:", true
	case "https://127.0.0.1:*":
		return "https://127.0.0.1:", true
	}
	return "", false
}

// singleBrokerResourceForProvider returns the unique Broker-backed Resource
// that references the given BrokerProvider. Used as a FK anchor for
// connect_pending_states when /connect/{provider} omits ?resource=.
//
// pre- this function returned rows[0] silently when the
// provider had several Broker resources — but the picked resource sets
// both the return-URL allowlist and the upstream scope catalog, so a
// silent pick can issue the wrong scopes or allow the wrong return URL.
// The contract is now strict:
//
//   - 0 broker resources →  ErrInvalidTarget (nothing to anchor on)
//   - 1 broker resource  →  return it (unambiguous)
//   - ≥2 broker resources → ErrAmbiguousBrokerResource (caller must
//     supply ?resource= so the policy choice is explicit)
func (s *ConnectService) singleBrokerResourceForProvider(ctx context.Context, providerID string) (*resource.Resource, error) {
	rows, err := s.resources.List(ctx, output.ResourceFilter{
		BackendKind:      resource.BackendBroker,
		BrokerProviderID: providerID,
	})
	if err != nil {
		return nil, fmt.Errorf("lookup broker resources for provider %q: %w", providerID, err)
	}
	if len(rows) == 0 {
		return nil, fmt.Errorf("%w: no broker resource references provider %q", domain.ErrInvalidTarget, providerID)
	}
	if len(rows) > 1 {
		return nil, fmt.Errorf("%w: provider %q has %d broker-backed resources", domain.ErrAmbiguousBrokerResource, providerID, len(rows))
	}
	return rows[0], nil
}

// matchesASelf reports whether the URL is exactly the AS's own /connections
// page — the canonical destination the consent_url synthesizer sends users to.
func (s *ConnectService) matchesASelf(ctx context.Context, redirectBaseURL, returnURL string) bool {
	// Best-effort: if issuer resolution fails, treat it as empty so only
	// redirectBaseURL is checked (safe conservative behavior).
	issuer, err := s.issuerProvider.Issuer(ctx)
	if err != nil {
		s.logger.WarnContext(ctx, "treating issuer as empty; redirect_uri validation may reject legitimate URLs",
			"error", err,
			"site", "matchesASelf",
		)
	}
	for _, b := range []string{redirectBaseURL, issuer} {
		if b == "" {
			continue
		}
		if returnURL == b+"/connections" {
			return true
		}
	}
	return false
}

// callbackURL builds the absolute upstream redirect_uri the brokerproto
// adapter registers with the upstream OAuth provider. Format:
// `<redirect_base_url|issuer>/connect/<provider>/callback`. The
// per-provider path means a single brokerproto/oauth adapter instance can
// serve every provider in the deployment — the URL is computed by the
// orchestration layer and passed to the adapter on each call.
//
// Returns "" when neither redirect_base_url nor issuer are set; the
// adapter then omits redirect_uri (acceptable for upstreams that fall back
// to the OAuth client's single registered redirect URI).
func (s *ConnectService) callbackURL(ctx context.Context, redirectBaseURL, providerSlug string) string {
	base := redirectBaseURL
	if redirectBaseURL == "" {
		// Best-effort: if issuer resolution fails, fall back to empty so the
		// adapter omits redirect_uri (acceptable for upstreams with a single
		// registered redirect URI).
		var issuerErr error
		base, issuerErr = s.issuerProvider.Issuer(ctx)
		if issuerErr != nil {
			s.logger.WarnContext(ctx, "treating issuer as empty; upstream callback URL may omit base",
				"error", issuerErr,
				"site", "callbackURL",
			)
		}
	}
	if base == "" {
		return ""
	}
	return base + "/connect/" + providerSlug + "/callback"
}

// generateStateToken produces an HMAC-bound state token. The atomic Consume
// on ConnectPendingStateStore is the primary CSRF gate; the HMAC is
// defense-in-depth against state-row forgery.
func (s *ConnectService) generateStateToken(ctx context.Context, userID, providerSlug, returnURL string) (string, error) {
	key, err := s.resolveStateKey(ctx)
	if err != nil {
		return "", err
	}
	stateID := crypto.GenerateRandomString(16)
	mac := computeStateHMAC(key, stateID, userID, providerSlug, returnURL)
	return stateID + "." + base64.RawURLEncoding.EncodeToString(mac), nil
}

func (s *ConnectService) verifyStateToken(ctx context.Context, stateToken, userID, providerSlug, returnURL string) (bool, error) {
	key, err := s.resolveStateKey(ctx)
	if err != nil {
		return false, err
	}
	parts := strings.SplitN(stateToken, ".", 2)
	if len(parts) != 2 {
		return false, nil
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return false, nil
	}
	expected := computeStateHMAC(key, parts[0], userID, providerSlug, returnURL)
	return hmac.Equal(sig, expected), nil
}

// resolveStateKey resolves the per-call HMAC signing key and rejects an empty
// one defensively, so an alternate provider cannot cause signing/verification
// with no key.
func (s *ConnectService) resolveStateKey(ctx context.Context) ([]byte, error) {
	cfg, err := s.stateConfig.Config(ctx)
	if err != nil {
		return nil, fmt.Errorf("connect: resolve state config: %w", err)
	}
	if len(cfg.Key) == 0 {
		return nil, fmt.Errorf("connect: empty state signing key")
	}
	return cfg.Key, nil
}

func computeStateHMAC(key []byte, stateID, userID, providerSlug, returnURL string) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(stateID + ":" + userID + ":" + providerSlug + ":" + returnURL))
	return mac.Sum(nil)
}

// rebindStateInURL replaces the `state` query parameter in upstreamURL with
// stateToken. The brokerproto/oauth adapter chooses its own state value when
// it builds the URL; ConnectService swaps in the HMAC-bound token so the
// callback handler can verify it without depending on the adapter's choice.
func rebindStateInURL(upstreamURL, stateToken string) string {
	parsed, err := url.Parse(upstreamURL)
	if err != nil {
		return upstreamURL
	}
	q := parsed.Query()
	if !q.Has("state") {
		return upstreamURL
	}
	q.Set("state", stateToken)
	parsed.RawQuery = q.Encode()
	return parsed.String()
}
