package services

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"

	"github.com/authplane/authserver/internal/crypto"
	"github.com/authplane/authserver/internal/domain"
	"github.com/authplane/authserver/internal/domain/client"
	"github.com/authplane/authserver/internal/domain/resource"
	"github.com/authplane/authserver/internal/domain/session"
	"github.com/authplane/authserver/internal/observability"
	"github.com/authplane/authserver/internal/ports/input"
	"github.com/authplane/authserver/internal/ports/output"
)

var _ input.AuthorizePort = (*AuthorizeService)(nil)

// AuthorizeService implements the authorization code flow.
type AuthorizeService struct {
	clients       output.ClientStore
	sessions      output.SessionStore
	consentGrants output.ConsentGrantStore
	cimd          input.CIMDPort // nil when CIMD is disabled
	registry      *ResourceRegistry
	oauthConfig   output.OAuthConfigProvider
	logger        *slog.Logger
	tracer        trace.Tracer
	metrics       *observability.Metrics
}

// ResourceInfo holds resource configuration needed by the authorize and token services.
type ResourceInfo struct {
	URI               string
	Scopes            []string          // advertised scope names
	ScopeDescriptions map[string]string // name → human-readable description (consent UI)
	ClientID          string            // client authorized to exchange tokens for this resource (populates may_act claim)
	Audience          string            // audience value for tokens targeting this resource
}

// NewAuthorizeService creates a new authorize service.
// oauthConfig supplies per-request OAuth behavior (e.g. RequireScope). Use
// static.NewOAuthConfigProvider to wrap a boot-time bool (RFC 6749 §3.3 /
// ADR-012).
func NewAuthorizeService(
	clients output.ClientStore,
	sessions output.SessionStore,
	consentGrants output.ConsentGrantStore,
	cimd input.CIMDPort,
	registry *ResourceRegistry,
	oauthConfig output.OAuthConfigProvider,
	obs *observability.Provider,
) *AuthorizeService {
	if oauthConfig == nil {
		panic("NewAuthorizeService: oauthConfig must not be nil")
	}
	return &AuthorizeService{
		clients:       clients,
		sessions:      sessions,
		consentGrants: consentGrants,
		cimd:          cimd,
		registry:      registry,
		oauthConfig:   oauthConfig,
		logger:        obs.Logger,
		tracer:        obs.Tracer,
		metrics:       obs.Metrics,
	}
}

// StartAuthorization validates the authorize request and creates an auth session.
func (s *AuthorizeService) StartAuthorization(ctx context.Context, req input.AuthorizeRequest) (*input.AuthorizeResult, error) {
	ctx, span := s.tracer.Start(ctx, "AuthorizeService.StartAuthorization")
	defer span.End()

	span.SetAttributes(
		attribute.String("client_id", req.ClientID),
		attribute.String("scope", req.Scope),
		attribute.String("resource", req.Resource),
	)

	if req.ResponseType != "code" {
		err := fmt.Errorf("%w: response_type must be 'code'", domain.ErrInvalidGrant)
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}

	c, err := s.lookupClient(ctx, req.ClientID)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}

	if !c.IsActive() {
		span.RecordError(domain.ErrClientSuspended)
		span.SetStatus(codes.Error, "client suspended")
		return nil, domain.ErrClientSuspended
	}

	if !c.HasRedirectURI(req.RedirectURI) {
		span.RecordError(domain.ErrInvalidRedirectURI)
		span.SetStatus(codes.Error, "invalid redirect_uri")
		return nil, domain.ErrInvalidRedirectURI
	}

	if req.CodeChallenge == "" {
		err = fmt.Errorf("%w: code_challenge is required", domain.ErrInvalidPKCE)
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}
	if challengeErr := crypto.ValidateChallengeMethod(req.CodeChallengeMethod); challengeErr != nil {
		err = fmt.Errorf("%w: %v", domain.ErrInvalidPKCE, challengeErr)
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}

	// Resolve the resource= parameter through the unified registry. The
	// resolver accepts slug OR URI per  / the data model, and
	// returns typed errors (ErrResourceNotFound / ErrAmbiguousResource)
	// the handler maps to the error page. A Broker-backed resource is
	// rejected with ErrConsentResourceNotMint —  defense in depth
	// for the DESIGN_v4 §7 Mint-only invariant.
	var resolved *resource.Resource
	if req.Resource != "" {
		resolved, err = s.registry.Resolve(ctx, req.Resource)
		if err != nil {
			span.RecordError(err)
			span.SetStatus(codes.Error, err.Error())
			return nil, err
		}
		if !resolved.IsMint() {
			span.RecordError(domain.ErrConsentResourceNotMint)
			span.SetStatus(codes.Error, domain.ErrConsentResourceNotMint.Error())
			return nil, domain.ErrConsentResourceNotMint
		}
		// Persist the canonical URI form on the session — previously
		// stored req.Resource verbatim. Slugs can be renamed
		// (the data model); URIs are stable identifiers and the
		// JWT aud claim later reads from this field.
		req.Resource = resolved.URI
	}

	// Scope handling: when scope parameter is absent from the authorize request.
	if req.Scope == "" {
		// RequireScope only matters when scope is absent, so resolve the config
		// inside this branch — the common scope-present path skips it and can't
		// fail on an otherwise-irrelevant config error.
		oauthCfg, err := s.oauthConfig.Config(ctx)
		if err != nil {
			span.RecordError(err)
			span.SetStatus(codes.Error, err.Error())
			return nil, fmt.Errorf("resolve oauth config: %w", err)
		}
		if oauthCfg.RequireScope {
			// Strict mode (oauth.require_scope=true): reject per RFC 6749 §3.3.
			err := fmt.Errorf("%w: scope parameter is required (oauth.require_scope=true)", domain.ErrInvalidScope)
			span.RecordError(err)
			span.SetStatus(codes.Error, err.Error())
			return nil, err
		}
		// ADR-012 (oauth.require_scope=false): default to registered scopes.
		// MCP clients (notably Claude Code) omit scope from authorize requests.
		// Rather than issuing a zero-scope token (which causes opaque 403s on
		// every tool call), substitute all registered scopes for the resource.
		req.Scope = s.collectDefaultScopes(ctx, req.Resource)
		if req.Scope != "" {
			span.SetAttributes(attribute.Bool("scope.defaulted", true))
			s.logger.WarnContext(ctx, "scope absent from authorize request, using defaults",
				"client_id", req.ClientID,
				"resource", req.Resource,
				"defaulted_scope", req.Scope,
			)
		}
	}

	if req.Scope != "" && req.Resource != "" {
		if err := s.validateScopes(ctx, req.Scope, req.Resource); err != nil {
			span.RecordError(err)
			span.SetStatus(codes.Error, err.Error())
			return nil, err
		}
	}

	hasUser := req.UserID != ""
	loginRequired := !hasUser
	consentRequired := true

	if hasUser && resolved != nil {
		grant, err := s.consentGrants.Get(ctx, req.UserID, c.ID, resolved.ID)
		if err != nil {
			span.RecordError(err)
			span.SetStatus(codes.Error, err.Error())
			return nil, fmt.Errorf("check consent: %w", err)
		}
		// The store's Get already filters revoked_at IS NULL; the
		// IsRevoked check is structurally redundant — kept for defense
		// in depth.
		//
		//  note: this site uses the boolean CoversScopes (rather
		// than the new services.scopesNotConsented helper) deliberately.
		// /authorize's consent-skip is a routing decision — does an
		// existing grant cover the request, or do we redirect to
		// /consent? — not an error surface, so the missing-scope
		// diagnostic that scopesNotConsented carries has no consumer
		// here. If a future increment adds a "scope expansion" badge
		// to the /consent UI, lift to scopesNotConsented then.
		if grant != nil && !grant.IsRevoked() && grant.CoversScopes(strings.Fields(req.Scope)) {
			consentRequired = false
		}
	}

	now := time.Now().UTC()
	sess := &session.AuthSession{
		ID:                  crypto.GenerateRandomString(16),
		ClientID:            c.ID,
		UserID:              req.UserID,
		RedirectURI:         req.RedirectURI,
		Scope:               req.Scope,
		Resource:            req.Resource,
		State:               req.State,
		CodeChallenge:       req.CodeChallenge,
		CodeChallengeMethod: req.CodeChallengeMethod,
		ExpiresAt:           now.Add(session.AuthCodeTTL),
		CreatedAt:           now,
	}

	if err := s.sessions.Create(ctx, sess); err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return nil, fmt.Errorf("create session: %w", err)
	}

	s.logger.InfoContext(ctx, "authorization started",
		"session_id", sess.ID,
		"client_id", c.ID,
		"login_required", loginRequired,
		"consent_required", consentRequired,
	)

	return &input.AuthorizeResult{
		Session:         sess,
		LoginRequired:   loginRequired,
		ConsentRequired: consentRequired,
	}, nil
}

// CompleteAuthorization generates an auth code and updates the session.
func (s *AuthorizeService) CompleteAuthorization(ctx context.Context, sessionID string) (*input.CompleteAuthResult, error) {
	ctx, span := s.tracer.Start(ctx, "AuthorizeService.CompleteAuthorization")
	defer span.End()

	sess, err := s.sessions.GetByID(ctx, sessionID)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return nil, fmt.Errorf("get session: %w", err)
	}

	span.SetAttributes(attribute.String("client_id", sess.ClientID))

	if sess.IsExpired() {
		span.RecordError(domain.ErrSessionExpired)
		span.SetStatus(codes.Error, "session expired")
		return nil, domain.ErrSessionExpired
	}

	code := crypto.GenerateAuthCode()
	codeHash := crypto.HashSHA256(code)

	if err := s.sessions.UpdateCodeHashAndScope(ctx, sessionID, codeHash, sess.Scope); err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return nil, fmt.Errorf("update code hash: %w", err)
	}

	s.logger.InfoContext(ctx, "authorization completed", "session_id", sessionID, "client_id", sess.ClientID)

	// Record auth flow duration (session creation → code generation).
	// No client_id label — high cardinality on histograms causes Prometheus cardinality explosion.
	s.metrics.AuthFlowDuration.Record(ctx, time.Since(sess.CreatedAt).Seconds())

	return &input.CompleteAuthResult{
		RedirectURI: sess.RedirectURI,
		Code:        code,
		State:       sess.State,
	}, nil
}

func (s *AuthorizeService) lookupClient(ctx context.Context, clientID string) (*client.Client, error) {
	c, err := s.clients.GetByID(ctx, clientID)
	if err != nil {
		if clientID != "" && (strings.HasPrefix(clientID, "http://") || strings.HasPrefix(clientID, "https://")) {
			// Try DB lookup by CIMD URL first.
			c, err = s.clients.GetByCIMDURL(ctx, clientID)
			if err != nil {
				return nil, domain.ErrInvalidClient
			}
			if c != nil {
				return c, nil
			}
			// Client not in DB — attempt CIMD auto-registration if enabled.
			if s.cimd != nil {
				c, err = s.cimd.VerifyCIMD(ctx, clientID)
				if err != nil {
					s.logger.WarnContext(ctx, "cimd auto-registration failed", "client_id", clientID, "error", err)
					return nil, domain.ErrInvalidClient
				}
				return c, nil
			}
			return nil, domain.ErrInvalidClient
		}
		return nil, domain.ErrInvalidClient
	}
	return c, nil
}

// collectDefaultScopes returns all registered scopes for a resource (or all scopes
// globally if resource is empty) as a space-separated string. Used by ADR-012 to
// substitute a default scope when the client omits it from the authorize request.
func (s *AuthorizeService) collectDefaultScopes(ctx context.Context, resourceURI string) string {
	resources, err := s.registry.List(ctx)
	if err != nil {
		s.logger.WarnContext(ctx, "default scope collection: resource list failed, substituting no scopes", "error", err)
		return ""
	}

	seen := make(map[string]bool)
	var scopes []string

	for _, r := range resources {
		if resourceURI != "" && r.URI != resourceURI {
			continue
		}
		for _, sc := range r.Scopes {
			if !seen[sc] {
				seen[sc] = true
				scopes = append(scopes, sc)
			}
		}
		if resourceURI != "" {
			break
		}
	}

	return strings.Join(scopes, " ")
}

func (s *AuthorizeService) validateScopes(ctx context.Context, scopeStr, resourceURI string) error {
	scopes := strings.Fields(scopeStr)

	// Build allowed set from the resource registry.
	resources, err := s.registry.List(ctx)
	if err != nil {
		return fmt.Errorf("validate scopes: %w", err)
	}
	allowed := make(map[string]bool)
	for _, r := range resources {
		if r.URI == resourceURI {
			for _, sc := range r.Scopes {
				allowed[sc] = true
			}
			break
		}
	}

	// If no scopes are configured at all, reject the request.
	// An empty scope registry means no scopes have been defined for this resource.
	if len(allowed) == 0 {
		s.logger.WarnContext(ctx, "no scopes registered for resource, denying request",
			"resource", resourceURI,
		)
		return fmt.Errorf("%w: no scopes registered for resource %q", domain.ErrInvalidScope, resourceURI)
	}
	for _, sc := range scopes {
		if !allowed[sc] {
			return fmt.Errorf("%w: scope %q not allowed for resource %q", domain.ErrInvalidScope, sc, resourceURI)
		}
	}
	return nil
}
