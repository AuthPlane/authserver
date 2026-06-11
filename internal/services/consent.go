package services

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	otelmetric "go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/trace"

	"github.com/authplane/authserver/internal/crypto"
	"github.com/authplane/authserver/internal/domain"
	"github.com/authplane/authserver/internal/domain/audit"
	"github.com/authplane/authserver/internal/domain/resource"
	"github.com/authplane/authserver/internal/domain/scope"
	"github.com/authplane/authserver/internal/observability"
	"github.com/authplane/authserver/internal/ports/input"
	"github.com/authplane/authserver/internal/ports/output"
)

var _ input.ConsentPort = (*ConsentService)(nil)

// ConsentService manages user consent for OAuth flows. It resolves the
// session's resource through the unified ResourceRegistry, renders
// the per-MCP consent screen sourced from the resolved resource's scope
// catalog, and persists approvals to the unified ConsentGrantStore.
//
// Mint-only invariant (DESIGN_v4 §7): consent only applies to Mint
// resources. Broker resources are gated by operator policy + broker_grants
// and never appear on this consent screen.
type ConsentService struct {
	consentGrants output.ConsentGrantStore
	sessions      output.SessionStore
	clients       output.ClientStore
	registry      *ResourceRegistry
	txManager     output.TransactionManager // optional — nil if not available
	audit         AuditRecorder
	logger        *slog.Logger
	tracer        trace.Tracer
	metrics       *observability.Metrics
}

// NewConsentService creates a new consent service.
func NewConsentService(
	consentGrants output.ConsentGrantStore,
	sessions output.SessionStore,
	clients output.ClientStore,
	registry *ResourceRegistry,
	obs *observability.Provider,
	auditor AuditRecorder,
) *ConsentService {
	return &ConsentService{
		consentGrants: consentGrants,
		sessions:      sessions,
		clients:       clients,
		registry:      registry,
		audit:         auditor,
		logger:        obs.Logger,
		tracer:        obs.Tracer,
		metrics:       obs.Metrics,
	}
}

// WithConsentTransactions enables transactional atomicity for consent + code generation.
func (s *ConsentService) WithConsentTransactions(tm output.TransactionManager) {
	s.txManager = tm
}

// GetPendingConsent returns the consent view for a pending authorization
// session. Resolves the session's resource through the registry (slug or
// URI per ), enforces the Mint-only invariant, and renders the
// per-scope catalog filtered by the session's requested scopes.
func (s *ConsentService) GetPendingConsent(ctx context.Context, sessionID string) (*input.ConsentView, error) {
	ctx, span := s.tracer.Start(ctx, "ConsentService.GetPendingConsent")
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

	c, err := s.clients.GetByID(ctx, sess.ClientID)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return nil, fmt.Errorf("get client: %w", err)
	}

	view := &input.ConsentView{
		SessionID:  sess.ID,
		ClientName: c.Name,
		ClientID:   c.ID,
		Resource:   sess.Resource,
		Scopes:     []input.ScopeInfo{},
	}

	// Empty resource= takes the AS-level path (e.g., introspection / OIDC
	// userinfo). No registry lookup; render the requested scopes with no
	// catalog descriptions. This preserves legacy behavior for the
	// edge case.
	if sess.Resource == "" {
		scopeFields := strings.Fields(sess.Scope)
		view.Scopes = make([]input.ScopeInfo, 0, len(scopeFields))
		for _, scopeName := range scopeFields {
			view.Scopes = append(view.Scopes, input.ScopeInfo{Name: scopeName})
		}
		return view, nil
	}

	resolved, err := s.registry.Resolve(ctx, sess.Resource)
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

	view.Resource = resolved.URI
	view.ResourceSlug = resolved.Slug
	view.ResourceDisplayName = resolved.DisplayName
	if view.ResourceDisplayName == "" {
		view.ResourceDisplayName = resolved.Slug
	}
	if view.ResourceDisplayName == "" {
		view.ResourceDisplayName = resolved.URI
	}

	view.Scopes = filterScopes(resolved.Scopes, strings.Fields(sess.Scope))
	return view, nil
}

// filterScopes returns the catalog entries whose Name appears in the
// requested set, preserving catalog order so the consent screen reads the
// same regardless of agent ordering.
func filterScopes(catalog []resource.Scope, requested []string) []input.ScopeInfo {
	if len(requested) == 0 {
		return []input.ScopeInfo{}
	}
	wanted := make(map[string]struct{}, len(requested))
	for _, r := range requested {
		wanted[r] = struct{}{}
	}
	out := make([]input.ScopeInfo, 0, len(catalog))
	for _, sc := range catalog {
		if _, ok := wanted[sc.Name]; !ok {
			continue
		}
		out = append(out, input.ScopeInfo{
			Name:        sc.Name,
			Description: sc.Description,
		})
	}
	return out
}

// GrantConsent records the user's approval, generates auth code, and returns redirect info.
func (s *ConsentService) GrantConsent(ctx context.Context, req input.GrantConsentRequest) (*input.GrantConsentResult, error) {
	ctx, span := s.tracer.Start(ctx, "ConsentService.GrantConsent")
	defer span.End()

	sess, err := s.sessions.GetByID(ctx, req.SessionID)
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

	// Without this check, any logged-in user holding the session_id can
	// advance someone else's flow — the auth code is bound to sess.UserID at
	// issuance time, so the foreign caller's submission yields a code for
	// the original user with a misattributed consent grant.
	if req.UserID == "" || (sess.UserID != "" && sess.UserID != req.UserID) {
		span.RecordError(domain.ErrInvalidGrant)
		span.SetStatus(codes.Error, "session owner mismatch")
		return nil, domain.ErrInvalidGrant
	}

	// Validate approved scopes: must be a non-empty subset of the session's
	// requested scopes.
	//
	// Empty ApprovedScopes is invalid — not "approve everything." The consent
	// form always renders the requested scopes as pre-checked boxes, so the
	// only way to arrive here with zero scopes is for the user to actively
	// uncheck every box and submit allow. Treating that as "approve all"
	// would invert user intent. If the user wanted no access, they would
	// have clicked deny. Surface invalid_scope so the handler can re-prompt.
	requestedScopes := scope.Parse(sess.Scope)
	approvedScopes := scope.New(req.ApprovedScopes...)
	if approvedScopes.IsEmpty() {
		span.RecordError(domain.ErrInvalidScope)
		span.SetStatus(codes.Error, "no scopes approved")
		return nil, domain.ErrInvalidScope
	}
	if !approvedScopes.IsSubset(requestedScopes) {
		span.RecordError(domain.ErrInvalidScope)
		span.SetStatus(codes.Error, "approved scopes exceed requested scopes")
		return nil, domain.ErrInvalidScope
	}

	// Narrow to only the approved scopes (user may have unchecked some).
	effectiveScope := approvedScopes.String()

	// Resolve the session's resource for both the Mint-only check and the
	// resource_id we persist on the unified consent grant. Empty
	// resource= takes the AS-level path (no registry hit; no grant
	// written).
	var resolved *resource.Resource
	if sess.Resource != "" {
		resolved, err = s.registry.Resolve(ctx, sess.Resource)
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
	}

	effectiveScopeList := strings.Fields(effectiveScope)

	// Generate auth code with the narrowed scope.
	code := crypto.GenerateAuthCode()
	codeHash := crypto.HashSHA256(code)

	// Persist consent + generate code atomically to prevent orphaned consent
	// grants if code generation fails. The unified store's Upsert
	// is unconditional (no "non-remember" mode); the wire-format Remember
	// flag is preserved for shape parity but is now a no-op.
	persistAndCode := func(txCtx context.Context) error {
		if resolved != nil {
			now := time.Now().UTC()
			grant := &resource.ConsentGrant{
				ID:         crypto.GenerateRandomString(16),
				UserID:     req.UserID,
				ClientID:   sess.ClientID,
				ResourceID: resolved.ID,
				Scopes:     effectiveScopeList,
				CreatedAt:  now,
				UpdatedAt:  now,
			}
			if upsertErr := s.consentGrants.Upsert(txCtx, grant); upsertErr != nil {
				return fmt.Errorf("upsert consent grant: %w", upsertErr)
			}
		}
		if updateErr := s.sessions.UpdateCodeHashAndScope(txCtx, req.SessionID, codeHash, effectiveScope); updateErr != nil {
			return fmt.Errorf("update code hash and scope: %w", updateErr)
		}
		return nil
	}

	if s.txManager != nil {
		err = s.txManager.WithTransaction(ctx, persistAndCode)
	} else {
		err = persistAndCode(ctx)
	}
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}

	s.logger.InfoContext(ctx, "consent granted",
		"session_id", req.SessionID,
		"client_id", sess.ClientID,
		"remember", req.Remember,
	)

	s.metrics.ConsentDecisions.Add(ctx, 1, otelmetric.WithAttributes(
		attribute.String("decision", "granted"),
	))

	if s.audit != nil {
		detail := ""
		if resolved != nil {
			detail = fmt.Sprintf("resource=%s scopes=%s", resolved.Slug, strings.Join(effectiveScopeList, " "))
		}
		s.audit.Record(ctx, audit.NewEvent(audit.ActionConsentGranted, req.UserID, sess.ClientID, "", detail))
	}

	return &input.GrantConsentResult{
		RedirectURI: sess.RedirectURI,
		Code:        code,
		State:       sess.State,
	}, nil
}

// DenyConsent records the user's denial and deletes the authorization
// session so it cannot be re-prompted and approved later within its TTL.
// A best-effort delete: failure is logged but does not block the denial
// response — the user has already chosen, and a stale session row will
// be reaped by DeleteExpired at worst within the session's natural TTL.
func (s *ConsentService) DenyConsent(ctx context.Context, sessionID, userID string) error {
	ctx, span := s.tracer.Start(ctx, "ConsentService.DenyConsent")
	defer span.End()

	// Owner binding mirror of GrantConsent. We look up the session before
	// deletion so a stranger holding a leaked session_id cannot abort the
	// owner's pending flow. A missing session is treated as success-shaped
	// (the legacy contract returns ErrConsentRequired) — the lookup error is
	// only consulted to enforce the ownership check when the session exists.
	if sess, err := s.sessions.GetByID(ctx, sessionID); err == nil && sess != nil {
		if userID == "" || (sess.UserID != "" && sess.UserID != userID) {
			span.RecordError(domain.ErrInvalidGrant)
			span.SetStatus(codes.Error, "session owner mismatch on deny")
			return domain.ErrInvalidGrant
		}
	}

	if err := s.sessions.Delete(ctx, sessionID); err != nil {
		span.RecordError(err)
		s.logger.WarnContext(ctx, "consent deny: session delete failed (will expire naturally)",
			"session_id", sessionID, "error", err,
		)
	}

	s.logger.InfoContext(ctx, "consent denied", "session_id", sessionID)

	s.metrics.ConsentDecisions.Add(ctx, 1, otelmetric.WithAttributes(
		attribute.String("decision", "denied"),
	))

	if s.audit != nil {
		s.audit.Record(ctx, audit.NewEvent(audit.ActionConsentDenied, "", "", "", "session="+sessionID))
	}
	return domain.ErrConsentRequired
}
