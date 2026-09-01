package services

import (
	"context"
	"fmt"
	"log/slog"
	"slices"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	otelmetric "go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/trace"

	"github.com/authplane/authserver/internal/crypto"
	"github.com/authplane/authserver/internal/domain"
	"github.com/authplane/authserver/internal/domain/audit"
	"github.com/authplane/authserver/internal/domain/client"
	"github.com/authplane/authserver/internal/observability"
	"github.com/authplane/authserver/internal/ports/input"
	"github.com/authplane/authserver/internal/ports/output"
)

// DCRService handles Dynamic Client Registration (RFC 7591).
type DCRService struct {
	clients      output.ClientStore
	audit        AuditRecorder
	modeProvider output.DCRModeProvider // resolves the DCR policy from ctx
	// grantsProvider resolves the grant types the AS honors, per request.
	// nil ⇒ no enforcement (tests). Optional, injected via WithDCREnabledGrants.
	grantsProvider output.EnabledGrantsProvider
	logger         *slog.Logger
	tracer         trace.Tracer
	metrics        *observability.Metrics
}

var _ input.DCRPort = (*DCRService)(nil)

// DCRServiceOpt configures optional DCRService dependencies.
type DCRServiceOpt func(*DCRService)

// WithDCREnabledGrants injects the per-request enabled-grants provider.
// DCRService rejects RegisterClient requests carrying a grant outside the set
// the provider returns so a client whose grant /oauth/token cannot serve never
// lands as status=active.
func WithDCREnabledGrants(p output.EnabledGrantsProvider) DCRServiceOpt {
	return func(s *DCRService) { s.grantsProvider = p }
}

// NewDCRService creates a new DCR service.
func NewDCRService(
	clients output.ClientStore,
	modeProvider output.DCRModeProvider,
	obs *observability.Provider,
	auditor AuditRecorder,
	opts ...DCRServiceOpt,
) *DCRService {
	s := &DCRService{
		clients:      clients,
		audit:        auditor,
		modeProvider: modeProvider,
		logger:       obs.Logger,
		tracer:       obs.Tracer,
		metrics:      obs.Metrics,
	}
	for _, opt := range opts {
		opt(s)
	}
	return s
}

// RegisterClient creates a new client via DCR (RFC 7591).
func (s *DCRService) RegisterClient(ctx context.Context, req input.RegisterClientRequest) (*input.RegisterClientResponse, error) {
	ctx, span := s.tracer.Start(ctx, "DCRService.RegisterClient")
	defer span.End()

	policy, err := s.modeProvider.Get(ctx)
	if err != nil {
		// Fail closed: if the policy can't be resolved we reject rather than
		// fall back to a permissive default.
		s.logger.ErrorContext(ctx, "dcr mode provider failed during RegisterClient", "error", err)
		span.RecordError(err)
		return nil, fmt.Errorf("get dcr mode: %w", err)
	}

	span.SetAttributes(
		attribute.String("registration_source", "dcr"),
		attribute.String("dcr_mode", policy.Mode),
	)

	// Enforce DCR mode.
	if err := s.enforceMode(policy, req); err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}

	// Apply RFC 7591 defaults.
	params := client.CreateParams{
		Name:                    req.ClientName,
		RedirectURIs:            req.RedirectURIs,
		GrantTypes:              req.GrantTypes,
		ResponseTypes:           req.ResponseTypes,
		TokenEndpointAuthMethod: req.TokenEndpointAuthMethod,
		RegistrationSource:      client.SourceDCR,
		IsAgent:                 req.Agent,
		AgentDescription:        req.AgentDescription,
	}
	params.Defaults()

	// Resolve the enabled-grant set per request (shared helper: nil provider ⇒
	// no enforcement, provider error ⇒ fail closed).
	enabledGrants, gErr := resolveEnabledGrants(ctx, s.grantsProvider)
	if gErr != nil {
		span.RecordError(gErr)
		span.SetStatus(codes.Error, gErr.Error())
		return nil, gErr
	}
	// Validate.
	if err := client.ValidateCreateParams(params, enabledGrants); err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return nil, fmt.Errorf("%w: %v", domain.ErrInvalidClient, err)
	}

	// Generate client_id.
	now := time.Now().UTC()
	c := &client.Client{
		ID:                      crypto.GenerateClientID(),
		Name:                    params.Name,
		RedirectURIs:            params.RedirectURIs,
		GrantTypes:              params.GrantTypes,
		ResponseTypes:           params.ResponseTypes,
		TokenEndpointAuthMethod: params.TokenEndpointAuthMethod,
		Status:                  client.StatusActive,
		RegistrationSource:      client.SourceDCR,
		IsAgent:                 params.IsAgent,
		AgentDescription:        params.AgentDescription,
		IssuedAt:                now,
		UpdatedAt:               now,
	}

	// Handle confidential client (secret generation).
	var plainSecret string
	if params.TokenEndpointAuthMethod != "none" {
		plainSecret = crypto.GenerateClientSecret()
		hash, err := crypto.HashClientSecret(plainSecret)
		if err != nil {
			span.RecordError(err)
			span.SetStatus(codes.Error, err.Error())
			return nil, fmt.Errorf("hash client secret: %w", err)
		}
		c.SecretHash = hash
	}

	// Persist.
	if err := s.clients.Create(ctx, c); err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return nil, fmt.Errorf("create client: %w", err)
	}

	span.SetAttributes(attribute.String("client_id", c.ID))

	s.logger.InfoContext(ctx, "registered client via dcr",
		"client_id", c.ID,
		"client_name", c.Name,
		"auth_method", c.TokenEndpointAuthMethod,
		"mode", policy.Mode,
	)

	s.metrics.ClientsRegistered.Add(ctx, 1, otelmetric.WithAttributes(
		attribute.String("source", "dcr"),
	))

	if s.audit != nil {
		s.audit.Record(ctx, audit.NewEvent(audit.ActionClientRegistered, "", c.ID, "", "source=dcr"))
	}

	resp := &input.RegisterClientResponse{
		ClientID:                c.ID,
		ClientIDIssuedAt:        now.Unix(),
		RedirectURIs:            c.RedirectURIs,
		ClientName:              c.Name,
		GrantTypes:              c.GrantTypes,
		ResponseTypes:           c.ResponseTypes,
		TokenEndpointAuthMethod: c.TokenEndpointAuthMethod,
		Agent:                   c.IsAgent,
		AgentDescription:        c.AgentDescription,
	}

	if plainSecret != "" {
		resp.ClientSecret = plainSecret
		zero := int64(0)
		resp.ClientSecretExpiresAt = &zero // 0 = never expires (RFC 7591 §3.2)
	}

	return resp, nil
}

// SetMode updates the DCR mode at runtime (thread-safe).
func (s *DCRService) SetMode(ctx context.Context, mode string) error {
	return s.modeProvider.Set(ctx, output.DCRMode{Mode: mode})
}

// GetMode returns the current DCR mode resolved by the configured
// DCRModeProvider. It propagates a provider error so callers (e.g. the admin
// DCR settings handler) can surface the failure with a 500 instead of
// reporting an empty mode. GetMode/SetMode are the runtime read/write control
// used by the admin DCR handler.
func (s *DCRService) GetMode(ctx context.Context) (string, error) {
	mode, err := s.modeProvider.Get(ctx)
	if err != nil {
		// The caller (admin DCR settings handler) logs and maps this to a 500;
		// don't double-log here.
		return "", fmt.Errorf("get dcr mode: %w", err)
	}
	return mode.Mode, nil
}

// enforceMode checks whether the registration request is allowed under the
// DCR policy resolved for this request.
func (s *DCRService) enforceMode(policy output.DCRMode, req input.RegisterClientRequest) error {
	switch policy.Mode {
	case "open":
		return nil

	case "approved_redirects":
		// Exact string match only — no wildcards, no prefix matching, no
		// normalization. This is a security invariant per RFC 9700 / OAuth
		// Security BCP.
		for _, uri := range req.RedirectURIs {
			if !slices.Contains(policy.ApprovedRedirects, uri) {
				return fmt.Errorf("%w: redirect_uri %q not in approved list", domain.ErrInvalidRedirectURI, uri)
			}
		}
		return nil

	case "admin_only":
		return domain.ErrRegistrationDisabled

	default:
		return fmt.Errorf("unknown dcr mode: %s", policy.Mode)
	}
}
