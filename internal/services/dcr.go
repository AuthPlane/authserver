package services

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
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

// DCRMode holds the DCR configuration values needed by the service.
// Defined here to avoid importing internal/config from services.
type DCRMode struct {
	Mode              string
	ApprovedRedirects []string
}

// DCRService handles Dynamic Client Registration (RFC 7591).
type DCRService struct {
	clients       output.ClientStore
	audit         AuditRecorder
	dcrCfg        DCRMode
	enabledGrants []string     // grant types the AS is configured to honor; empty = no enforcement
	mu            sync.RWMutex // protects dcrCfg for runtime updates
	logger        *slog.Logger
	tracer        trace.Tracer
	metrics       *observability.Metrics
}

var _ input.DCRPort = (*DCRService)(nil)

// DCRServiceOpt configures optional DCRService dependencies.
type DCRServiceOpt func(*DCRService)

// WithDCREnabledGrants sets the grant types the running AS is configured
// to honor. DCRService rejects RegisterClient requests carrying a grant
// outside this set so a client whose grant the /oauth/token
// endpoint cannot serve never lands as status=active.
func WithDCREnabledGrants(grants []string) DCRServiceOpt {
	return func(s *DCRService) { s.enabledGrants = grants }
}

// NewDCRService creates a new DCR service.
func NewDCRService(
	clients output.ClientStore,
	dcrCfg DCRMode,
	obs *observability.Provider,
	auditor AuditRecorder,
	opts ...DCRServiceOpt,
) *DCRService {
	s := &DCRService{
		clients: clients,
		audit:   auditor,
		dcrCfg:  dcrCfg,
		logger:  obs.Logger,
		tracer:  obs.Tracer,
		metrics: obs.Metrics,
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

	currentMode := s.GetMode()
	span.SetAttributes(
		attribute.String("registration_source", "dcr"),
		attribute.String("dcr_mode", currentMode),
	)

	// Enforce DCR mode.
	if err := s.enforceMode(req); err != nil {
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

	// Validate.
	if err := client.ValidateCreateParams(params, s.enabledGrants); err != nil {
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
		"mode", currentMode,
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
func (s *DCRService) SetMode(mode string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.dcrCfg.Mode = mode
}

// GetMode returns the current DCR mode (thread-safe).
func (s *DCRService) GetMode() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.dcrCfg.Mode
}

// enforceMode checks whether the registration request is allowed under the configured DCR mode.
func (s *DCRService) enforceMode(req input.RegisterClientRequest) error {
	s.mu.RLock()
	mode := s.dcrCfg.Mode
	s.mu.RUnlock()
	switch mode {
	case "open":
		return nil

	case "approved_redirects":
		for _, uri := range req.RedirectURIs {
			if !s.matchesApprovedPattern(uri) {
				return fmt.Errorf("%w: redirect_uri %q not in approved list", domain.ErrInvalidRedirectURI, uri)
			}
		}
		return nil

	case "admin_only":
		return domain.ErrRegistrationDisabled

	default:
		return fmt.Errorf("unknown dcr mode: %s", mode)
	}
}

// matchesApprovedPattern checks if a redirect URI matches any of the approved URIs.
// Exact string match only — no wildcards, no prefix matching, no normalization.
// This is a security invariant per RFC 9700 / OAuth Security BCP.
func (s *DCRService) matchesApprovedPattern(uri string) bool {
	for _, approved := range s.dcrCfg.ApprovedRedirects {
		if uri == approved {
			return true
		}
	}
	return false
}
