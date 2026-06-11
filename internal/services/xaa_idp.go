package services

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	otelmetric "go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/trace"

	"github.com/authplane/authserver/internal/crypto"
	"github.com/authplane/authserver/internal/domain/idp"
	"github.com/authplane/authserver/internal/observability"
	"github.com/authplane/authserver/internal/ports/input"
	"github.com/authplane/authserver/internal/ports/output"
)

var _ input.XAAIDPPort = (*XAAIDPService)(nil)

// JWKSDiscoveryFunc discovers a jwks_uri from an OIDC issuer URL.
type JWKSDiscoveryFunc func(ctx context.Context, issuerURL string) (string, error)

// XAAIDPService manages trusted IdP registration and JWKS discovery.
type XAAIDPService struct {
	idpStore  output.IDPStore
	jwksCache output.IDPJWKSCache
	discover  JWKSDiscoveryFunc
	issuer    string // our AS issuer URL (default audience)
	logger    *slog.Logger
	tracer    trace.Tracer
	metrics   *observability.Metrics
	audit     AuditRecorder
}

// NewXAAIDPService creates a new XAA IdP administration service.
func NewXAAIDPService(
	idpStore output.IDPStore,
	jwksCache output.IDPJWKSCache,
	discover JWKSDiscoveryFunc,
	issuer string,
	obs *observability.Provider,
	audit AuditRecorder,
) *XAAIDPService {
	return &XAAIDPService{
		idpStore:  idpStore,
		jwksCache: jwksCache,
		discover:  discover,
		issuer:    issuer,
		logger:    obs.Logger.With("component", "xaa_idp"),
		tracer:    obs.Tracer,
		metrics:   obs.Metrics,
		audit:     audit,
	}
}

// RegisterIDP implements input.XAAIDPPort.
func (s *XAAIDPService) RegisterIDP(ctx context.Context, req input.RegisterIDPRequest) (*idp.TrustedIDP, error) {
	ctx, span := s.tracer.Start(ctx, "XAAIDPService.RegisterIdP")
	defer span.End()

	audience := req.Audience
	if audience == "" {
		audience = s.issuer
	}

	jwksURI := req.JWKSUri
	if jwksURI == "" {
		// Discover from OIDC metadata.
		discovered, err := s.discover(ctx, req.Issuer)
		if err != nil {
			span.RecordError(err)
			span.SetStatus(codes.Error, err.Error())
			return nil, fmt.Errorf("OIDC discovery for %q failed: %w", req.Issuer, err)
		}
		jwksURI = discovered
		s.logger.InfoContext(ctx, "discovered jwks_uri from OIDC metadata", "issuer", req.Issuer, "jwks_uri", jwksURI)
	}

	now := time.Now().UTC()
	entity := idp.TrustedIDP{
		ID:        crypto.GenerateRandomString(16),
		Name:      req.Name,
		Issuer:    req.Issuer,
		JWKSUri:   jwksURI,
		Audience:  audience,
		Enabled:   true,
		CreatedAt: now,
		UpdatedAt: now,
	}

	if err := entity.Validate(); err != nil {
		return nil, fmt.Errorf("validation: %w", err)
	}

	if err := s.idpStore.Save(ctx, entity); err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}

	s.logger.InfoContext(ctx, "trusted IdP registered", "idp_id", entity.ID, "issuer", entity.Issuer)
	s.metrics.XAAIDPOperationsTotal.Add(ctx, 1, otelmetric.WithAttributes(
		attribute.String("operation", "register"),
	))
	return &entity, nil
}

// GetIDP implements input.XAAIDPPort.
func (s *XAAIDPService) GetIDP(ctx context.Context, id string) (*idp.TrustedIDP, error) {
	ctx, span := s.tracer.Start(ctx, "XAAIDPService.GetIdP")
	defer span.End()

	entity, err := s.idpStore.GetByID(ctx, id)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}
	return entity, nil
}

// ListIDPs implements input.XAAIDPPort.
func (s *XAAIDPService) ListIDPs(ctx context.Context) ([]idp.TrustedIDP, error) {
	ctx, span := s.tracer.Start(ctx, "XAAIDPService.ListIdPs")
	defer span.End()

	idps, err := s.idpStore.List(ctx)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}
	return idps, nil
}

// UpdateIDP implements input.XAAIDPPort.
func (s *XAAIDPService) UpdateIDP(ctx context.Context, id string, req input.UpdateIDPRequest) (*idp.TrustedIDP, error) {
	ctx, span := s.tracer.Start(ctx, "XAAIDPService.UpdateIdP")
	defer span.End()

	existing, err := s.idpStore.GetByID(ctx, id)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}

	if req.Name != nil {
		existing.Name = *req.Name
	}
	if req.Enabled != nil {
		existing.Enabled = *req.Enabled
	}
	existing.UpdatedAt = time.Now().UTC()

	if err := s.idpStore.Save(ctx, *existing); err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}

	s.logger.InfoContext(ctx, "trusted IdP updated", "idp_id", id)
	return existing, nil
}

// DeleteIDP implements input.XAAIDPPort.
func (s *XAAIDPService) DeleteIDP(ctx context.Context, id string) error {
	ctx, span := s.tracer.Start(ctx, "XAAIDPService.DeleteIdP")
	defer span.End()

	// Get the IdP first so we can invalidate its cache.
	existing, err := s.idpStore.GetByID(ctx, id)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return err
	}

	if err := s.idpStore.Delete(ctx, id); err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return err
	}

	// Invalidate JWKS cache for this issuer.
	_ = s.jwksCache.InvalidateCache(ctx, existing.Issuer)

	s.logger.InfoContext(ctx, "trusted IdP deleted", "idp_id", id, "issuer", existing.Issuer)
	s.metrics.XAAIDPOperationsTotal.Add(ctx, 1, otelmetric.WithAttributes(
		attribute.String("operation", "delete"),
	))
	return nil
}

// RefreshKeys implements input.XAAIDPPort.
func (s *XAAIDPService) RefreshKeys(ctx context.Context, id string) error {
	ctx, span := s.tracer.Start(ctx, "XAAIDPService.RefreshKeys")
	defer span.End()

	existing, err := s.idpStore.GetByID(ctx, id)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return err
	}

	if err := s.jwksCache.InvalidateCache(ctx, existing.Issuer); err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return fmt.Errorf("invalidate cache: %w", err)
	}

	// Force a re-fetch.
	if _, err := s.jwksCache.GetKeys(ctx, existing.Issuer); err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return fmt.Errorf("refresh keys: %w", err)
	}

	s.logger.InfoContext(ctx, "IdP JWKS refreshed", "idp_id", id, "issuer", existing.Issuer)
	return nil
}
