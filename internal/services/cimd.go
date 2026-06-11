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

	"github.com/authplane/authserver/internal/domain"
	"github.com/authplane/authserver/internal/domain/client"
	"github.com/authplane/authserver/internal/observability"
	"github.com/authplane/authserver/internal/ports/input"
	"github.com/authplane/authserver/internal/ports/output"
)

// CIMDService handles Client ID Metadata Document verification.
// CIMD is pull-based: the AS fetches the client's metadata URL to auto-register.
type CIMDService struct {
	clients       output.ClientStore
	cimd          output.CIMDFetcher
	dcrMode       DCRMode
	enabledGrants []string // grant types the AS is configured to honor; empty = no enforcement
	logger        *slog.Logger
	tracer        trace.Tracer
	metrics       *observability.Metrics
}

var _ input.CIMDPort = (*CIMDService)(nil)

// CIMDServiceOpt configures optional CIMDService dependencies.
type CIMDServiceOpt func(*CIMDService)

// WithCIMDEnabledGrants sets the grant types the running AS is
// configured to honor. CIMDService rejects fetched documents whose
// grant_types aren't in this set — same fail-loud guarantee
// AdminService and DCRService now have, applied at the third
// client-registration path.
func WithCIMDEnabledGrants(grants []string) CIMDServiceOpt {
	return func(s *CIMDService) { s.enabledGrants = grants }
}

// NewCIMDService creates a new CIMD service.
// dcrMode is used to enforce DCR policy on CIMD auto-registration — CIMD
// must not bypass admin_only or approved_redirects restrictions.
func NewCIMDService(
	clients output.ClientStore,
	cimd output.CIMDFetcher,
	dcrMode DCRMode,
	obs *observability.Provider,
	opts ...CIMDServiceOpt,
) *CIMDService {
	s := &CIMDService{
		clients: clients,
		cimd:    cimd,
		dcrMode: dcrMode,
		logger:  obs.Logger,
		tracer:  obs.Tracer,
		metrics: obs.Metrics,
	}
	for _, opt := range opts {
		opt(s)
	}
	return s
}

// VerifyCIMD fetches and validates a CIMD document, then creates or updates the client.
func (s *CIMDService) VerifyCIMD(ctx context.Context, clientID string) (*client.Client, error) {
	ctx, span := s.tracer.Start(ctx, "CIMDService.VerifyCIMD")
	defer span.End()

	span.SetAttributes(
		attribute.String("registration_source", "cimd"),
		attribute.String("cimd_url", clientID),
	)

	// Enforce DCR policy before CIMD auto-registration.
	// CIMD must not bypass admin_only or approved_redirects restrictions.
	if s.dcrMode.Mode == "admin_only" {
		span.SetStatus(codes.Error, "cimd blocked by dcr admin_only")
		s.logger.WarnContext(ctx, "cimd auto-registration blocked by DCR admin_only mode", "client_id", clientID)
		return nil, domain.ErrRegistrationDisabled
	}

	start := time.Now()
	doc, err := s.cimd.Fetch(ctx, clientID)
	s.metrics.CIMDFetchDuration.Record(ctx, time.Since(start).Seconds())
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}

	// reject CIMD-fetched docs that ask for a grant the AS isn't
	// configured to honor. Without this, CIMD remained the third path
	// (alongside admin REST and DCR) that could persist status=active
	// clients whose grants /oauth/token can't serve.
	if grantErr := client.ValidateGrantTypesEnabled(doc.GrantTypes, s.enabledGrants); grantErr != nil {
		span.RecordError(grantErr)
		span.SetStatus(codes.Error, grantErr.Error())
		s.logger.WarnContext(ctx, "cimd auto-registration blocked by disabled grant",
			"client_id", clientID, "grant_types", doc.GrantTypes)
		return nil, fmt.Errorf("%w: %v", domain.ErrInvalidClient, grantErr)
	}

	// Enforce approved_redirects: every redirect URI in the CIMD document
	// must appear in the approved list (exact match, no wildcards).
	if s.dcrMode.Mode == "approved_redirects" {
		for _, uri := range doc.RedirectURIs {
			if s.matchesApprovedRedirect(uri) {
				continue
			}
			uriErr := fmt.Errorf("%w: cimd redirect_uri %q not in approved list", domain.ErrInvalidRedirectURI, uri)
			span.RecordError(uriErr)
			span.SetStatus(codes.Error, uriErr.Error())
			s.logger.WarnContext(ctx, "cimd auto-registration blocked by DCR approved_redirects",
				"client_id", clientID, "rejected_uri", uri)
			return nil, uriErr
		}
	}

	// Check if client already exists for this CIMD URL.
	existing, err := s.clients.GetByCIMDURL(ctx, clientID)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return nil, fmt.Errorf("lookup cimd client: %w", err)
	}

	now := time.Now().UTC()

	if existing != nil {
		// Update existing client from CIMD document.
		existing.Name = doc.ClientName
		existing.RedirectURIs = doc.RedirectURIs
		existing.GrantTypes = doc.GrantTypes
		existing.ResponseTypes = doc.ResponseTypes
		existing.TokenEndpointAuthMethod = doc.TokenEndpointAuthMethod
		existing.UpdatedAt = now

		if err := s.clients.Update(ctx, existing); err != nil {
			span.RecordError(err)
			span.SetStatus(codes.Error, err.Error())
			return nil, fmt.Errorf("update cimd client: %w", err)
		}
		s.logger.InfoContext(ctx, "updated cimd client", "client_id", existing.ID, "cimd_url", clientID)
		return existing, nil
	}

	// Create new client from CIMD document.
	c := &client.Client{
		ID:                      clientID, // For CIMD, client_id IS the URL.
		Name:                    doc.ClientName,
		RedirectURIs:            doc.RedirectURIs,
		GrantTypes:              doc.GrantTypes,
		ResponseTypes:           doc.ResponseTypes,
		TokenEndpointAuthMethod: doc.TokenEndpointAuthMethod,
		Status:                  client.StatusActive,
		RegistrationSource:      client.SourceCIMD,
		CIMDURL:                 clientID,
		IssuedAt:                now,
		UpdatedAt:               now,
	}

	if err := s.clients.Create(ctx, c); err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return nil, fmt.Errorf("create cimd client: %w", err)
	}

	s.logger.InfoContext(ctx, "created cimd client", "client_id", c.ID, "cimd_url", clientID)

	s.metrics.ClientsRegistered.Add(ctx, 1, otelmetric.WithAttributes(
		attribute.String("source", "cimd"),
	))

	return c, nil
}

// matchesApprovedRedirect checks if a redirect URI matches any of the approved URIs.
// Exact string match only — no wildcards, no prefix matching, no normalization.
// Mirrors DCRService.matchesApprovedPattern.
func (s *CIMDService) matchesApprovedRedirect(uri string) bool {
	return slices.Contains(s.dcrMode.ApprovedRedirects, uri)
}
