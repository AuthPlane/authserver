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
	clients      output.ClientStore
	cimd         output.CIMDFetcher
	modeProvider output.DCRModeProvider // required; resolves the DCR policy from ctx
	// grantsProvider resolves the grant types the AS honors, per request.
	// nil ⇒ no enforcement (tests). Optional, injected via WithCIMDEnabledGrants.
	grantsProvider output.EnabledGrantsProvider
	// oauthConfig supplies the scope ceiling to assign, since a CIMD document
	// carries no scope. nil ⇒ no ceiling assigned (tests). Optional, injected
	// via WithCIMDOAuthConfig.
	oauthConfig output.OAuthConfigProvider
	// cimdConfig is the per-request config seam and the single source of truth
	// for the fetch knobs (RequireHTTPS/CacheTTL/FetchTimeout) and the Enabled
	// gate, both consumed at the top of VerifyCIMD. Required (a constructor
	// parameter). The static default returns boot values (OSS unchanged); a
	// substitute provider may vary it per request.
	cimdConfig output.CIMDConfigProvider
	logger     *slog.Logger
	tracer     trace.Tracer
	metrics    *observability.Metrics
}

var _ input.CIMDPort = (*CIMDService)(nil)

// CIMDServiceOpt configures optional CIMDService dependencies.
type CIMDServiceOpt func(*CIMDService)

// WithCIMDEnabledGrants injects the per-request enabled-grants provider.
// CIMDService rejects fetched documents whose grant_types aren't in the set the
// provider returns — same fail-loud guarantee AdminService and DCRService have.
func WithCIMDEnabledGrants(p output.EnabledGrantsProvider) CIMDServiceOpt {
	return func(s *CIMDService) { s.grantsProvider = p }
}

// WithCIMDOAuthConfig injects the per-request OAuth config provider.
// CIMDService reads DefaultClientScope from it and stamps that ceiling on the
// clients it auto-registers: a CIMD document carries no scope, and an unset
// ceiling denies every scope on the machine grants, and will do so on
// authorize too from v0.3.0.
func WithCIMDOAuthConfig(p output.OAuthConfigProvider) CIMDServiceOpt {
	return func(s *CIMDService) { s.oauthConfig = p }
}

// NewCIMDService creates a new CIMD service.
// modeProvider enforces DCR policy on CIMD auto-registration (CIMD must not
// bypass admin_only or approved_redirects). cimdConfig is the required
// per-request config seam (single source of truth for the fetch knobs and the
// Enabled gate) — a positional parameter like modeProvider, not an option.
func NewCIMDService(
	clients output.ClientStore,
	cimd output.CIMDFetcher,
	modeProvider output.DCRModeProvider,
	cimdConfig output.CIMDConfigProvider,
	obs *observability.Provider,
	opts ...CIMDServiceOpt,
) *CIMDService {
	s := &CIMDService{
		clients:      clients,
		cimd:         cimd,
		modeProvider: modeProvider,
		cimdConfig:   cimdConfig,
		logger:       obs.Logger,
		tracer:       obs.Tracer,
		metrics:      obs.Metrics,
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

	// Resolve the per-request CIMD config — the single source of truth for the
	// Enabled gate and the fetch knobs. A substitute provider may vary it per
	// request; the static default returns boot values. Fail closed on provider
	// error; deny when the feature is disabled.
	cfg, cfgErr := s.cimdConfig.Config(ctx)
	if cfgErr != nil {
		s.logger.ErrorContext(ctx, "cimd blocked: config provider failed during VerifyCIMD", "error", cfgErr)
		span.RecordError(cfgErr)
		return nil, fmt.Errorf("resolve cimd config: %w", cfgErr)
	}
	if !cfg.Enabled {
		span.SetStatus(codes.Error, "cimd blocked: disabled by config provider")
		s.logger.WarnContext(ctx, "cimd auto-registration blocked: disabled by config provider", "client_id", clientID)
		return nil, domain.ErrRegistrationDisabled
	}

	// Enforce DCR policy before CIMD auto-registration.
	// CIMD must not bypass admin_only or approved_redirects restrictions.
	policy, err := s.modeProvider.Get(ctx)
	if err != nil {
		s.logger.ErrorContext(ctx, "cimd blocked: dcr mode provider failed during VerifyCIMD", "error", err)
		span.RecordError(err)
		return nil, fmt.Errorf("get dcr mode: %w", err)
	}

	// Fail closed on an unrecognized mode: mirror DCRService.enforceMode's
	// allowlist posture (default-deny) instead of falling through to
	// auto-registration. Keeps both registration paths in agreement.
	switch policy.Mode {
	case "open", "approved_redirects", "admin_only":
		// recognized mode
	default:
		span.SetStatus(codes.Error, "cimd blocked by unknown dcr mode")
		s.logger.ErrorContext(ctx, "cimd auto-registration blocked by unknown DCR mode",
			"client_id", clientID, "mode", policy.Mode)
		return nil, fmt.Errorf("unknown dcr mode: %s", policy.Mode)
	}

	if policy.Mode == "admin_only" {
		span.SetStatus(codes.Error, "cimd blocked by dcr admin_only")
		s.logger.WarnContext(ctx, "cimd auto-registration blocked by DCR admin_only mode", "client_id", clientID)
		return nil, domain.ErrRegistrationDisabled
	}

	// The fetch duration is recorded by the fetcher, around the outbound round
	// trip itself, so the histogram measures what a slow target costs. Timing
	// the call from here would fold in cache hits, suppressed re-fetches and
	// waits on another caller's in-flight fetch as near-zero samples — which
	// would make the metric look best exactly when fetches are being driven.
	doc, err := s.cimd.Fetch(ctx, clientID, output.CIMDFetchConfig{
		RequireHTTPS:          cfg.RequireHTTPS,
		AllowPrivateAddresses: cfg.AllowPrivateAddresses,
		CacheTTL:              cfg.CacheTTL,
		FetchTimeout:          cfg.FetchTimeout,
	})
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}

	// Resolve the enabled-grant set per request (shared helper: nil provider ⇒
	// no enforcement, provider error ⇒ fail closed), then reject docs asking for
	// a grant the AS isn't configured to honor.
	enabledGrants, gErr := resolveEnabledGrants(ctx, s.grantsProvider)
	if gErr != nil {
		span.RecordError(gErr)
		span.SetStatus(codes.Error, gErr.Error())
		return nil, gErr
	}
	if grantErr := client.ValidateGrantTypesEnabled(doc.GrantTypes, enabledGrants); grantErr != nil {
		span.RecordError(grantErr)
		span.SetStatus(codes.Error, grantErr.Error())
		s.logger.WarnContext(ctx, "cimd auto-registration blocked by disabled grant",
			"client_id", clientID, "grant_types", doc.GrantTypes)
		return nil, fmt.Errorf("%w: %v", domain.ErrInvalidClient, grantErr)
	}

	// Enforce approved_redirects: every redirect URI in the CIMD document
	// must appear in the approved list (exact match, no wildcards).
	if policy.Mode == "approved_redirects" {
		for _, uri := range doc.RedirectURIs {
			if slices.Contains(policy.ApprovedRedirects, uri) {
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
		// An empty ceiling is deliberately not filled in here: this branch is
		// only reachable when two registrations race — an existing CIMD client
		// is served straight from the store without re-verifying its document
		// (see AuthorizeService.lookupClient), so there is no periodic refresh
		// to hang a backfill off — and filling it would re-arm a client whose
		// ceiling an operator emptied on purpose.
		//
		// A ceiling that exists is cleared when the document's grants no longer
		// qualify. The client hosts that document, so it chooses when it
		// changes: without this, publishing authorization_code to earn a
		// ceiling and then adding client_credentials would leave a
		// self-registered machine client holding scopes with no consent behind
		// them — exactly what the create path refuses. Unreachable today for
		// the same reason as above, but the guard belongs with the invariant,
		// not with the path that currently happens to be the only one.
		//
		// Neither direction is free, which is worth spelling out because this
		// is unreachable today and whoever makes it reachable will inherit
		// these lines rather than re-derive them.
		//
		// On the authorization_code path an empty ceiling is unenforced until
		// v0.3.0, so clearing widens: the client goes from bounded by its
		// ceiling to bounded by the resource catalog.
		//
		// On the machine grants an empty ceiling is deny-all, so clearing
		// revokes — including a ceiling an operator set by hand through
		// PATCH /admin/clients/{client_id}, which this cannot distinguish from
		// one stamped from the default. Token requests that worked start
		// failing with invalid_scope.
		//
		// It is kept because the alternative — a self-registered machine client
		// holding scopes its own document says it should never have had — is
		// worse than either. A periodic CIMD refresh must not inherit this
		// as-is: it needs to tell a stamped ceiling from an operator-set one
		// first.
		if !isDelegatedOnly(doc.GrantTypes) {
			existing.Scope = ""
		}

		if err := s.clients.Update(ctx, existing); err != nil {
			span.RecordError(err)
			span.SetStatus(codes.Error, err.Error())
			return nil, fmt.Errorf("update cimd client: %w", err)
		}
		s.logger.InfoContext(ctx, "updated cimd client", "client_id", existing.ID, "cimd_url", clientID)
		return existing, nil
	}

	// The ceiling to assign. A CIMD document carries no scope, so the server
	// supplies one (RFC 7591 §2). Resolved here rather than above the update
	// branch: that branch never uses it, and a config-provider failure should
	// not fail an update that does not need the value.
	//
	// This is reachable in production: oauth.default_client_scope is a startup
	// warning, not a boot requirement, so an operator can run with it unset and
	// every client registered here then carries no ceiling.
	//
	// Delegated grants only, for the same reason as DCR: a self-registering
	// client must never be handed scopes usable on a grant that has no user
	// and no consent bounding the token.
	var defaultScope string
	if s.oauthConfig != nil && isDelegatedOnly(doc.GrantTypes) {
		oauthCfg, cfgErr := s.oauthConfig.Config(ctx)
		if cfgErr != nil {
			span.RecordError(cfgErr)
			span.SetStatus(codes.Error, cfgErr.Error())
			return nil, fmt.Errorf("resolve oauth config: %w", cfgErr)
		}
		defaultScope = oauthCfg.DefaultClientScope
	}

	// Create new client from CIMD document.
	c := &client.Client{
		ID:                      clientID, // For CIMD, client_id IS the URL.
		Name:                    doc.ClientName,
		RedirectURIs:            doc.RedirectURIs,
		GrantTypes:              doc.GrantTypes,
		ResponseTypes:           doc.ResponseTypes,
		TokenEndpointAuthMethod: doc.TokenEndpointAuthMethod,
		Scope:                   defaultScope,
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
