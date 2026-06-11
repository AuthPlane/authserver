package services

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"

	"github.com/authplane/authserver/internal/domain"
	"github.com/authplane/authserver/internal/domain/resource"
	"github.com/authplane/authserver/internal/observability"
	"github.com/authplane/authserver/internal/ports/output"
)

// ResourceRegistry is the unified read-model for resources (the architecture doc
// §5.1). It wraps ResourceStore + BrokerProviderStore and exposes the
// operations services and handlers actually need: Resolve, GetWithProvider,
// ListScopes. List is preserved as a backward-compat seam that satisfies
// the existing ResourceLister interface so 's wiring swap from
// CachedResourceProvider is mechanical; consumers move to the typed
// methods after that.
type ResourceRegistry struct {
	resources output.ResourceStore
	providers output.BrokerProviderStore
	logger    *slog.Logger
	tracer    trace.Tracer
}

// Compile-time assertion that ResourceRegistry satisfies the legacy
// ResourceLister interface ( substitution gate).
var _ ResourceLister = (*ResourceRegistry)(nil)

// NewResourceRegistry constructs a ResourceRegistry over the unified
// resources + broker_providers tables. No in-memory cache: every read is a
// fresh DB hit (the data model — Resolve is a single indexed lookup).
func NewResourceRegistry(
	rs output.ResourceStore,
	bps output.BrokerProviderStore,
	obs *observability.Provider,
) *ResourceRegistry {
	return &ResourceRegistry{
		resources: rs,
		providers: bps,
		logger:    obs.Logger.With("component", "resource_registry"),
		tracer:    obs.Tracer,
	}
}

// Resolve implements the resource= parameter resolution rule from
// the data model / §6 Q1: 0 rows → ErrResourceNotFound; 1 row → return
// it; ≥2 rows → ErrAmbiguousResource (caller hints user to use slug).
func (r *ResourceRegistry) Resolve(ctx context.Context, slugOrURI string) (*resource.Resource, error) {
	ctx, span := r.tracer.Start(ctx, "ResourceRegistry.Resolve")
	defer span.End()

	span.SetAttributes(attribute.String("slug_or_uri", slugOrURI))

	rows, err := r.resources.Resolve(ctx, slugOrURI)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		r.logger.ErrorContext(ctx, "resource resolve failed", "slug_or_uri", slugOrURI, "error", err)
		return nil, err
	}

	switch len(rows) {
	case 0:
		span.RecordError(domain.ErrResourceNotFound)
		span.SetStatus(codes.Error, domain.ErrResourceNotFound.Error())
		return nil, domain.ErrResourceNotFound
	case 1:
		return rows[0], nil
	default:
		span.RecordError(domain.ErrAmbiguousResource)
		span.SetStatus(codes.Error, domain.ErrAmbiguousResource.Error())
		r.logger.WarnContext(ctx, "ambiguous resource lookup",
			"slug_or_uri", slugOrURI,
			"matches", len(rows),
		)
		return nil, domain.ErrAmbiguousResource
	}
}

// FindByRuntimeClientID returns the Resource whose policy.runtime.client_ids
// contains clientID — used by the broker dispatch agent-attestation gate
// (token_exchange.go) to identify which Resource an authenticated client
// represents on the wire. Returns domain.ErrResourceNotFound when nothing
// is configured (fail-closed) and domain.ErrAmbiguousResource when two or
// more Resources list the same clientID (operator misconfiguration)..
func (r *ResourceRegistry) FindByRuntimeClientID(ctx context.Context, clientID string) (*resource.Resource, error) {
	ctx, span := r.tracer.Start(ctx, "ResourceRegistry.FindByRuntimeClientID")
	defer span.End()

	span.SetAttributes(attribute.String("client_id", clientID))

	res, err := r.resources.FindByRuntimeClientID(ctx, clientID)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		if errors.Is(err, domain.ErrAmbiguousResource) {
			r.logger.WarnContext(ctx, "ambiguous runtime client_id mapping",
				"client_id", clientID,
			)
		}
		return nil, err
	}
	return res, nil
}

// GetWithProvider returns the Resource and, when the resource is Broker-backed,
// also its BrokerProvider. Mint resources return (res, nil, nil). Used by
// BrokerIssuer.
func (r *ResourceRegistry) GetWithProvider(
	ctx context.Context,
	resourceID string,
) (*resource.Resource, *resource.BrokerProvider, error) {
	ctx, span := r.tracer.Start(ctx, "ResourceRegistry.GetWithProvider")
	defer span.End()

	span.SetAttributes(attribute.String("resource_id", resourceID))

	res, err := r.resources.GetByID(ctx, resourceID)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return nil, nil, err
	}

	if !res.IsBroker() {
		return res, nil, nil
	}

	prov, err := r.providers.GetByID(ctx, res.BrokerProviderID)
	if err != nil {
		// Broker resource references a provider row that does not exist
		// (or the lookup itself failed). Wrap so callers can distinguish
		// from the resource lookup error.
		wrapped := fmt.Errorf("broker provider %q for resource %q: %w", res.BrokerProviderID, res.ID, err)
		span.RecordError(wrapped)
		span.SetStatus(codes.Error, wrapped.Error())
		r.logger.ErrorContext(ctx, "broker provider lookup failed",
			"resource_id", res.ID,
			"broker_provider_id", res.BrokerProviderID,
			"error", err,
		)
		return nil, nil, wrapped
	}

	return res, prov, nil
}

// ListScopes returns the scope catalog of a resource. Used by the consent UI
// to render per-scope descriptions.
func (r *ResourceRegistry) ListScopes(ctx context.Context, resourceID string) ([]resource.Scope, error) {
	ctx, span := r.tracer.Start(ctx, "ResourceRegistry.ListScopes")
	defer span.End()

	span.SetAttributes(attribute.String("resource_id", resourceID))

	res, err := r.resources.GetByID(ctx, resourceID)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}

	return res.Scopes, nil
}

// List satisfies the legacy ResourceLister interface.  rotates
// consumers to the typed methods on ResourceRegistry; until then this is the
// substitution seam for CachedResourceProvider in cmd/authserver/serve.go.
//
// The interface signature (List() []ResourceInfo, no context, no error)
// forces a context.Background() DB read here. Errors are logged and
// surfaced as a nil slice — same semantics as CachedResourceProvider on a
// failed initial reload.
func (r *ResourceRegistry) List() []ResourceInfo {
	ctx := context.Background()
	ctx, span := r.tracer.Start(ctx, "ResourceRegistry.List")
	defer span.End()

	rows, err := r.resources.List(ctx, output.ResourceFilter{})
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		r.logger.ErrorContext(ctx, "resource list failed", "error", err)
		return nil
	}

	infos := make([]ResourceInfo, len(rows))
	for i, row := range rows {
		infos[i] = resourceToInfo(row)
	}
	return infos
}

// resourceToInfo converts the unified Resource shape into the legacy flat
// ResourceInfo shape consumed by -era services (token, authorize,
// consent, jwt_bearer, client_credentials, token_exchange). ClientID is
// empty: the v3 may_act seam moved to Policy.Exchange.AllowedClientIDs and
// is rewired in .
func resourceToInfo(r *resource.Resource) ResourceInfo {
	names := make([]string, len(r.Scopes))
	descs := make(map[string]string, len(r.Scopes))
	for i, sc := range r.Scopes {
		names[i] = sc.Name
		if sc.Description != "" {
			descs[sc.Name] = sc.Description
		}
	}
	return ResourceInfo{
		URI:               r.URI,
		Scopes:            names,
		ScopeDescriptions: descs,
	}
}
