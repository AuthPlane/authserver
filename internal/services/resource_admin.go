package services

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"strings"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"

	"github.com/authplane/authserver/internal/crypto"
	"github.com/authplane/authserver/internal/domain"
	"github.com/authplane/authserver/internal/domain/audit"
	"github.com/authplane/authserver/internal/domain/resource"
	"github.com/authplane/authserver/internal/observability"
	"github.com/authplane/authserver/internal/ports/input"
	"github.com/authplane/authserver/internal/ports/output"
)

// ResourceAdminService implements input.ResourceAdminPort over the unified
// resources + broker_providers tables. It validates that Broker
// resources reference an existing provider, that policy.exchange.allowed_client_ids
// reference known clients, and audit-records every successful mutation.
//
// Cross-table coupling: ResourceAdminService takes ClientStore as a constructor
// dependency to validate policy.exchange.allowed_client_ids on Create + Patch.
// The legacy ResourceServerService does not —  retires that service so
// the divergence is intentional and bounded.
//
// Fronting: when a FrontingValidator is wired, Patch consults it
// before persisting (block scope-removal/rename + kind-change when links
// reference the resource), and DeleteWithCascade consults it for the
// dependents list and the cascade path. Nil-tolerant — tests + minimal
// deployments that haven't wired the FrontingService skip the hooks
// (equivalent to "no links exist anywhere").
type ResourceAdminService struct {
	resources output.ResourceStore
	providers output.BrokerProviderStore
	clients   output.ClientStore
	fronting  FrontingValidator
	tx        output.TransactionManager
	audit     AuditRecorder
	logger    *slog.Logger
	tracer    trace.Tracer
}

var _ input.ResourceAdminPort = (*ResourceAdminService)(nil)

// FrontingValidator is the subset of FrontingService consumed by
// ResourceAdminService for edit-time validation + cascade. Defined here so
// ResourceAdminService stays independent of the concrete FrontingService
// (and its sibling deps) — and so tests can stub the hooks cheaply.
type FrontingValidator interface {
	// ValidateResourceUpdate runs the §Edit-time hooks against the
	// pre-/post-Patch snapshots; returns a domain InvalidRequestError when
	// the proposed update would orphan a referenced scope or change kind
	// while links exist.
	ValidateResourceUpdate(ctx context.Context, prev, next *resource.Resource) error

	// ListForResource returns every fronting link referencing slug as
	// either source or target. Used by the pre-delete cascade preflight
	// and by Patch to detect a slug-rename with dependent links.
	ListForResource(ctx context.Context, slug string) ([]*resource.FrontingLink, error)

	// CascadeDeleteForResource removes every link referencing slug and
	// returns the affected list (for audit / UI). Called only after the
	// admin has confirmed with ?cascade=true.
	CascadeDeleteForResource(ctx context.Context, slug, actorID string) ([]*resource.FrontingLink, error)
}

// ResourceAdminServiceOpt configures optional ResourceAdminService deps.
type ResourceAdminServiceOpt func(*ResourceAdminService)

// WithFrontingValidator wires the fronting-link edit-time + cascade hooks.
// When omitted the service degrades to its pre- behavior (no fronting
// awareness) — appropriate for tests that don't care about fronting.
func WithFrontingValidator(v FrontingValidator) ResourceAdminServiceOpt {
	return func(s *ResourceAdminService) { s.fronting = v }
}

// WithResourceAdminTransactionManager wires a transaction manager so the
// cascade path (resource delete + link deletes) commits atomically. Optional
// — without it, cascade falls back to best-effort sequential deletes.
func WithResourceAdminTransactionManager(tm output.TransactionManager) ResourceAdminServiceOpt {
	return func(s *ResourceAdminService) { s.tx = tm }
}

// NewResourceAdminService constructs a ResourceAdminService.
func NewResourceAdminService(
	resources output.ResourceStore,
	providers output.BrokerProviderStore,
	clients output.ClientStore,
	obs *observability.Provider,
	auditSvc AuditRecorder,
	opts ...ResourceAdminServiceOpt,
) *ResourceAdminService {
	svc := &ResourceAdminService{
		resources: resources,
		providers: providers,
		clients:   clients,
		audit:     auditSvc,
		logger:    obs.Logger,
		tracer:    obs.Tracer,
	}
	for _, opt := range opts {
		opt(svc)
	}
	return svc
}

// List returns Resources matching the filter.
func (s *ResourceAdminService) List(ctx context.Context, filter input.ResourceFilter) ([]*resource.Resource, error) {
	ctx, span := s.tracer.Start(ctx, "ResourceAdminService.List")
	defer span.End()

	rows, err := s.resources.List(ctx, output.ResourceFilter{
		BackendKind:      filter.BackendKind,
		BrokerProviderID: filter.BrokerProviderID,
		Limit:            filter.Limit,
		Offset:           filter.Offset,
	})
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return nil, fmt.Errorf("list resources: %w", err)
	}
	return rows, nil
}

// GetByID returns the Resource with the given id.
func (s *ResourceAdminService) GetByID(ctx context.Context, id string) (*resource.Resource, error) {
	ctx, span := s.tracer.Start(ctx, "ResourceAdminService.GetByID")
	defer span.End()
	span.SetAttributes(attribute.String("id", id))

	r, err := s.resources.GetByID(ctx, id)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}
	return r, nil
}

// GetBySlug returns the Resource with the given slug.
func (s *ResourceAdminService) GetBySlug(ctx context.Context, slug string) (*resource.Resource, error) {
	ctx, span := s.tracer.Start(ctx, "ResourceAdminService.GetBySlug")
	defer span.End()
	span.SetAttributes(attribute.String("slug", slug))

	r, err := s.resources.GetBySlug(ctx, slug)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}
	return r, nil
}

// Create inserts a new Resource after validation.
func (s *ResourceAdminService) Create(ctx context.Context, r *resource.Resource) error {
	ctx, span := s.tracer.Start(ctx, "ResourceAdminService.Create")
	defer span.End()
	span.SetAttributes(attribute.String("slug", r.Slug))

	if r.ID != "" {
		err := domain.NewInvalidRequestError("id must not be supplied on create")
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return err
	}

	canonicalSlug, err := resource.NormalizeSlug(r.Slug)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return err
	}
	r.Slug = canonicalSlug

	if err := r.Validate(); err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return err
	}

	if err := s.validateBrokerProviderRef(ctx, r.BackendKind, r.BrokerProviderID); err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return err
	}

	if err := s.validatePolicyClients(ctx, r.Policy); err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return err
	}

	// Pre-check for slug conflicts so the wire-level error is a clean 409
	// rather than a 500 from the underlying UNIQUE-constraint driver error.
	// Race window: a concurrent Create can still slip through and the loser
	// surfaces as 500. Acceptable for v0.1.0-rc1 admin (rare, retried).
	if err := s.assertSlugAvailable(ctx, r.Slug, ""); err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return err
	}

	// Mint resources have no connect semantics — drop any caller-
	// supplied connect block before persistence so the DB row matches what
	// the wire response shows. Without this, `policy.connect` sent on a
	// Mint resource would be silently persisted and reappear on a future
	// Mint→Broker conversion. Audit finding G7.
	stripMintConnectPolicy(r)

	now := time.Now().UTC()
	r.ID = crypto.GenerateRandomString(16)
	r.CreatedAt = now
	r.UpdatedAt = now

	if err := s.resources.Create(ctx, r); err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return err
	}

	if s.audit != nil {
		s.audit.Record(ctx, audit.NewEvent(
			audit.ActionResourceCreated,
			"admin", "", "",
			fmt.Sprintf("id=%s slug=%s", r.ID, r.Slug),
		))
	}

	s.logger.InfoContext(ctx, "resource created",
		"id", r.ID, "slug", r.Slug, "backend_kind", string(r.BackendKind))
	return nil
}

// Patch applies a partial update per ResourcePatch semantics.
func (s *ResourceAdminService) Patch(ctx context.Context, id string, patch input.ResourcePatch) (*resource.Resource, error) {
	ctx, span := s.tracer.Start(ctx, "ResourceAdminService.Patch")
	defer span.End()
	span.SetAttributes(attribute.String("id", id))

	if id == "" {
		err := domain.NewInvalidRequestError("id is required")
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}

	r, err := s.resources.GetByID(ctx, id)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}

	var touched []string
	if patch.Slug != nil {
		canonical, err := resource.NormalizeSlug(*patch.Slug)
		if err != nil {
			span.RecordError(err)
			span.SetStatus(codes.Error, err.Error())
			return nil, err
		}
		r.Slug = canonical
		touched = append(touched, "slug")
	}
	if patch.URI != nil {
		r.URI = *patch.URI
		touched = append(touched, "uri")
	}
	if patch.BackendKind != nil {
		r.BackendKind = *patch.BackendKind
		touched = append(touched, "backend_kind")
	}
	if patch.BrokerProviderID != nil {
		r.BrokerProviderID = *patch.BrokerProviderID
		touched = append(touched, "broker_provider_id")
	}
	if patch.DisplayName != nil {
		r.DisplayName = *patch.DisplayName
		touched = append(touched, "display_name")
	}
	if patch.Scopes != nil {
		r.Scopes = *patch.Scopes
		touched = append(touched, "scopes")
	}
	if patch.Policy != nil {
		r.Policy = *patch.Policy
		touched = append(touched, "policy")
	}

	// Empty patch: no fields touched → no DB write, no audit row, no
	// UpdatedAt bump. Returning the existing resource lets callers treat
	// PATCH-with-no-fields as a refresh-style read; emitting an audit
	// record with `fields=` (empty) would be log noise that obscures real
	// mutations.
	if len(touched) == 0 {
		return r, nil
	}

	if err := r.Validate(); err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}

	// Re-validate cross-table references whenever the relevant fields are
	// touched (or, for Policy, even if the resource shape didn't change but
	// the allowlist might have).
	if patch.BackendKind != nil || patch.BrokerProviderID != nil {
		if err := s.validateBrokerProviderRef(ctx, r.BackendKind, r.BrokerProviderID); err != nil {
			span.RecordError(err)
			span.SetStatus(codes.Error, err.Error())
			return nil, err
		}
	}
	if patch.Policy != nil {
		if err := s.validatePolicyClients(ctx, r.Policy); err != nil {
			span.RecordError(err)
			span.SetStatus(codes.Error, err.Error())
			return nil, err
		}
	}

	if patch.Slug != nil {
		if err := s.assertSlugAvailable(ctx, r.Slug, r.ID); err != nil {
			span.RecordError(err)
			span.SetStatus(codes.Error, err.Error())
			return nil, err
		}
	}

	// edit-time hooks: block scope removal/rename referenced by any
	// fronting link; forbid kind change when links exist. We need the
	// pre-Patch snapshot for the diff — re-fetch from the store rather than
	// rely on the closure variable r (which has been mutated by the
	// patch above).
	//
	// Slug change is implicitly handled because the FrontingValidator
	// looks up by slug; re-validation runs against the (still-old) slug
	// stored on existing fronting_links rows. A slug-rename when links
	// exist would be the equivalent of "scope rename" — also forbidden —
	// so the safer behavior here is to block slug changes when links
	// reference the resource.
	if s.fronting != nil {
		prev, fetchErr := s.resources.GetByID(ctx, id)
		if fetchErr != nil {
			span.RecordError(fetchErr)
			span.SetStatus(codes.Error, fetchErr.Error())
			return nil, fetchErr
		}
		if patch.Slug != nil && prev.Slug != r.Slug {
			deps, err := s.fronting.ListForResource(ctx, prev.Slug)
			if err != nil {
				span.RecordError(err)
				span.SetStatus(codes.Error, err.Error())
				return nil, err
			}
			if len(deps) > 0 {
				err := domain.NewInvalidRequestError(fmt.Sprintf(
					"cannot rename resource %q to %q: %d fronting link(s) reference the current slug — drop the links first",
					prev.Slug, r.Slug, len(deps)))
				span.RecordError(err)
				span.SetStatus(codes.Error, err.Error())
				return nil, err
			}
		}
		if err := s.fronting.ValidateResourceUpdate(ctx, prev, r); err != nil {
			span.RecordError(err)
			span.SetStatus(codes.Error, err.Error())
			return nil, err
		}
	}

	// Same Mint connect-policy guard as Create (audit G7). Patches that
	// flip backend_kind broker→mint (rare but possible) also drop the
	// orphaned connect block at this point.
	stripMintConnectPolicy(r)

	r.UpdatedAt = time.Now().UTC()

	if err := s.resources.Update(ctx, r); err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}

	if s.audit != nil {
		s.audit.Record(ctx, audit.NewEvent(
			audit.ActionResourcePatched,
			"admin", "", "",
			fmt.Sprintf("id=%s slug=%s fields=%s", r.ID, r.Slug, strings.Join(touched, ",")),
		))
	}

	s.logger.InfoContext(ctx, "resource patched",
		"id", r.ID, "slug", r.Slug, "fields", strings.Join(touched, ","))
	return r, nil
}

// Delete removes the Resource by id. Equivalent to DeleteWithCascade(ctx, id,
// false) but discards the dependents slice — preserved as an interface method
// for the existing /admin/resources/{id} DELETE without cascade=true.
func (s *ResourceAdminService) Delete(ctx context.Context, id string) error {
	_, err := s.DeleteWithCascade(ctx, id, false)
	return err
}

// DeleteWithCascade removes the Resource and (when cascade=true) every
// fronting_links row referencing it. Returns the dependent links — populated
// both on the 409 path (so the caller can include the list in the error
// body) and on the success-with-cascade path (so callers can audit what was
// removed).
//
// Atomicity: when a transaction manager is wired, link cascade + resource
// delete commit in a single tx so a mid-flight failure rolls both back. When
// no tx manager is wired we fall back to sequential operations — acceptable
// for SQLite single-writer + tests; production wires the tx manager.
func (s *ResourceAdminService) DeleteWithCascade(ctx context.Context, id string, cascade bool) ([]*resource.FrontingLink, error) {
	ctx, span := s.tracer.Start(ctx, "ResourceAdminService.DeleteWithCascade")
	defer span.End()
	span.SetAttributes(attribute.String("id", id), attribute.Bool("cascade", cascade))

	if id == "" {
		err := domain.NewInvalidRequestError("id is required")
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}

	// Resolve the slug once — every downstream call (fronting lookup,
	// audit, logger) is keyed on slug. Also surfaces 404 cleanly before
	// we fan out into the cascade preflight.
	r, err := s.resources.GetByID(ctx, id)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}

	var dependents []*resource.FrontingLink
	if s.fronting != nil {
		dependents, err = s.fronting.ListForResource(ctx, r.Slug)
		if err != nil {
			span.RecordError(err)
			span.SetStatus(codes.Error, err.Error())
			return nil, err
		}
	}

	if len(dependents) > 0 && !cascade {
		conflictErr := domain.ErrResourceHasFrontingLinks
		span.RecordError(conflictErr)
		span.SetStatus(codes.Error, conflictErr.Error())
		return dependents, conflictErr
	}

	doDelete := func(ctx context.Context) error {
		if cascade && len(dependents) > 0 && s.fronting != nil {
			if _, err := s.fronting.CascadeDeleteForResource(ctx, r.Slug, "admin"); err != nil {
				return err
			}
		}
		return s.resources.Delete(ctx, id)
	}

	if s.tx != nil {
		if err := s.tx.WithTransaction(ctx, doDelete); err != nil {
			span.RecordError(err)
			span.SetStatus(codes.Error, err.Error())
			return dependents, err
		}
	} else {
		if err := doDelete(ctx); err != nil {
			span.RecordError(err)
			span.SetStatus(codes.Error, err.Error())
			return dependents, err
		}
	}

	if s.audit != nil {
		detail := fmt.Sprintf("id=%s slug=%s", id, r.Slug)
		if cascade && len(dependents) > 0 {
			detail += fmt.Sprintf(" cascaded_links=%d", len(dependents))
		}
		s.audit.Record(ctx, audit.NewEvent(
			audit.ActionResourceDeleted,
			"admin", "", "",
			detail,
		))
	}

	s.logger.InfoContext(ctx, "resource deleted",
		"id", id, "slug", r.Slug, "cascaded_links", len(dependents))
	return dependents, nil
}

// validateBrokerProviderRef ensures Broker resources reference an existing
// provider and Mint resources do not. The Resource.Validate() method already
// enforces field presence/absence; this is the cross-table existence check.
func (s *ResourceAdminService) validateBrokerProviderRef(ctx context.Context, kind resource.BackendKind, providerID string) error {
	if kind != resource.BackendBroker {
		return nil
	}
	if providerID == "" {
		return domain.NewInvalidRequestError("broker resource must reference a broker provider")
	}
	_, err := s.providers.GetByID(ctx, providerID)
	if err != nil {
		if errors.Is(err, domain.ErrResourceNotFound) {
			return domain.NewInvalidRequestError(fmt.Sprintf("broker_provider_id %q does not exist", providerID))
		}
		return fmt.Errorf("lookup broker provider %q: %w", providerID, err)
	}
	return nil
}

// assertSlugAvailable returns a CodeConflict domain error if a different
// Resource row already holds the given slug. excludeID is the id of the row
// being patched (so a no-op slug write succeeds); pass "" on Create.
//
// This is a TOCTOU pre-check: a concurrent Create racing past this lookup
// will surface as a 500 (the underlying SQL UNIQUE-constraint violation
// bubbles up unwrapped per the ResourceStore contract). The clean fix —
// surfacing a typed domain.ErrSlugConflict from the storage adapter on
// UNIQUE violation — is out of scope here. Admin operations are rare
// and retried by hand, so the race-loser ergonomics regression is
// acceptable.
func (s *ResourceAdminService) assertSlugAvailable(ctx context.Context, slug, excludeID string) error {
	existing, err := s.resources.GetBySlug(ctx, slug)
	if err != nil {
		if errors.Is(err, domain.ErrResourceNotFound) {
			return nil
		}
		return fmt.Errorf("lookup resource by slug %q: %w", slug, err)
	}
	if existing.ID == excludeID {
		return nil
	}
	return domain.NewConflictError(fmt.Sprintf("slug %q is already in use", slug))
}

// stripMintConnectPolicy zeroes the Connect policy on Mint resources so
// the persisted row matches what the wire response shows. Mint resources
// have no connect semantics, but the storage adapter marshals
// the full Policy struct verbatim — without this normalization, a
// caller-supplied connect block on a Mint resource would persist
// invisibly and reappear on a future Mint→Broker conversion.
//
// No-op for Broker resources. Called from Create + Patch right before
// the Update/Create call.
func stripMintConnectPolicy(r *resource.Resource) {
	if r.IsMint() {
		r.Policy.Connect = resource.ConnectPolicy{}
	}
}

// AddAllowedClient idempotently adds clientID to the resource's
// policy.exchange.allowed_client_ids. The lookup is by slug.
//
// Concurrency: this is a service-level read-modify-write (no SQL-level row
// lock). Two operators editing the same resource policy concurrently can
// race; the loser's mutation is silently overwritten. Acceptable for
// rc1 — admin operations are rare, and the common Add/Remove case is
// idempotent so re-running the loser converges to the desired state.
// Tightening to a tx-level CAS would require port-level transactional
// primitives (out of scope for /).
func (s *ResourceAdminService) AddAllowedClient(ctx context.Context, slug, clientID string) ([]string, error) {
	ctx, span := s.tracer.Start(ctx, "ResourceAdminService.AddAllowedClient")
	defer span.End()
	span.SetAttributes(attribute.String("slug", slug), attribute.String("client_id", clientID))

	if clientID == "" {
		err := domain.NewInvalidRequestError("client_id is required")
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}

	// Validate the client exists before mutating the policy. Same check the
	// Patch path runs via validatePolicyClients; doing it up front keeps the
	// audit row honest (no "added" event for a clientID that never resolved).
	if _, err := s.clients.GetByID(ctx, clientID); err != nil {
		if errors.Is(err, domain.ErrInvalidClient) {
			invalidErr := domain.NewInvalidRequestError(fmt.Sprintf("client_id %q does not exist", clientID))
			span.RecordError(invalidErr)
			span.SetStatus(codes.Error, invalidErr.Error())
			return nil, invalidErr
		}
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return nil, fmt.Errorf("lookup client %q: %w", clientID, err)
	}

	r, err := s.resources.GetBySlug(ctx, slug)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}

	for _, existing := range r.Policy.Exchange.AllowedClientIDs {
		if existing == clientID {
			return append([]string(nil), r.Policy.Exchange.AllowedClientIDs...), nil
		}
	}

	r.Policy.Exchange.AllowedClientIDs = append(r.Policy.Exchange.AllowedClientIDs, clientID)
	r.UpdatedAt = time.Now().UTC()

	if err := s.resources.Update(ctx, r); err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}

	if s.audit != nil {
		s.audit.Record(ctx, audit.NewEvent(
			audit.ActionResourcePolicyExchangeAllowedClientAdded,
			"admin", r.ID, "",
			fmt.Sprintf("slug=%s client_id=%s", r.Slug, clientID),
		))
	}

	s.logger.InfoContext(ctx, "resource policy exchange.allowed_client added",
		"id", r.ID, "slug", r.Slug, "client_id", clientID)

	return append([]string(nil), r.Policy.Exchange.AllowedClientIDs...), nil
}

// RemoveAllowedClient idempotently removes clientID from the resource's
// policy.exchange.allowed_client_ids.
func (s *ResourceAdminService) RemoveAllowedClient(ctx context.Context, slug, clientID string) ([]string, error) {
	ctx, span := s.tracer.Start(ctx, "ResourceAdminService.RemoveAllowedClient")
	defer span.End()
	span.SetAttributes(attribute.String("slug", slug), attribute.String("client_id", clientID))

	if clientID == "" {
		err := domain.NewInvalidRequestError("client_id is required")
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}

	r, err := s.resources.GetBySlug(ctx, slug)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}

	idx := -1
	for i, existing := range r.Policy.Exchange.AllowedClientIDs {
		if existing == clientID {
			idx = i
			break
		}
	}
	if idx < 0 {
		return append([]string(nil), r.Policy.Exchange.AllowedClientIDs...), nil
	}

	r.Policy.Exchange.AllowedClientIDs = append(r.Policy.Exchange.AllowedClientIDs[:idx], r.Policy.Exchange.AllowedClientIDs[idx+1:]...)
	r.UpdatedAt = time.Now().UTC()

	if err := s.resources.Update(ctx, r); err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}

	if s.audit != nil {
		s.audit.Record(ctx, audit.NewEvent(
			audit.ActionResourcePolicyExchangeAllowedClientRemoved,
			"admin", r.ID, "",
			fmt.Sprintf("slug=%s client_id=%s", r.Slug, clientID),
		))
	}

	s.logger.InfoContext(ctx, "resource policy exchange.allowed_client removed",
		"id", r.ID, "slug", r.Slug, "client_id", clientID)

	return append([]string(nil), r.Policy.Exchange.AllowedClientIDs...), nil
}

// ListAllowedClients returns the resource's policy.exchange.allowed_client_ids.
func (s *ResourceAdminService) ListAllowedClients(ctx context.Context, slug string) ([]string, error) {
	ctx, span := s.tracer.Start(ctx, "ResourceAdminService.ListAllowedClients")
	defer span.End()
	span.SetAttributes(attribute.String("slug", slug))

	r, err := s.resources.GetBySlug(ctx, slug)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}
	return append([]string(nil), r.Policy.Exchange.AllowedClientIDs...), nil
}

// AddAllowedReturnURL idempotently adds returnURL to the resource's
// policy.connect.allowed_return_urls. Mint resources reject the call —
// Connect policy is broker-only (the design §6 + stripMintConnectPolicy).
func (s *ResourceAdminService) AddAllowedReturnURL(ctx context.Context, slug, returnURL string) ([]string, error) {
	ctx, span := s.tracer.Start(ctx, "ResourceAdminService.AddAllowedReturnURL")
	defer span.End()
	span.SetAttributes(attribute.String("slug", slug), attribute.String("return_url", returnURL))

	if err := validateReturnURL(returnURL); err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}

	r, err := s.resources.GetBySlug(ctx, slug)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}
	if r.IsMint() {
		err := domain.NewInvalidRequestError("connect policy is not applicable to mint resources")
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}

	for _, existing := range r.Policy.Connect.AllowedReturnURLs {
		if existing == returnURL {
			return append([]string(nil), r.Policy.Connect.AllowedReturnURLs...), nil
		}
	}

	r.Policy.Connect.AllowedReturnURLs = append(r.Policy.Connect.AllowedReturnURLs, returnURL)
	r.UpdatedAt = time.Now().UTC()

	if err := s.resources.Update(ctx, r); err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}

	if s.audit != nil {
		s.audit.Record(ctx, audit.NewEvent(
			audit.ActionResourcePolicyConnectAllowedReturnURLAdded,
			"admin", r.ID, "",
			fmt.Sprintf("slug=%s return_url=%s", r.Slug, returnURL),
		))
	}

	s.logger.InfoContext(ctx, "resource policy connect.allowed_return_url added",
		"id", r.ID, "slug", r.Slug, "return_url", returnURL)

	return append([]string(nil), r.Policy.Connect.AllowedReturnURLs...), nil
}

// RemoveAllowedReturnURL idempotently removes returnURL from the resource's
// policy.connect.allowed_return_urls.
func (s *ResourceAdminService) RemoveAllowedReturnURL(ctx context.Context, slug, returnURL string) ([]string, error) {
	ctx, span := s.tracer.Start(ctx, "ResourceAdminService.RemoveAllowedReturnURL")
	defer span.End()
	span.SetAttributes(attribute.String("slug", slug), attribute.String("return_url", returnURL))

	if returnURL == "" {
		err := domain.NewInvalidRequestError("url is required")
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}

	r, err := s.resources.GetBySlug(ctx, slug)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}
	if r.IsMint() {
		err := domain.NewInvalidRequestError("connect policy is not applicable to mint resources")
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}

	idx := -1
	for i, existing := range r.Policy.Connect.AllowedReturnURLs {
		if existing == returnURL {
			idx = i
			break
		}
	}
	if idx < 0 {
		return append([]string(nil), r.Policy.Connect.AllowedReturnURLs...), nil
	}

	r.Policy.Connect.AllowedReturnURLs = append(r.Policy.Connect.AllowedReturnURLs[:idx], r.Policy.Connect.AllowedReturnURLs[idx+1:]...)
	r.UpdatedAt = time.Now().UTC()

	if err := s.resources.Update(ctx, r); err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}

	if s.audit != nil {
		s.audit.Record(ctx, audit.NewEvent(
			audit.ActionResourcePolicyConnectAllowedReturnURLRemoved,
			"admin", r.ID, "",
			fmt.Sprintf("slug=%s return_url=%s", r.Slug, returnURL),
		))
	}

	s.logger.InfoContext(ctx, "resource policy connect.allowed_return_url removed",
		"id", r.ID, "slug", r.Slug, "return_url", returnURL)

	return append([]string(nil), r.Policy.Connect.AllowedReturnURLs...), nil
}

// ListAllowedReturnURLs returns the resource's policy.connect.allowed_return_urls.
// Returns InvalidRequestError on Mint resources (no Connect policy semantics).
func (s *ResourceAdminService) ListAllowedReturnURLs(ctx context.Context, slug string) ([]string, error) {
	ctx, span := s.tracer.Start(ctx, "ResourceAdminService.ListAllowedReturnURLs")
	defer span.End()
	span.SetAttributes(attribute.String("slug", slug))

	r, err := s.resources.GetBySlug(ctx, slug)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}
	if r.IsMint() {
		err := domain.NewInvalidRequestError("connect policy is not applicable to mint resources")
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}
	return append([]string(nil), r.Policy.Connect.AllowedReturnURLs...), nil
}

// validateReturnURL accepts loopback-port wildcards (`http://localhost:*`,
// `http://127.0.0.1:*`) verbatim, then falls back to net/url parsing. The
// loopback-port wildcard form mirrors AUTHPLANE_CONNECT_ALLOWED_RETURN_URLS
// matching semantics (cmd/authserver/serve.go); this entrypoint must accept
// the same operator-shaped strings.
func validateReturnURL(returnURL string) error {
	if returnURL == "" {
		return domain.NewInvalidRequestError("url is required")
	}
	// Loopback-port wildcards are stable strings the connect handler will
	// match exactly; no URL parsing is meaningful. Two well-known forms.
	if strings.HasPrefix(returnURL, "http://localhost:") ||
		strings.HasPrefix(returnURL, "http://127.0.0.1:") ||
		strings.HasPrefix(returnURL, "https://localhost:") ||
		strings.HasPrefix(returnURL, "https://127.0.0.1:") {
		return nil
	}
	u, err := url.Parse(returnURL)
	if err != nil {
		return domain.NewInvalidRequestError(fmt.Sprintf("url is not a valid URL: %v", err))
	}
	if !u.IsAbs() {
		return domain.NewInvalidRequestError("url must be absolute (include scheme + host)")
	}
	switch u.Scheme {
	case "http", "https":
		// ok
	default:
		return domain.NewInvalidRequestError(fmt.Sprintf("url scheme must be http or https, got %q", u.Scheme))
	}
	if u.Host == "" {
		return domain.NewInvalidRequestError("url must include a host")
	}
	return nil
}

// validatePolicyClients ensures every entry in policy.exchange.allowed_client_ids
// AND policy.runtime.client_ids resolves to a known OAuth client. Empty
// exchange allowlist means "any client" (permissive). Empty runtime list
// means "no client may act as this Resource" (default-deny) — both are
// valid; only non-empty lists are validated for FK existence.
func (s *ResourceAdminService) validatePolicyClients(ctx context.Context, p resource.Policy) error {
	if err := s.validateClientIDList(ctx, p.Exchange.AllowedClientIDs, "policy.exchange.allowed_client_ids"); err != nil {
		return err
	}
	if err := s.validateClientIDList(ctx, p.Runtime.ClientIDs, "policy.runtime.client_ids"); err != nil {
		return err
	}
	return nil
}

// validateClientIDList checks every non-empty entry resolves to a known
// OAuth client; empty list is a no-op (callers decide the empty-list
// semantics — see validatePolicyClients).
func (s *ResourceAdminService) validateClientIDList(ctx context.Context, ids []string, fieldName string) error {
	for _, cid := range ids {
		if cid == "" {
			return domain.NewInvalidRequestError(fmt.Sprintf("%s must not contain empty entries", fieldName))
		}
		_, err := s.clients.GetByID(ctx, cid)
		if err != nil {
			if errors.Is(err, domain.ErrInvalidClient) {
				return domain.NewInvalidRequestError(fmt.Sprintf("client_id %q in %s does not exist", cid, fieldName))
			}
			return fmt.Errorf("lookup client %q: %w", cid, err)
		}
	}
	return nil
}

// AddRuntimeClientID idempotently adds clientID to the resource's
// policy.runtime.client_ids. The lookup is by slug. Same TOCTOU caveat as
// AddAllowedClient — admin operations are rare + idempotent..
func (s *ResourceAdminService) AddRuntimeClientID(ctx context.Context, slug, clientID string) ([]string, error) {
	ctx, span := s.tracer.Start(ctx, "ResourceAdminService.AddRuntimeClientID")
	defer span.End()
	span.SetAttributes(attribute.String("slug", slug), attribute.String("client_id", clientID))

	if clientID == "" {
		err := domain.NewInvalidRequestError("client_id is required")
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}

	if _, err := s.clients.GetByID(ctx, clientID); err != nil {
		if errors.Is(err, domain.ErrInvalidClient) {
			invalidErr := domain.NewInvalidRequestError(fmt.Sprintf("client_id %q does not exist", clientID))
			span.RecordError(invalidErr)
			span.SetStatus(codes.Error, invalidErr.Error())
			return nil, invalidErr
		}
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return nil, fmt.Errorf("lookup client %q: %w", clientID, err)
	}

	r, err := s.resources.GetBySlug(ctx, slug)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}

	for _, existing := range r.Policy.Runtime.ClientIDs {
		if existing == clientID {
			return append([]string(nil), r.Policy.Runtime.ClientIDs...), nil
		}
	}

	r.Policy.Runtime.ClientIDs = append(r.Policy.Runtime.ClientIDs, clientID)
	r.UpdatedAt = time.Now().UTC()

	if err := s.resources.Update(ctx, r); err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}

	if s.audit != nil {
		s.audit.Record(ctx, audit.NewEvent(
			audit.ActionResourcePolicyRuntimeClientAdded,
			"admin", r.ID, "",
			fmt.Sprintf("slug=%s client_id=%s", r.Slug, clientID),
		))
	}

	s.logger.InfoContext(ctx, "resource policy runtime.client_id added",
		"id", r.ID, "slug", r.Slug, "client_id", clientID)

	return append([]string(nil), r.Policy.Runtime.ClientIDs...), nil
}

// RemoveRuntimeClientID idempotently removes clientID from the resource's
// policy.runtime.client_ids..
func (s *ResourceAdminService) RemoveRuntimeClientID(ctx context.Context, slug, clientID string) ([]string, error) {
	ctx, span := s.tracer.Start(ctx, "ResourceAdminService.RemoveRuntimeClientID")
	defer span.End()
	span.SetAttributes(attribute.String("slug", slug), attribute.String("client_id", clientID))

	if clientID == "" {
		err := domain.NewInvalidRequestError("client_id is required")
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}

	r, err := s.resources.GetBySlug(ctx, slug)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}

	idx := -1
	for i, existing := range r.Policy.Runtime.ClientIDs {
		if existing == clientID {
			idx = i
			break
		}
	}
	if idx < 0 {
		return append([]string(nil), r.Policy.Runtime.ClientIDs...), nil
	}

	r.Policy.Runtime.ClientIDs = append(r.Policy.Runtime.ClientIDs[:idx], r.Policy.Runtime.ClientIDs[idx+1:]...)
	r.UpdatedAt = time.Now().UTC()

	if err := s.resources.Update(ctx, r); err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}

	if s.audit != nil {
		s.audit.Record(ctx, audit.NewEvent(
			audit.ActionResourcePolicyRuntimeClientRemoved,
			"admin", r.ID, "",
			fmt.Sprintf("slug=%s client_id=%s", r.Slug, clientID),
		))
	}

	s.logger.InfoContext(ctx, "resource policy runtime.client_id removed",
		"id", r.ID, "slug", r.Slug, "client_id", clientID)

	return append([]string(nil), r.Policy.Runtime.ClientIDs...), nil
}

// ListRuntimeClientIDs returns the resource's policy.runtime.client_ids.
// Empty list = no client may act as this Resource (default-deny)..
func (s *ResourceAdminService) ListRuntimeClientIDs(ctx context.Context, slug string) ([]string, error) {
	ctx, span := s.tracer.Start(ctx, "ResourceAdminService.ListRuntimeClientIDs")
	defer span.End()
	span.SetAttributes(attribute.String("slug", slug))

	r, err := s.resources.GetBySlug(ctx, slug)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}
	return append([]string(nil), r.Policy.Runtime.ClientIDs...), nil
}
