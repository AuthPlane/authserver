// Package services — FrontingService implements the operator-declared
// cross-Mint fronting-links surface. Fronting links describe
// which Mint Resource may mint tokens for a downstream Mint or Broker
// Resource via RFC 8693 token-exchange. wires the admin surface and
// storage; lights the runtime path that reads these rows during
// /oauth/token.
package services

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"strings"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"

	"github.com/authplane/authserver/internal/domain"
	"github.com/authplane/authserver/internal/domain/audit"
	"github.com/authplane/authserver/internal/domain/resource"
	"github.com/authplane/authserver/internal/observability"
	"github.com/authplane/authserver/internal/ports/input"
	"github.com/authplane/authserver/internal/ports/output"
)

// FrontingService implements input.FrontingAdminPort over output.FrontingLinkStore
// + output.ResourceStore. Validation rules + cycle detection live here; the
// adapter layer is intentionally thin so identical rules apply whether the
// caller is HTTP (api/admin/fronting.go) or the CLI (cmd/authserver/admin_fronting.go).
type FrontingService struct {
	links     output.FrontingLinkStore
	resources output.ResourceStore
	tx        output.TransactionManager // optional — cascade falls back to best-effort sequential delete when nil
	audit     AuditRecorder
	logger    *slog.Logger
	tracer    trace.Tracer
}

var _ input.FrontingAdminPort = (*FrontingService)(nil)

// NewFrontingService constructs a FrontingService. tx may be nil — the
// service degrades to non-transactional cascade when no transaction manager
// is wired (in-memory test stubs, exotic deployments). Production wires both.
func NewFrontingService(
	links output.FrontingLinkStore,
	resources output.ResourceStore,
	tx output.TransactionManager,
	obs *observability.Provider,
	auditSvc AuditRecorder,
) *FrontingService {
	return &FrontingService{
		links:     links,
		resources: resources,
		tx:        tx,
		audit:     auditSvc,
		logger:    obs.Logger,
		tracer:    obs.Tracer,
	}
}

// Get returns a single link by (source, target).
func (s *FrontingService) Get(ctx context.Context, sourceSlug, targetSlug string) (*resource.FrontingLink, error) {
	ctx, span := s.tracer.Start(ctx, "FrontingService.Get")
	defer span.End()
	span.SetAttributes(attribute.String("source", sourceSlug), attribute.String("target", targetSlug))

	link, err := s.links.Get(ctx, sourceSlug, targetSlug)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}
	return link, nil
}

// List returns links matching filter.
func (s *FrontingService) List(ctx context.Context, filter input.FrontingLinkFilter) ([]*resource.FrontingLink, error) {
	ctx, span := s.tracer.Start(ctx, "FrontingService.List")
	defer span.End()

	rows, err := s.links.List(ctx, output.FrontingLinkFilter{
		Source: filter.Source,
		Target: filter.Target,
		Limit:  filter.Limit,
		Offset: filter.Offset,
	})
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return nil, fmt.Errorf("list fronting links: %w", err)
	}
	return rows, nil
}

// ListForResource returns every link that references slug as source or target.
func (s *FrontingService) ListForResource(ctx context.Context, slug string) ([]*resource.FrontingLink, error) {
	ctx, span := s.tracer.Start(ctx, "FrontingService.ListForResource")
	defer span.End()
	span.SetAttributes(attribute.String("slug", slug))

	rows, err := s.links.ListForResource(ctx, slug)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return nil, fmt.Errorf("list fronting links for resource: %w", err)
	}
	return rows, nil
}

// Validate runs the full pre-write validation pass without persisting. Powers
// the ?dry_run=true preflight. Returns a domain error on failure, nil on
// success. Validation order matches §Validation rules (cheapest + most
// specific first):
//
//  1. shape (source/target slugs, scope_map non-empty + non-empty entries)
//  2. self-loop (rejected by FrontingLink.Validate)
//  3. resource existence + active state
//  4. source.kind == mint, target.kind ∈ {mint, broker}
//  5. scope-map keys ⊆ source.scopes
//  6. scope-map values ⊆ target.published_scopes
//  7. broker target: provider must be set
//  8. uniqueness ((source, target) not already present)
//  9. cycle detection over the proposed graph
func (s *FrontingService) Validate(ctx context.Context, link *resource.FrontingLink) error {
	ctx, span := s.tracer.Start(ctx, "FrontingService.Validate")
	defer span.End()
	if link != nil {
		span.SetAttributes(attribute.String("source", link.SourceSlug), attribute.String("target", link.TargetSlug))
	}
	if err := s.validate(ctx, link); err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return err
	}
	return nil
}

// Create persists a new fronting link after validation. actorID is recorded
// on the row's created_by field and the audit event.
func (s *FrontingService) Create(ctx context.Context, link *resource.FrontingLink, actorID string) error {
	ctx, span := s.tracer.Start(ctx, "FrontingService.Create")
	defer span.End()
	if link == nil {
		err := domain.NewInvalidRequestError("link is required")
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return err
	}
	span.SetAttributes(attribute.String("source", link.SourceSlug), attribute.String("target", link.TargetSlug))

	if err := s.validate(ctx, link); err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return err
	}

	link.CreatedAt = time.Now().UTC()
	link.CreatedBy = actorID
	if err := s.links.Create(ctx, link); err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return err
	}

	if s.audit != nil {
		s.audit.Record(ctx, audit.NewEvent(
			audit.ActionFrontingLinkCreated,
			actorIDOrAdmin(actorID), "", "",
			fmt.Sprintf("source=%s target=%s scopes=%s", link.SourceSlug, link.TargetSlug, summarizeScopeMap(link.ScopeMap)),
		))
	}
	s.logger.InfoContext(ctx, "fronting link created",
		"source", link.SourceSlug, "target", link.TargetSlug, "actor", actorID)
	return nil
}

// Patch replaces the scope_map of an existing link. Other fields are immutable
// (delete + recreate to rewire). Re-runs the scope-membership validation.
func (s *FrontingService) Patch(ctx context.Context, sourceSlug, targetSlug string, patch input.FrontingLinkPatch, actorID string) (*resource.FrontingLink, error) {
	ctx, span := s.tracer.Start(ctx, "FrontingService.Patch")
	defer span.End()
	span.SetAttributes(attribute.String("source", sourceSlug), attribute.String("target", targetSlug))

	existing, err := s.links.Get(ctx, sourceSlug, targetSlug)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}

	// Empty patch — same convention as ResourceAdminService.Patch: no DB
	// write, no audit row, return the existing row.
	if patch.ScopeMap == nil {
		return existing, nil
	}

	candidate := *existing
	candidate.ScopeMap = *patch.ScopeMap

	// Re-run validation of the updated link. Cycle detection is unaffected
	// because the (source, target) pair is unchanged, but scope-membership
	// must re-fire against the current Resource catalogs.
	if err := s.validateForPatch(ctx, &candidate); err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}

	if err := s.links.Update(ctx, &candidate); err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}

	if s.audit != nil {
		s.audit.Record(ctx, audit.NewEvent(
			audit.ActionFrontingLinkPatched,
			actorIDOrAdmin(actorID), "", "",
			fmt.Sprintf("source=%s target=%s scopes=%s", candidate.SourceSlug, candidate.TargetSlug, summarizeScopeMap(candidate.ScopeMap)),
		))
	}
	s.logger.InfoContext(ctx, "fronting link patched",
		"source", candidate.SourceSlug, "target", candidate.TargetSlug, "actor", actorID)
	return &candidate, nil
}

// Delete removes a link.
func (s *FrontingService) Delete(ctx context.Context, sourceSlug, targetSlug string, actorID string) error {
	ctx, span := s.tracer.Start(ctx, "FrontingService.Delete")
	defer span.End()
	span.SetAttributes(attribute.String("source", sourceSlug), attribute.String("target", targetSlug))

	if err := s.links.Delete(ctx, sourceSlug, targetSlug); err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return err
	}

	if s.audit != nil {
		s.audit.Record(ctx, audit.NewEvent(
			audit.ActionFrontingLinkDeleted,
			actorIDOrAdmin(actorID), "", "",
			fmt.Sprintf("source=%s target=%s", sourceSlug, targetSlug),
		))
	}
	s.logger.InfoContext(ctx, "fronting link deleted",
		"source", sourceSlug, "target", targetSlug, "actor", actorID)
	return nil
}

// ValidateResourceUpdate enforces the edit-time hooks documented in
// §Edit-time re-validation. Called from ResourceAdminService.Patch with the
// pre-Patch and post-Patch resource snapshots.
//
//   - kind change (mint↔broker) when ANY link references the resource → forbidden
//   - source: scope removed that's a scope_map key in any link starting at
//     this resource → block
//   - target: scope removed that's a scope_map value in any link ending at
//     this resource → block
//
// "Rename" is a special case of "remove + add" because Resource.Scopes
// carries scopes by name; a name change presents to this hook as the old
// name disappearing from the slice. forbids scope renames entirely
// when referenced — same code path as scope removal here. Defense-in-depth
// for new-name validation: if the new name doesn't match any existing
// scope_map value, the standard reject-on-removal fires.
//
// prev/next must be the same resource (same id/slug); the function returns
// nil if neither relevant field changed.
func (s *FrontingService) ValidateResourceUpdate(ctx context.Context, prev, next *resource.Resource) error {
	ctx, span := s.tracer.Start(ctx, "FrontingService.ValidateResourceUpdate")
	defer span.End()
	if prev == nil || next == nil {
		return nil
	}
	span.SetAttributes(attribute.String("slug", prev.Slug))

	links, err := s.links.ListForResource(ctx, prev.Slug)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return fmt.Errorf("list fronting links for resource: %w", err)
	}
	if len(links) == 0 {
		return nil
	}

	if prev.BackendKind != next.BackendKind {
		return domain.NewInvalidRequestError(fmt.Sprintf(
			"resource %q has %d fronting link(s); kind change (%s→%s) is forbidden — drop links first",
			prev.Slug, len(links), prev.BackendKind, next.BackendKind))
	}

	prevScopes := scopeNameSet(prev.Scopes)
	nextScopes := scopeNameSet(next.Scopes)

	for _, link := range links {
		if link.SourceSlug == prev.Slug {
			// We are the source — scope_map keys must remain in our scope
			// catalog.
			for src := range link.ScopeMap {
				if _, prevHad := prevScopes[src]; !prevHad {
					continue
				}
				if _, stillHas := nextScopes[src]; !stillHas {
					return domain.NewInvalidRequestError(fmt.Sprintf(
						"cannot remove scope %q from resource %q: referenced by fronting link source=%s target=%s",
						src, prev.Slug, link.SourceSlug, link.TargetSlug))
				}
			}
		}
		if link.TargetSlug == prev.Slug {
			// We are the target — scope_map values must remain in our scope
			// catalog.
			for _, tgts := range link.ScopeMap {
				for _, tgt := range tgts {
					if _, prevHad := prevScopes[tgt]; !prevHad {
						continue
					}
					if _, stillHas := nextScopes[tgt]; !stillHas {
						return domain.NewInvalidRequestError(fmt.Sprintf(
							"cannot remove scope %q from resource %q: referenced by fronting link source=%s target=%s",
							tgt, prev.Slug, link.SourceSlug, link.TargetSlug))
					}
				}
			}
		}
	}
	return nil
}

// CascadeDeleteForResource removes every link that references slug. Called
// by ResourceAdminService.DeleteWithCascade after the admin has confirmed
// with ?cascade=true. Returns the dependents that were removed so the
// audit/UI layers can surface what was affected.
//
// The caller is expected to be running inside ResourceAdminService's
// transaction (so the resource delete + link deletes are atomic). If no
// transaction is in flight the operation is best-effort sequential.
func (s *FrontingService) CascadeDeleteForResource(ctx context.Context, slug string, actorID string) ([]*resource.FrontingLink, error) {
	ctx, span := s.tracer.Start(ctx, "FrontingService.CascadeDeleteForResource")
	defer span.End()
	span.SetAttributes(attribute.String("slug", slug))

	dependents, err := s.links.ListForResource(ctx, slug)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return nil, fmt.Errorf("list fronting links for resource: %w", err)
	}
	if len(dependents) == 0 {
		return nil, nil
	}

	if _, err := s.links.DeleteForResource(ctx, slug); err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}

	if s.audit != nil {
		for _, l := range dependents {
			// `slug` is always one of l.SourceSlug / l.TargetSlug — the
			// link wouldn't be in `dependents` otherwise. Don't repeat it
			// in detail; reason= alone is enough for a forensic query that
			// wants to filter cascade-driven deletes from explicit ones.
			s.audit.Record(ctx, audit.NewEvent(
				audit.ActionFrontingLinkDeleted,
				actorIDOrAdmin(actorID), "", "",
				fmt.Sprintf("source=%s target=%s reason=resource_cascade", l.SourceSlug, l.TargetSlug),
			))
		}
	}
	s.logger.InfoContext(ctx, "fronting links cascade-deleted",
		"slug", slug, "count", len(dependents), "actor", actorID)
	return dependents, nil
}

// --- internals ---

// validate runs the full pre-write validation pass for a brand-new link.
// validateForPatch reuses everything except the uniqueness check (the row
// being patched is the existing one) and skips cycle detection (graph
// topology unchanged when only scope_map mutates).
func (s *FrontingService) validate(ctx context.Context, link *resource.FrontingLink) error {
	if link == nil {
		return domain.NewInvalidRequestError("link is required")
	}
	if err := link.Validate(); err != nil {
		return err
	}

	source, err := s.lookupResource(ctx, link.SourceSlug, "source_slug")
	if err != nil {
		return err
	}
	target, err := s.lookupResource(ctx, link.TargetSlug, "target_slug")
	if err != nil {
		return err
	}

	if !source.IsMint() {
		return domain.NewInvalidRequestError(fmt.Sprintf(
			"source resource %q must have backend_kind=mint, got %q", source.Slug, source.BackendKind))
	}
	switch target.BackendKind {
	case resource.BackendMint, resource.BackendBroker:
		// ok
	default:
		return domain.NewInvalidRequestError(fmt.Sprintf(
			"target resource %q has unsupported backend_kind %q", target.Slug, target.BackendKind))
	}

	if err := s.assertScopeMapMembership(link.ScopeMap, source, target); err != nil {
		return err
	}

	if target.IsBroker() && target.BrokerProviderID == "" {
		return domain.NewInvalidRequestError(fmt.Sprintf(
			"target broker resource %q has no broker_provider_id (provider must be configured before fronting)", target.Slug))
	}

	// Uniqueness — pre-check so the wire-level error is a clean 409 instead
	// of a 500 from the underlying UNIQUE-constraint driver error. Same
	// race-window note as ResourceAdminService.assertSlugAvailable applies.
	if _, err := s.links.Get(ctx, link.SourceSlug, link.TargetSlug); err == nil {
		return domain.ErrFrontingLinkExists
	} else if !errors.Is(err, domain.ErrFrontingLinkNotFound) {
		return fmt.Errorf("check existing link: %w", err)
	}

	if err := s.assertNoCycle(ctx, link.SourceSlug, link.TargetSlug); err != nil {
		return err
	}
	return nil
}

// validateForPatch is a strict subset of validate: every pre-write rule
// EXCEPT (a) uniqueness — the row already exists, by definition — and
// (b) cycle detection — the (source, target) pair is unchanged on PATCH so
// the graph topology is identical. Defense-in-depth for rules 2/3/8 even
// though the kind-change + DB CHECK guards make the violating states
// unreachable in practice; keeping the validator a strict subset of validate
// prevents drift if the upstream rules ever shift.
func (s *FrontingService) validateForPatch(ctx context.Context, link *resource.FrontingLink) error {
	if link == nil {
		return domain.NewInvalidRequestError("link is required")
	}
	if err := link.Validate(); err != nil {
		return err
	}
	source, err := s.lookupResource(ctx, link.SourceSlug, "source_slug")
	if err != nil {
		return err
	}
	target, err := s.lookupResource(ctx, link.TargetSlug, "target_slug")
	if err != nil {
		return err
	}
	if !source.IsMint() {
		return domain.NewInvalidRequestError(fmt.Sprintf(
			"source resource %q must have backend_kind=mint, got %q", source.Slug, source.BackendKind))
	}
	switch target.BackendKind {
	case resource.BackendMint, resource.BackendBroker:
		// ok
	default:
		return domain.NewInvalidRequestError(fmt.Sprintf(
			"target resource %q has unsupported backend_kind %q", target.Slug, target.BackendKind))
	}
	if err := s.assertScopeMapMembership(link.ScopeMap, source, target); err != nil {
		return err
	}
	if target.IsBroker() && target.BrokerProviderID == "" {
		return domain.NewInvalidRequestError(fmt.Sprintf(
			"target broker resource %q has no broker_provider_id (provider must be configured before fronting)", target.Slug))
	}
	return nil
}

func (s *FrontingService) lookupResource(ctx context.Context, slug, paramName string) (*resource.Resource, error) {
	r, err := s.resources.GetBySlug(ctx, slug)
	if err != nil {
		if errors.Is(err, domain.ErrResourceNotFound) {
			return nil, domain.NewInvalidRequestError(fmt.Sprintf("%s %q does not reference an existing resource", paramName, slug))
		}
		return nil, fmt.Errorf("lookup resource %q: %w", slug, err)
	}
	return r, nil
}

func (s *FrontingService) assertScopeMapMembership(m resource.ScopeMap, source, target *resource.Resource) error {
	srcCatalog := scopeNameSet(source.Scopes)
	tgtCatalog := scopeNameSet(target.Scopes)
	for src, tgts := range m {
		if _, ok := srcCatalog[src]; !ok {
			return domain.NewInvalidRequestError(fmt.Sprintf(
				"scope_map key %q is not a scope on source resource %q", src, source.Slug))
		}
		for _, tgt := range tgts {
			if _, ok := tgtCatalog[tgt]; !ok {
				return domain.NewInvalidRequestError(fmt.Sprintf(
					"scope_map value %q (under key %q) is not a scope on target resource %q",
					tgt, src, target.Slug))
			}
		}
	}
	return nil
}

// assertNoCycle runs DFS from target over the existing fronting graph; if it
// can reach source, the proposed edge source→target would close a cycle.
//
// Self-loops are caught at link.Validate() time. The graph excludes the
// proposed edge itself — we're asking whether the existing graph plus the new
// edge contains a cycle, which is equivalent to asking whether target can
// already reach source.
func (s *FrontingService) assertNoCycle(ctx context.Context, sourceSlug, targetSlug string) error {
	// BFS/DFS over outgoing edges from target. We resolve children lazily
	// (one ListForResource per node visited) — the fronting graph is small
	// enough that the marginal cost is acceptable, and lazy resolution
	// keeps memory bounded.
	visited := map[string]struct{}{targetSlug: {}}
	stack := []string{targetSlug}
	for len(stack) > 0 {
		node := stack[len(stack)-1]
		stack = stack[:len(stack)-1]

		// Outgoing edges from `node` only (filter source=node). ListForResource
		// returns both directions, which would force us to filter on every
		// hop; the per-source filter is more direct.
		out, err := s.links.List(ctx, output.FrontingLinkFilter{Source: node})
		if err != nil {
			return fmt.Errorf("walk fronting graph from %q: %w", node, err)
		}
		for _, e := range out {
			if e.TargetSlug == sourceSlug {
				return domain.ErrFrontingLinkCycle
			}
			if _, seen := visited[e.TargetSlug]; seen {
				continue
			}
			visited[e.TargetSlug] = struct{}{}
			stack = append(stack, e.TargetSlug)
		}
	}
	return nil
}

func scopeNameSet(scopes []resource.Scope) map[string]struct{} {
	out := make(map[string]struct{}, len(scopes))
	for _, s := range scopes {
		out[s.Name] = struct{}{}
	}
	return out
}

// summarizeScopeMap renders a stable, compact representation for audit-detail
// strings. Format: "src1->dst1+dst2,src2->dst3". Sorted on both axes so a
// rerun against the same map produces the same string.
func summarizeScopeMap(m resource.ScopeMap) string {
	if len(m) == 0 {
		return "{}"
	}
	srcs := m.SourceScopes()
	parts := make([]string, 0, len(srcs))
	for _, src := range srcs {
		tgts := append([]string(nil), m[src]...)
		sort.Strings(tgts)
		parts = append(parts, src+"->"+strings.Join(tgts, "+"))
	}
	return strings.Join(parts, ",")
}

// actorIDOrAdmin keeps audit rows non-empty: when the caller is anonymous
// (e.g. CLI without an admin context), we record "admin" so audit queries
// remain consistent with the rest of the admin surface.
func actorIDOrAdmin(actorID string) string {
	if actorID == "" {
		return "admin"
	}
	return actorID
}
