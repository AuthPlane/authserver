package input

import (
	"context"

	"github.com/authplane/authserver/internal/domain/resource"
)

// FrontingAdminPort exposes administrative CRUD over the fronting_links
// table. The driving adapter is /admin/fronting in
// api/admin/fronting.go; the driven adapter is FrontingService over
// output.FrontingLinkStore + output.ResourceStore.
//
// All write methods accept actorID — the admin (user or API-key) initiating
// the change. The service layer records this on fronting_links.created_by
// and on the audit row.
type FrontingAdminPort interface {
	// Get returns the link with the given (source, target) pair, or
	// domain.ErrFrontingLinkNotFound on miss.
	Get(ctx context.Context, sourceSlug, targetSlug string) (*resource.FrontingLink, error)

	// List returns links matching the filter ordered by (source_slug,
	// target_slug). Empty filter fields mean "any".
	List(ctx context.Context, filter FrontingLinkFilter) ([]*resource.FrontingLink, error)

	// ListForResource returns every link that names slug as source or
	// target. Used by GET /admin/resources/{slug}/fronting and by the
	// pre-delete cascade preflight in ResourceAdminService.
	ListForResource(ctx context.Context, slug string) ([]*resource.FrontingLink, error)

	// Validate runs the full pre-write validation pass without persisting.
	// Used by POST /admin/fronting?dry_run=true so the Admin UI can flag
	// invalid input before commit.
	Validate(ctx context.Context, link *resource.FrontingLink) error

	// Create persists a new fronting link after running every validation
	// rule from §Validation. Returns domain.ErrFrontingLinkExists on
	// duplicate (source, target), domain.ErrFrontingLinkCycle when the
	// proposed link closes a cycle, or domain.NewInvalidRequestError
	// carrying a specific rule failure for everything else.
	Create(ctx context.Context, link *resource.FrontingLink, actorID string) error

	// Patch replaces the scope_map of an existing link, re-running
	// validation rules that touch the map (membership in source/target
	// scope catalogs). created_at + created_by are preserved.
	Patch(ctx context.Context, sourceSlug, targetSlug string, patch FrontingLinkPatch, actorID string) (*resource.FrontingLink, error)

	// Delete removes the link.
	Delete(ctx context.Context, sourceSlug, targetSlug string, actorID string) error

	// ValidateResourceUpdate runs the edit-time hooks documented in
	// §Edit-time re-validation: blocks scope removals/renames referenced
	// by any link, forbids kind changes (mint↔broker) when links exist.
	// Returns domain.NewInvalidRequestError with a specific message on
	// failure, nil otherwise.
	ValidateResourceUpdate(ctx context.Context, prev, next *resource.Resource) error
}

// FrontingLinkFilter narrows FrontingAdminPort.List. Empty fields mean "any".
// Mirrors output.FrontingLinkFilter so the API layer never imports
// internal/ports/output.
type FrontingLinkFilter struct {
	Source string
	Target string
	Limit  int
	Offset int
}

// FrontingLinkPatch encodes the writable fields on a Patch. Only ScopeMap is
// patchable — source/target slugs are part of the primary key (delete +
// recreate to rewire). Nil-pointer fields are LEFT UNCHANGED, matching
// ResourcePatch semantics; this matters less here since there's only one
// patchable field, but the convention keeps the surface uniform.
type FrontingLinkPatch struct {
	ScopeMap *resource.ScopeMap
}
