package output

import (
	"context"

	"github.com/authplane/authserver/internal/domain/resource"
)

// FrontingLinkStore persists operator-declared cross-Mint fronting
// links. Keyed on (source_slug, target_slug) — one link per direction.
// The store layer enforces the FK to resources(slug) at the DB level
// (ON DELETE RESTRICT); cascade is handled by FrontingService so it
// can return the dependent list to the admin before destroying anything.
type FrontingLinkStore interface {
	// Get returns the link with the given (source, target) pair, or
	// domain.ErrFrontingLinkNotFound on miss.
	Get(ctx context.Context, sourceSlug, targetSlug string) (*resource.FrontingLink, error)

	// List returns links matching the filter ordered by (source_slug,
	// target_slug). Empty filter fields mean "any".
	List(ctx context.Context, filter FrontingLinkFilter) ([]*resource.FrontingLink, error)

	// ListForResource returns every link that references slug, in either
	// direction (source OR target). Used by the per-Resource detail view
	// and by the cascade-on-delete preflight.
	ListForResource(ctx context.Context, slug string) ([]*resource.FrontingLink, error)

	// Create inserts a new link. Returns domain.ErrFrontingLinkExists on a
	// (source_slug, target_slug) UNIQUE violation. The adapter does not
	// validate scope-map shape — callers (FrontingService) own that.
	Create(ctx context.Context, link *resource.FrontingLink) error

	// Update replaces the scope_map of an existing link identified by
	// (source_slug, target_slug). Returns domain.ErrFrontingLinkNotFound if
	// no row matches. created_at and created_by are preserved.
	Update(ctx context.Context, link *resource.FrontingLink) error

	// Delete removes the link identified by (source_slug, target_slug).
	// Returns domain.ErrFrontingLinkNotFound if no row matches.
	Delete(ctx context.Context, sourceSlug, targetSlug string) error

	// DeleteForResource removes every link that references slug (source OR
	// target). Used by the Resource cascade-delete path (admin-supplied
	// ?cascade=true on DELETE /admin/resources/{id}). Returns the number of
	// rows deleted.
	DeleteForResource(ctx context.Context, slug string) (int, error)
}

// FrontingLinkFilter narrows FrontingLinkStore.List. Empty fields mean "any".
// Source and Target are mutually permissive — supplying both filters to the
// matching pair (effectively a Get).
type FrontingLinkFilter struct {
	Source string
	Target string
	Limit  int
	Offset int
}
