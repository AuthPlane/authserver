package output

import (
	"context"

	"github.com/authplane/authserver/internal/domain/resource"
)

// ResourceStore persists the unified Resource registry. See
// the architecture doc and the data model
//
// Slug normalization (resource.NormalizeSlug) is applied at the adapter
// boundary on Create/Update; non-conforming input returns
// domain.ErrInvalidSlug before any SQL runs. The SQL UNIQUE on slug is
// the second line of defense; the CHECK constraint in the schema is the
// third.
type ResourceStore interface {
	// GetByID returns the Resource with the given id, or
	// domain.ErrResourceNotFound.
	GetByID(ctx context.Context, id string) (*resource.Resource, error)

	// GetBySlug returns the Resource with the given slug, or
	// domain.ErrResourceNotFound. The caller is responsible for normalizing
	// the slug; the store does not lowercase on read.
	GetBySlug(ctx context.Context, slug string) (*resource.Resource, error)

	// Resolve implements the resource= parameter resolution rule from
	// the data model / §6 Q1: match by slug exact OR uri exact, LIMIT 2,
	// de-duped by id. Callers distinguish 0/1/2 row results:
	// 0 → domain.ErrResourceNotFound (caller's choice — store returns
	// empty slice with nil error), 1 → use it, 2 → caller maps to
	// domain.ErrAmbiguousResource.
	Resolve(ctx context.Context, slugOrURI string) ([]*resource.Resource, error)

	// List returns Resources matching the filter. Empty filter fields are
	// wildcards.
	List(ctx context.Context, filter ResourceFilter) ([]*resource.Resource, error)

	// Create inserts a new Resource. The adapter normalizes the slug and
	// rejects non-conforming input with domain.ErrInvalidSlug. UNIQUE-slug
	// conflicts surface unwrapped as the underlying driver error (callers
	// rarely race here; collision is a programmer-supplied-id mistake).
	Create(ctx context.Context, r *resource.Resource) error

	// Update replaces the Resource with id r.ID. Same slug-normalization
	// rules as Create. Returns domain.ErrResourceNotFound if no row matches.
	Update(ctx context.Context, r *resource.Resource) error

	// Delete removes the Resource by id. Returns
	// domain.ErrResourceHasReferences if consent_grants or issuances
	// rows reference it (FK block). Returns domain.ErrResourceNotFound if
	// the row did not exist.
	Delete(ctx context.Context, id string) error

	// FindByRuntimeClientID returns the Resource whose policy.runtime.client_ids
	// contains clientID. Used by the broker dispatch agent-attestation gate
	// (token_exchange.go) to identify which Resource an authenticated client
	// represents at runtime..
	//
	// Returns domain.ErrResourceNotFound when no Resource lists clientID;
	// domain.ErrAmbiguousResource when two or more Resources do (operator
	// misconfiguration — clientID should map to a single Resource role per
	// call). The runtime treats the ambiguous case as fail-closed.
	FindByRuntimeClientID(ctx context.Context, clientID string) (*resource.Resource, error)
}

// ResourceFilter narrows ResourceStore.List. Empty fields mean "any".
type ResourceFilter struct {
	BackendKind      resource.BackendKind
	BrokerProviderID string
	Limit            int
	Offset           int
}
