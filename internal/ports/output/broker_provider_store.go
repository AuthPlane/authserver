package output

import (
	"context"

	"github.com/authplane/authserver/internal/domain/resource"
)

// BrokerProviderStore persists upstream OAuth-app (or equivalent)
// registrations shared across all Broker Resources that target the same
// upstream. See the architecture doc and the data model
//
// ConfigData is opaque JSON owned by the BrokerProtocol adapter for the
// provider's protocol. The store round-trips it byte-for-byte and never
// inspects it.
type BrokerProviderStore interface {
	// GetByID returns the provider by id, or domain.ErrResourceNotFound.
	GetByID(ctx context.Context, id string) (*resource.BrokerProvider, error)

	// GetBySlug returns the provider by slug, or domain.ErrResourceNotFound.
	GetBySlug(ctx context.Context, slug string) (*resource.BrokerProvider, error)

	// List returns all providers ordered by slug.
	List(ctx context.Context) ([]*resource.BrokerProvider, error)

	// Create inserts a new provider. Slug is normalized via
	// resource.NormalizeSlug; non-conforming input returns
	// domain.ErrInvalidSlug. Duplicate-slug conflicts surface unwrapped.
	Create(ctx context.Context, p *resource.BrokerProvider) error

	// Update replaces the provider with id p.ID. Same slug rules as Create.
	// Returns domain.ErrResourceNotFound if no row matches.
	Update(ctx context.Context, p *resource.BrokerProvider) error

	// Delete removes the provider by id. Returns
	// domain.ErrBrokerProviderHasReferences if resources.broker_provider_id
	// or broker_grants.broker_provider_id rows reference it (FK block).
	// Returns domain.ErrResourceNotFound if the row did not exist.
	Delete(ctx context.Context, id string) error
}
