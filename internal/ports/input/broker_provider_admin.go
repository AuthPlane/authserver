package input

import (
	"context"
	"encoding/json"

	"github.com/authplane/authserver/internal/domain/resource"
)

// BrokerProviderAdminPort exposes administrative CRUD over the broker_providers
// table (the design §6 / the data model). The driving adapter is
// /admin/broker-providers (api/admin/broker_providers.go); the driven adapter
// is BrokerProviderAdminService over output.BrokerProviderStore.
type BrokerProviderAdminPort interface {
	// List returns all BrokerProviders ordered by slug.
	List(ctx context.Context) ([]*resource.BrokerProvider, error)

	// GetByID returns the BrokerProvider with the given id, or
	// domain.ErrResourceNotFound.
	GetByID(ctx context.Context, id string) (*resource.BrokerProvider, error)

	// GetBySlug returns the BrokerProvider with the given slug, or
	// domain.ErrResourceNotFound. Used by the seed-loop idempotency check
	// (cmd/authserver/serve.go) so YAML edits referencing existing rows by
	// slug skip cleanly without surfacing benign UNIQUE-constraint errors.
	GetBySlug(ctx context.Context, slug string) (*resource.BrokerProvider, error)

	// Create inserts a new BrokerProvider. The service generates the id and
	// timestamps; callers MUST leave BrokerProvider.ID empty.
	Create(ctx context.Context, p *resource.BrokerProvider) error

	// Patch applies a partial update per BrokerProviderPatch semantics and
	// returns the post-patch BrokerProvider. Nil-pointer fields are LEFT
	// UNCHANGED; non-nil fields are REPLACED in full.
	Patch(ctx context.Context, id string, patch BrokerProviderPatch) (*resource.BrokerProvider, error)

	// Delete removes the BrokerProvider by id. Returns
	// domain.ErrBrokerProviderHasReferences when an FK block prevents the
	// row from being removed (resources, broker_grants), or
	// domain.ErrResourceNotFound on miss.
	Delete(ctx context.Context, id string) error
}

// BrokerProviderPatch encodes "fields the caller intends to change" using the
// same pointer-vs-value semantics as ResourcePatch.
//
// ConfigData is a json.RawMessage so the admin layer round-trips the
// adapter-owned JSON byte-for-byte. The brokerproto adapter validates the
// schema at first vend.
type BrokerProviderPatch struct {
	Slug        *string
	DisplayName *string
	Protocol    *resource.Protocol
	ConfigData  *json.RawMessage
}
