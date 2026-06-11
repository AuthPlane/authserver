package input

import (
	"context"

	"github.com/authplane/authserver/internal/domain/resource"
)

// ResourceAdminPort exposes administrative CRUD over the unified resources
// table (the design §6 / the data model). The driving adapter is
// /admin/resources (api/admin/resources.go); the driven adapter is the
// ResourceAdminService over output.ResourceStore + output.BrokerProviderStore
// + output.ClientStore.
type ResourceAdminPort interface {
	// List returns Resources matching the filter. Empty filter fields are
	// wildcards.
	List(ctx context.Context, filter ResourceFilter) ([]*resource.Resource, error)

	// GetByID returns the Resource with the given id, or
	// domain.ErrResourceNotFound.
	GetByID(ctx context.Context, id string) (*resource.Resource, error)

	// GetBySlug returns the Resource with the given slug, or
	// domain.ErrResourceNotFound. Used by the seed-loop idempotency check
	// (cmd/authserver/serve.go) so YAML edits referencing existing rows by
	// slug skip cleanly without surfacing benign UNIQUE-constraint errors.
	GetBySlug(ctx context.Context, slug string) (*resource.Resource, error)

	// Create inserts a new Resource. The service generates the id and
	// timestamps; callers MUST leave Resource.ID empty (caller-supplied ids
	// are rejected).
	Create(ctx context.Context, r *resource.Resource) error

	// Patch applies a partial update per ResourcePatch semantics and returns
	// the post-patch Resource. Nil-pointer fields are LEFT UNCHANGED;
	// non-nil fields are REPLACED in full.
	Patch(ctx context.Context, id string, patch ResourcePatch) (*resource.Resource, error)

	// Delete removes the Resource by id. Returns
	// domain.ErrResourceHasReferences when an FK block prevents the row
	// from being removed (consent_grants, issuances), or
	// domain.ErrResourceNotFound on miss.
	Delete(ctx context.Context, id string) error

	// DeleteWithCascade removes the Resource and (when cascade=true) any
	// fronting_links rows that reference it as source or target. The
	// returned slice carries the dependent links that were affected — empty
	// when cascade=false and there were no dependents, populated when
	// cascade=true so callers can surface what was removed in audit/UI.
	//
	// Returns domain.ErrResourceHasFrontingLinks (CodeConflict) when
	// cascade=false and dependents exist; the dependents slice is also
	// populated in that case so the HTTP layer can include the list in the
	// 409 body..
	DeleteWithCascade(ctx context.Context, id string, cascade bool) (dependents []*resource.FrontingLink, err error)

	// AddAllowedClient idempotently adds clientID to the resource's
	// policy.exchange.allowed_client_ids and returns the post-mutation list.
	// The lookup is by slug (/ ergonomics). Returns
	// domain.ErrResourceNotFound on slug miss; domain.NewInvalidRequestError
	// if clientID is empty or does not resolve to a known client. Adding a
	// client already in the list is a no-op (returns the existing list).
	AddAllowedClient(ctx context.Context, slug, clientID string) ([]string, error)

	// RemoveAllowedClient idempotently removes clientID from the resource's
	// policy.exchange.allowed_client_ids and returns the post-mutation list.
	// Removing a client not in the list is a no-op. Returns
	// domain.ErrResourceNotFound on slug miss.
	RemoveAllowedClient(ctx context.Context, slug, clientID string) ([]string, error)

	// ListAllowedClients returns the resource's
	// policy.exchange.allowed_client_ids. Returns domain.ErrResourceNotFound
	// on slug miss. An empty list means "any client" per ExchangePolicy
	// semantics (resource.go).
	ListAllowedClients(ctx context.Context, slug string) ([]string, error)

	// AddAllowedReturnURL idempotently adds returnURL to the resource's
	// policy.connect.allowed_return_urls and returns the post-mutation list.
	// Returns domain.ErrResourceNotFound on slug miss;
	// domain.NewInvalidRequestError if returnURL is empty or malformed, or
	// if the resource is Mint (Connect policy is broker-only — the design §6).
	AddAllowedReturnURL(ctx context.Context, slug, returnURL string) ([]string, error)

	// RemoveAllowedReturnURL idempotently removes returnURL from the
	// resource's policy.connect.allowed_return_urls and returns the
	// post-mutation list. Returns domain.ErrResourceNotFound on slug miss
	// or domain.NewInvalidRequestError on Mint resources.
	RemoveAllowedReturnURL(ctx context.Context, slug, returnURL string) ([]string, error)

	// ListAllowedReturnURLs returns the resource's
	// policy.connect.allowed_return_urls. Returns
	// domain.ErrResourceNotFound on slug miss or
	// domain.NewInvalidRequestError on Mint resources (which carry no
	// Connect policy). An empty list means "no return URLs allowed" per
	// ConnectPolicy semantics.
	ListAllowedReturnURLs(ctx context.Context, slug string) ([]string, error)

	// AddRuntimeClientID idempotently adds clientID to the resource's
	// policy.runtime.client_ids and returns the post-mutation list. Validates
	// that clientID resolves to a known OAuth client. Returns
	// domain.ErrResourceNotFound on slug miss; domain.NewInvalidRequestError
	// if clientID is empty or does not resolve to a known client..
	AddRuntimeClientID(ctx context.Context, slug, clientID string) ([]string, error)

	// RemoveRuntimeClientID idempotently removes clientID from the resource's
	// policy.runtime.client_ids and returns the post-mutation list. Removing
	// a client not in the list is a no-op. Returns domain.ErrResourceNotFound
	// on slug miss..
	RemoveRuntimeClientID(ctx context.Context, slug, clientID string) ([]string, error)

	// ListRuntimeClientIDs returns the resource's policy.runtime.client_ids.
	// Returns domain.ErrResourceNotFound on slug miss. An empty list means
	// "no client may act as this Resource" — RuntimePolicy is default-deny,
	// distinct from the permissive default of ExchangePolicy..
	ListRuntimeClientIDs(ctx context.Context, slug string) ([]string, error)
}

// ResourceFilter narrows ResourceAdminPort.List. Empty fields mean "any".
// Mirrors output.ResourceFilter so the API layer never imports
// internal/ports/output.
type ResourceFilter struct {
	BackendKind      resource.BackendKind
	BrokerProviderID string
	Limit            int
	Offset           int
}

// ResourcePatch encodes "fields the caller intends to change". Nil-pointer
// fields are LEFT UNCHANGED. Non-nil fields are REPLACED in full (no inner
// merging). To wipe a field, send the explicit empty value:
// `Scopes: &emptySlice`, `Policy: &resource.Policy{}` etc.
//
// The pointer-vs-value distinction is the load-bearing security guard for
// `policy.exchange.allowed_client_ids`: omitting `policy` from the request
// body keeps the existing allowlist; sending `policy: {}` widens it to
// permissive. Operators must opt in to widening explicitly.
type ResourcePatch struct {
	Slug             *string
	URI              *string
	BackendKind      *resource.BackendKind
	BrokerProviderID *string
	DisplayName      *string
	Scopes           *[]resource.Scope
	Policy           *resource.Policy
}
