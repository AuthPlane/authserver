package output

import (
	"context"

	"github.com/authplane/authserver/internal/domain/resource"
)

// ConsentGrantStore persists per-MCP user→Agent authorizations against
// Mint resources. See the architecture doc / §5.4 and the data model
// / §3.1 / §6 Q2.
//
// ClientID is always the Agent (the Client the user explicitly consented
// to); MCPs that act as the actor at /oauth/token never appear here. The
// adapter persists whatever resource_id it receives — the Mint-only
// invariant is enforced by the service layer, not at the storage
// tier; the SQL FK only guarantees the resource exists. This is the
// only store and the only `consent_grants` table.
type ConsentGrantStore interface {
	// Get returns the active grant for (user, client, resource), or
	// (nil, nil) when no row matches. Filter clause:
	// WHERE revoked_at IS NULL. Mirrors the legacy ConsentStore.Get
	// not-found contract for v0.1.0-rc1 simplicity.
	Get(ctx context.Context, userID, clientID, resourceID string) (*resource.ConsentGrant, error)

	// GetByID returns the grant with the given id (active or revoked),
	// or (nil, nil) when no row matches. Used by the admin revocation
	// cascade to recover the (user, client, resource)
	// triple needed for IssuanceStore.RevokeFamily — see
	// the data model Does NOT filter on revoked_at: the cascade
	// targets the original grant's triple regardless of current state.
	GetByID(ctx context.Context, id string) (*resource.ConsentGrant, error)

	// Upsert inserts a new grant or updates the existing one keyed on
	// (user_id, client_id, resource_id) via INSERT … ON CONFLICT DO
	// UPDATE. A re-grant after revocation re-activates the same row
	// (clears revoked_at) per the data model — row-history is not
	// maintained at the storage tier (audit_events covers it).
	Upsert(ctx context.Context, g *resource.ConsentGrant) error

	// Revoke sets revoked_at on the row with the given id. Idempotent:
	// returns nil if no row matches (the integration suite does not
	// assert a not-found sentinel).
	Revoke(ctx context.Context, id string) error

	// ListForUser returns every grant for the user — both active and
	// revoked — ordered by created_at descending. The history view
	// powers the admin/user-self-service "what have I authorized" page.
	ListForUser(ctx context.Context, userID string) ([]*resource.ConsentGrant, error)
}
