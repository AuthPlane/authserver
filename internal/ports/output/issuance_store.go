package output

import (
	"context"
	"time"

	"github.com/authplane/authserver/internal/domain/resource"
)

// IssuanceStore is the unified per-token audit log for both Mint and
// Broker issuances. One row per access token the AS hands out; rows are
// immutable except for the revoked_at column (set by Revoke /
// RevokeFamily). See the architecture doc and the data model
//
// Single-audience: each issuance targets exactly one Resource via
// ResourceID (v4.1). AgentID and AgentChain mirror the JWT claim shape
// from internal/services/agent_identity.go and are persisted on every
// issuance — Mint or Broker — so chain-origin forensics work end-to-end
// even though Broker tokens cannot carry these claims on the wire.
//
// Until  retires machine_tokens / revocation_store, this store
// runs in parallel with those legacy tables; it does not supersede them
// at runtime in this increment.
type IssuanceStore interface {
	// Insert writes a new issuance row. Caller is responsible for
	// uuid-shaped IDs and for populating AgentID / AgentChain when the
	// originating request has an Agent claim. Round-trips byte-exactly:
	// the agent_chain column persists the same []string the service
	// layer attaches to the JWT.
	Insert(ctx context.Context, i *resource.Issuance) error

	// GetByID returns the issuance whose id matches the given value, or
	// (nil, nil) when no row matches. Used by the admin path-keyed
	// GET /admin/issuances/{id}. The id field is the
	// issuance UUID; Broker issuances (whose jti is empty per )
	// remain addressable through this lookup. The (nil, nil) miss
	// contract is consistent with GetByJTI; the IssuanceAdminService
	// translates a nil result into domain.ErrIssuanceNotFound for the
	// admin 404 path.
	GetByID(ctx context.Context, id string) (*resource.Issuance, error)

	// GetByJTI returns the issuance whose jti matches the given value,
	// or (nil, nil) when no row matches. Used by /oauth/introspect for
	// revocation checks; only Mint issuances populate jti so this
	// implicitly filters Broker rows out.
	GetByJTI(ctx context.Context, jti string) (*resource.Issuance, error)

	// Revoke sets revoked_at on the row with the given id. Idempotent:
	// returns nil if no row matches. Used by single-token admin revoke
	// and refresh-token theft detection.
	Revoke(ctx context.Context, id string) (e error)

	// RevokeFamily marks every active Mint issuance for the
	// (subject_user_id, client_id, resource_id) tuple as revoked and
	// returns the count of rows updated. Filtered to backend_kind =
	// 'mint' — Broker issuances are not revocable by the AS. Used by
	// the consent revocation cascade.
	RevokeFamily(ctx context.Context, userID, clientID, resourceID string) (int, error)

	// ListForUser returns issuances for the user issued at or after
	// since, newest first. Powers the user-facing "what tokens have I
	// authorized" view. Backed by the (subject_user_id, issued_at DESC)
	// index.
	ListForUser(ctx context.Context, userID string, since time.Time) ([]*resource.Issuance, error)

	// ListForActor returns issuances where client_id matches and
	// issued_at >= since, newest first. v4 actor-based forensics
	// ("every issuance where Test MCP was the actor in the last hour").
	// Backed by the (client_id, issued_at DESC) index added in v4.
	ListForActor(ctx context.Context, clientID string, since time.Time) ([]*resource.Issuance, error)

	// ListForResource returns issuances where resource_id matches and
	// issued_at >= since, newest first. Powers the admin
	// Grants → Issuances cross-link — operators pivot from a
	// (user, client, resource) grant tuple onto the matching audit rows.
	// Backed by the (resource_id, issued_at DESC) index from migration 001.
	ListForResource(ctx context.Context, resourceID string, since time.Time) ([]*resource.Issuance, error)

	// PurgeExpired deletes issuances past the retention window per
	// the data model Q10. The predicate is:
	//   (revoked_at IS NULL AND expires_at < before)
	//   OR (revoked_at IS NOT NULL AND revoked_at < before)
	// Returns the number of rows deleted. Wired to the retention
	// runner in  — default window 90 days, configurable via
	// cfg.Issuances.RetentionDays.
	PurgeExpired(ctx context.Context, before time.Time) (int, error)
}
