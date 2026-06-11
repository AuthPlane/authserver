package input

import (
	"context"
	"time"

	"github.com/authplane/authserver/internal/domain/resource"
)

// IssuanceAdminPort exposes the per-token forensic + admin-revoke surface
// over output.IssuanceStore (the design §6 / the data model / §6 Q6 + Q7).
//
// There is no paginated ListAll: issuance volume scales linearly with
// traffic, and admins normally filter by user, actor, or jti. The list
// endpoint requires exactly one of those three; jti is a point-query
// included on the list endpoint (rather than as a separate path) so
// the operator can hand a leaked jti to the same form they use for
// windowed queries.
type IssuanceAdminPort interface {
	// ListForUser returns issuances for the user issued at or after
	// since, newest first. Backed by the (subject_user_id, issued_at
	// DESC) index.
	ListForUser(ctx context.Context, userID string, since time.Time) ([]*resource.Issuance, error)

	// ListForActor returns issuances where client_id matches and
	// issued_at >= since, newest first. Backed by the (client_id,
	// issued_at DESC) index added in v4.
	ListForActor(ctx context.Context, clientID string, since time.Time) ([]*resource.Issuance, error)

	// ListForResource returns issuances where resource_id matches and
	// issued_at >= since, newest first. Powers the admin
	// Grants → Issuances cross-link. Backed by the (resource_id,
	// issued_at DESC) index from migration 001.
	ListForResource(ctx context.Context, resourceID string, since time.Time) ([]*resource.Issuance, error)

	// GetByID returns the issuance with the given id (issuance UUID), or
	// domain.ErrIssuanceNotFound when no row matches.
	GetByID(ctx context.Context, id string) (*resource.Issuance, error)

	// GetByJTI returns the issuance whose jti matches, or (nil, nil) on
	// miss. Mirrors the storage contract — handler code wraps the
	// (nil, nil) into list-semantics (empty array, not 404) at the
	// /admin/issuances?jti=… endpoint.
	GetByJTI(ctx context.Context, jti string) (*resource.Issuance, error)

	// Revoke soft-deletes the issuance row by id (sets revoked_at).
	// Idempotent. The introspection endpoint already short-circuits on
	// revoked_at != null so the next /oauth/introspect reflects this
	// immediately.
	Revoke(ctx context.Context, id string) error
}
