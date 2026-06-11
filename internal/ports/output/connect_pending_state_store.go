package output

import (
	"context"
	"time"

	"github.com/authplane/authserver/internal/domain/resource"
)

// ConnectPendingStateStore is the ephemeral PKCE state store for the
// upstream Broker connect dance. One row per /connect request, consumed
// once on /connect/callback and then deleted. See the architecture doc
// and the data model.
//
// connect_pending_states references a BrokerProvider (provider_id) and
// a Resource (resource_id) by FK. UserID is intentionally NOT
// foreign-keyed to users(id) — the connect flow may run before a user
// is fully registered in OIDC-federated bootstrap (rare but supported).
type ConnectPendingStateStore interface {
	// Insert persists a new pending-state row. ID is the opaque state
	// token returned to the upstream; the caller must derive an
	// HMAC-validated value before passing it on the redirect. Scopes
	// is the requested fine-scope set persisted verbatim for the
	// callback to validate against the consent-time set.
	Insert(ctx context.Context, s *resource.ConnectPendingState) error

	// Consume atomically reads the row with the given id and deletes
	// it in the same transaction (DELETE ... RETURNING on backends
	// that support it; SELECT-then-DELETE inside one tx otherwise).
	// Returns domain.ErrPendingStateNotFound when no row matches —
	// either because the id is unknown, because expiry has passed,
	// or because a concurrent caller already consumed it. Single-use
	// semantics: a second Consume on the same id always returns the
	// sentinel.
	//
	// Expiry is filtered server-side; callers do not need to compare
	// against the clock before calling.
	Consume(ctx context.Context, id string) (*resource.ConnectPendingState, error)

	// PurgeExpired deletes rows whose expires_at is before the given
	// instant and returns the count removed.
	PurgeExpired(ctx context.Context, before time.Time) (int, error)
}
