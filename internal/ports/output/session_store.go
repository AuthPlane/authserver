package output

import (
	"context"

	"github.com/authplane/authserver/internal/domain/session"
)

// SessionStore persists authorization sessions (auth code state).
type SessionStore interface {
	// Create stores a new auth session.
	Create(ctx context.Context, s *session.AuthSession) error

	// GetByID returns a session by its ID.
	GetByID(ctx context.Context, id string) (*session.AuthSession, error)

	// ConsumeByCodeHash atomically marks the session as consumed.
	// Uses: UPDATE ... WHERE code_hash = ? AND consumed_at IS NULL RETURNING *
	// If already consumed, returns ErrCodeConsumed.
	ConsumeByCodeHash(ctx context.Context, codeHash string) (*session.AuthSession, error)

	// UpdateCodeHashAndScope sets the code_hash and (optionally narrowed) scope
	// on an existing session. Used after consent is granted to finalize the
	// authorization code with only the user-approved scopes.
	UpdateCodeHashAndScope(ctx context.Context, sessionID, codeHash, scope string) error

	// Delete removes a specific session by ID. Used by DenyConsent so a
	// denied authorization session cannot be re-prompted and approved
	// later while still within its TTL. A missing session is not an
	// error — the postcondition is "session is not present."
	Delete(ctx context.Context, id string) error

	// DeleteExpired removes sessions that have expired.
	DeleteExpired(ctx context.Context) (int64, error)
}
