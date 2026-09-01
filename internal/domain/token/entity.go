// Package token contains the Family and RefreshToken domain entities.
// Family groups all refresh tokens from a single authorization grant.
// Reuse of a consumed refresh token triggers family-wide revocation (theft detection).
package token

import "time"

// FamilyStatus represents the lifecycle state of a token family.
type FamilyStatus string

// Family status values.
const (
	FamilyActive  FamilyStatus = "active"
	FamilyRevoked FamilyStatus = "revoked"
)

// Family groups refresh tokens from a single authorization.
// If any consumed token is reused, the entire family is revoked.
type Family struct {
	ID        string
	ClientID  string
	UserID    string
	Scope     string // space-separated scopes
	Resource  string // RFC 8707 resource → JWT aud
	Status    FamilyStatus
	CreatedAt time.Time
	RevokedAt *time.Time

	// AuthSessionID is the AuthSession the family was born from. Empty when
	// unknown — rows created before migration 003 have no link, and nothing
	// backfills them. The code-reuse revocation path reads it to find which
	// family a replayed authorization code produced.
	AuthSessionID string
}

// IsActive reports whether the family is active (not revoked).
func (f *Family) IsActive() bool {
	return f.Status == FamilyActive
}

// Revoke marks the entire family as revoked. All tokens in the family become invalid.
func (f *Family) Revoke() {
	f.Status = FamilyRevoked
	now := time.Now().UTC()
	f.RevokedAt = &now
}

// RefreshToken represents a single refresh token within a family.
// Tokens are stored hashed (SHA-256). Each use rotates to a new token.
type RefreshToken struct {
	ID         string
	FamilyID   string
	TokenHash  string // SHA-256 of the plaintext token
	ExpiresAt  time.Time
	ConsumedAt *time.Time
	CreatedAt  time.Time
}

// IsExpired reports whether the refresh token has expired.
func (t *RefreshToken) IsExpired() bool {
	return time.Now().UTC().After(t.ExpiresAt)
}

// IsConsumed reports whether this token has already been used for rotation.
func (t *RefreshToken) IsConsumed() bool {
	return t.ConsumedAt != nil
}

// Consume marks the token as used. Returns an error if already consumed.
// A consumed token being presented again indicates theft — the caller must
// revoke the entire family.
func (t *RefreshToken) Consume() error {
	if t.ConsumedAt != nil {
		return ErrAlreadyConsumed
	}
	now := time.Now().UTC()
	t.ConsumedAt = &now
	return nil
}

// ErrAlreadyConsumed indicates a refresh token was presented after it was already
// consumed. This is a security event — the family should be revoked.
var ErrAlreadyConsumed = &consumedError{}

type consumedError struct{}

func (e *consumedError) Error() string { return "refresh token has already been consumed" }
