package output

import (
	"context"

	"github.com/authplane/authserver/internal/domain/token"
)

// TokenStore persists token families and refresh tokens.
// Consume operations MUST be atomic (UPDATE ... WHERE consumed_at IS NULL).
type TokenStore interface {
	// --- Token Families ---

	// CreateFamily stores a new token family.
	CreateFamily(ctx context.Context, f *token.Family) error

	// GetFamily returns a token family by ID.
	GetFamily(ctx context.Context, id string) (*token.Family, error)

	// RevokeFamily atomically revokes a family and all its refresh tokens.
	RevokeFamily(ctx context.Context, familyID string) error

	// --- Refresh Tokens ---

	// CreateRefreshToken stores a new refresh token.
	CreateRefreshToken(ctx context.Context, rt *token.RefreshToken) error

	// GetRefreshTokenByHash looks up a refresh token by its SHA-256 hash.
	GetRefreshTokenByHash(ctx context.Context, hash string) (*token.RefreshToken, error)

	// ConsumeRefreshToken atomically marks a refresh token as consumed.
	// Returns the consumed token on success.
	// If already consumed (reuse), returns ErrRefreshTokenReused.
	ConsumeRefreshToken(ctx context.Context, id string) (*token.RefreshToken, error)

	// PurgeExpired removes refresh tokens whose expires_at is in the past.
	// Deletes both consumed and unconsumed expired rows, since an expired
	// refresh token can no longer be used in any flow. Returns the number of
	// rows deleted.
	PurgeExpired(ctx context.Context) (int64, error)

	// CountIssuedSince returns the number of token families created since the given time.
	CountIssuedSince(ctx context.Context, since int64) (int, error)

	// CountRevokedSince returns the number of families revoked since the given time.
	CountRevokedSince(ctx context.Context, since int64) (int, error)

	// --- Admin queries ---

	// ListFamilies returns token families matching the filter.
	ListFamilies(ctx context.Context, filter FamilyFilter) ([]token.Family, int, error)

	// CountActiveByClientID returns the number of active families for a client.
	CountActiveByClientID(ctx context.Context, clientID string) (int, error)

	// RevokeByClientID revokes all active families for a client. Returns count revoked.
	RevokeByClientID(ctx context.Context, clientID string) (int, error)

	// RevokeByUserID revokes all active families for a user. Returns count revoked.
	RevokeByUserID(ctx context.Context, userID string) (int, error)
}

// FamilyFilter constrains token family listing.
type FamilyFilter struct {
	ClientID string
	UserID   string
	Status   string // "active", "revoked", or "" for all
	Limit    int
	Offset   int
}
