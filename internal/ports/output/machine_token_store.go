package output

import (
	"context"

	"github.com/authplane/authserver/internal/domain/token"
)

// MachineTokenStore persists machine tokens issued via the client_credentials grant.
// Machine tokens are stored by JTI for introspection and revocation.
type MachineTokenStore interface {
	// Save persists a machine token record.
	Save(ctx context.Context, mt token.MachineToken) error

	// GetByJTI returns a machine token by its JTI.
	// Returns nil, nil if not found.
	GetByJTI(ctx context.Context, jti string) (*token.MachineToken, error)

	// Revoke marks a machine token as revoked by JTI.
	Revoke(ctx context.Context, jti string) error

	// PurgeExpired removes expired machine tokens from storage.
	PurgeExpired(ctx context.Context) error

	// --- Admin queries ---

	// List returns machine tokens matching the filter.
	List(ctx context.Context, filter MachineTokenFilter) ([]token.MachineToken, int, error)

	// RevokeByClientID revokes all active machine tokens for a client. Returns count.
	RevokeByClientID(ctx context.Context, clientID string) (int, error)

	// CountIssuedSince returns the number of machine tokens issued since the given unix timestamp.
	CountIssuedSince(ctx context.Context, since int64) (int, error)

	// CountRevokedSince returns the number of machine tokens revoked since the given unix timestamp.
	CountRevokedSince(ctx context.Context, since int64) (int, error)
}

// MachineTokenFilter constrains machine token listing.
type MachineTokenFilter struct {
	ClientID string
	Limit    int
	Offset   int
}
