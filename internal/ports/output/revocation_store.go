package output

import (
	"context"
	"time"
)

// RevocationStore tracks revoked JWT token IDs (JTI blacklist)
// and maps JTIs to token families for bulk revocation.
type RevocationStore interface {
	// TrackJTI records that a JTI was issued for a given family with its expiry.
	TrackJTI(ctx context.Context, jti, familyID string, expiresAt time.Time) error

	// RevokeByFamily adds all JTIs belonging to a family to the blacklist.
	RevokeByFamily(ctx context.Context, familyID string) error

	// RevokeJTI adds a single JTI to the blacklist.
	RevokeJTI(ctx context.Context, jti string) error

	// IsRevoked checks if a JTI is in the blacklist.
	IsRevoked(ctx context.Context, jti string) (bool, error)

	// PurgeExpired removes expired JTI tracking and blacklist entries.
	PurgeExpired(ctx context.Context) (int64, error)
}
