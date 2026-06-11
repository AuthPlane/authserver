package output

import (
	"context"
	"time"
)

// AssertionJTIStore manages single-use enforcement for ID-JAG assertion JTIs.
type AssertionJTIStore interface {
	// ConsumeJTI marks a JTI as used. Returns domain.ErrAssertionReplay if already consumed.
	ConsumeJTI(ctx context.Context, jti string, expiry time.Time) error

	// PurgeExpired removes expired JTI records from storage.
	PurgeExpired(ctx context.Context) error
}
