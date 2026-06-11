package output

import (
	"context"
	"time"
)

// DPoPNonceStore manages DPoP proof JTI replay detection and server-issued nonces.
// Used by the token endpoint and resource server to validate DPoP proofs per RFC 9449.
type DPoPNonceStore interface {
	// ConsumeJTI records a DPoP proof JTI with an expiry time.
	// Returns domain.ErrDPoPReplay if the JTI has already been consumed.
	ConsumeJTI(ctx context.Context, jti string, expiry time.Time) error

	// IssueNonce generates and stores a server nonce with the given TTL.
	// Returns the nonce string.
	IssueNonce(ctx context.Context, ttl time.Duration) (string, error)

	// ValidateNonce checks that a nonce exists and has not expired.
	// Returns an error if the nonce is invalid or expired.
	ValidateNonce(ctx context.Context, nonce string) error

	// PurgeExpired removes expired JTIs and nonces from storage.
	PurgeExpired(ctx context.Context) error
}
