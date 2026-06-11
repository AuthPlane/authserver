package output

import (
	"context"

	"github.com/go-jose/go-jose/v4"
)

// IDPJWKSCache provides cached JWKS retrieval for trusted IdP issuers.
type IDPJWKSCache interface {
	// GetKeys returns the JWKS for an IdP issuer.
	// If not cached or expired, fetches from the IdP's jwks_uri.
	GetKeys(ctx context.Context, issuer string) (*jose.JSONWebKeySet, error)

	// InvalidateCache forces re-fetch on next GetKeys call for the given issuer.
	InvalidateCache(ctx context.Context, issuer string) error
}
