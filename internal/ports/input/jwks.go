package input

import "context"

// JWKSPort provides JWKS document operations for the HTTP layer.
type JWKSPort interface {
	// BuildJWKSDocument returns the JWKS document as serialized JSON bytes.
	BuildJWKSDocument(ctx context.Context) ([]byte, error)
}
