package input

import "context"

// RevocationPort handles token revocation (RFC 7009).
type RevocationPort interface {
	// RevokeToken revokes a token (access or refresh).
	// Always succeeds from the caller's perspective — unknown tokens are silently ignored.
	RevokeToken(ctx context.Context, req RevokeRequest) error
}

// RevokeRequest contains the parameters from POST /oauth/revoke.
type RevokeRequest struct {
	Token         string
	TokenTypeHint string // "access_token" or "refresh_token" (optional)
	ClientID      string
	ClientSecret  string // empty for public clients
}
