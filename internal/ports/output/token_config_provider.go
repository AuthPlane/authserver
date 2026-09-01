package output

import (
	"context"
	"time"
)

// TokenConfig is the per-request token-lifetime config.
type TokenConfig struct {
	AccessTokenExpiry  time.Duration // TTL for issued access tokens (RFC 9068)
	RefreshTokenExpiry time.Duration // TTL for issued refresh tokens
}

// TokenConfigProvider supplies token-lifetime config for a request.
type TokenConfigProvider interface {
	Config(ctx context.Context) (TokenConfig, error)
}
