package output

import (
	"context"
	"time"
)

// TokenExchangeConfig is the per-request RFC 8693 token-exchange config.
type TokenExchangeConfig struct {
	Enabled           bool
	AllowSelfExchange bool
	MaxChainDepth     int
	TokenExpiry       time.Duration
}

// TokenExchangeConfigProvider supplies token-exchange config for a request.
type TokenExchangeConfigProvider interface {
	Config(ctx context.Context) (TokenExchangeConfig, error)
}
