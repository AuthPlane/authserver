package static

import (
	"context"

	"github.com/authplane/authserver/internal/ports/output"
)

// TokenExchangeConfigProvider returns a fixed token-exchange config captured at
// construction. It performs no I/O.
type TokenExchangeConfigProvider struct {
	cfg output.TokenExchangeConfig
}

// NewTokenExchangeConfigProvider captures the boot-time config.
func NewTokenExchangeConfigProvider(cfg output.TokenExchangeConfig) *TokenExchangeConfigProvider {
	return &TokenExchangeConfigProvider{cfg: cfg}
}

// Config returns the captured config.
func (p *TokenExchangeConfigProvider) Config(_ context.Context) (output.TokenExchangeConfig, error) {
	return p.cfg, nil
}

var _ output.TokenExchangeConfigProvider = (*TokenExchangeConfigProvider)(nil)
