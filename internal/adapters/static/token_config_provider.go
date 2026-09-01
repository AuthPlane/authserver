package static

import (
	"context"

	"github.com/authplane/authserver/internal/ports/output"
)

// TokenConfigProvider returns a fixed token-lifetime config captured at
// construction. It performs no I/O.
type TokenConfigProvider struct {
	cfg output.TokenConfig
}

// NewTokenConfigProvider captures the boot-time config.
func NewTokenConfigProvider(cfg output.TokenConfig) *TokenConfigProvider {
	return &TokenConfigProvider{cfg: cfg}
}

// Config returns the captured config.
func (p *TokenConfigProvider) Config(_ context.Context) (output.TokenConfig, error) {
	return p.cfg, nil
}

var _ output.TokenConfigProvider = (*TokenConfigProvider)(nil)
