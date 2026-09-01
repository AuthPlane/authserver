package static

import (
	"context"

	"github.com/authplane/authserver/internal/ports/output"
)

// OAuthConfigProvider returns a fixed OAuth behavior config captured at
// construction. It performs no I/O.
type OAuthConfigProvider struct {
	cfg output.OAuthConfig
}

// NewOAuthConfigProvider captures the boot-time config.
func NewOAuthConfigProvider(cfg output.OAuthConfig) *OAuthConfigProvider {
	return &OAuthConfigProvider{cfg: cfg}
}

// Config returns the captured config.
func (p *OAuthConfigProvider) Config(_ context.Context) (output.OAuthConfig, error) {
	return p.cfg, nil
}

var _ output.OAuthConfigProvider = (*OAuthConfigProvider)(nil)
