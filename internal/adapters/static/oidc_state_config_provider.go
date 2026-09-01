package static

import (
	"context"

	"github.com/authplane/authserver/internal/ports/output"
)

// OIDCStateConfigProvider returns a fixed OIDC state-cookie policy captured at
// construction. It performs no I/O.
type OIDCStateConfigProvider struct {
	cfg output.OIDCStateConfig
}

// NewOIDCStateConfigProvider captures the boot-time config.
func NewOIDCStateConfigProvider(cfg output.OIDCStateConfig) *OIDCStateConfigProvider {
	return &OIDCStateConfigProvider{cfg: cfg}
}

// Config returns the captured config.
func (p *OIDCStateConfigProvider) Config(_ context.Context) (output.OIDCStateConfig, error) {
	return p.cfg, nil
}

var _ output.OIDCStateConfigProvider = (*OIDCStateConfigProvider)(nil)
