package static

import (
	"context"

	"github.com/authplane/authserver/internal/ports/output"
)

// ClientCredentialsConfigProvider returns a fixed client_credentials config
// captured at construction. It performs no I/O.
type ClientCredentialsConfigProvider struct {
	cfg output.ClientCredentialsConfig
}

// NewClientCredentialsConfigProvider captures the boot-time config.
func NewClientCredentialsConfigProvider(cfg output.ClientCredentialsConfig) *ClientCredentialsConfigProvider {
	return &ClientCredentialsConfigProvider{cfg: cfg}
}

// Config returns the captured config.
func (p *ClientCredentialsConfigProvider) Config(_ context.Context) (output.ClientCredentialsConfig, error) {
	return p.cfg, nil
}

var _ output.ClientCredentialsConfigProvider = (*ClientCredentialsConfigProvider)(nil)
