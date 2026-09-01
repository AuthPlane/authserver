package static

import (
	"context"

	"github.com/authplane/authserver/internal/ports/output"
)

// CIMDConfigProvider returns a fixed CIMD config captured at construction.
// It performs no I/O.
type CIMDConfigProvider struct {
	cfg output.CIMDConfig
}

// NewCIMDConfigProvider captures the boot-time config.
func NewCIMDConfigProvider(cfg output.CIMDConfig) *CIMDConfigProvider {
	return &CIMDConfigProvider{cfg: cfg}
}

// Config returns the captured config.
func (p *CIMDConfigProvider) Config(_ context.Context) (output.CIMDConfig, error) {
	return p.cfg, nil
}

var _ output.CIMDConfigProvider = (*CIMDConfigProvider)(nil)
