package static

import (
	"context"

	"github.com/authplane/authserver/internal/ports/output"
)

// XAAConfigProvider returns a fixed XAA config captured at construction.
// It performs no I/O.
type XAAConfigProvider struct {
	cfg output.XAAConfig
}

// NewXAAConfigProvider captures the boot-time config.
func NewXAAConfigProvider(cfg output.XAAConfig) *XAAConfigProvider {
	return &XAAConfigProvider{cfg: cfg}
}

// Config returns the captured config.
func (p *XAAConfigProvider) Config(_ context.Context) (output.XAAConfig, error) {
	return p.cfg, nil
}

var _ output.XAAConfigProvider = (*XAAConfigProvider)(nil)
