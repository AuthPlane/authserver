package static

import (
	"context"

	"github.com/authplane/authserver/internal/ports/output"
)

// DPoPConfigProvider returns a fixed DPoP config captured at construction.
// It performs no I/O.
type DPoPConfigProvider struct {
	cfg output.DPoPConfig
}

// NewDPoPConfigProvider captures the boot-time config.
func NewDPoPConfigProvider(cfg output.DPoPConfig) *DPoPConfigProvider {
	return &DPoPConfigProvider{cfg: cfg}
}

// Config returns the captured config.
func (p *DPoPConfigProvider) Config(_ context.Context) (output.DPoPConfig, error) {
	return p.cfg, nil
}

var _ output.DPoPConfigProvider = (*DPoPConfigProvider)(nil)
