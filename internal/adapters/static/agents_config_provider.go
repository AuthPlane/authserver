package static

import (
	"context"

	"github.com/authplane/authserver/internal/ports/output"
)

// AgentsConfigProvider returns a fixed agent-identity config captured at
// construction. It performs no I/O.
type AgentsConfigProvider struct {
	cfg output.AgentsConfig
}

// NewAgentsConfigProvider captures the boot-time config.
func NewAgentsConfigProvider(cfg output.AgentsConfig) *AgentsConfigProvider {
	return &AgentsConfigProvider{cfg: cfg}
}

// Config returns the captured config.
func (p *AgentsConfigProvider) Config(_ context.Context) (output.AgentsConfig, error) {
	return p.cfg, nil
}

var _ output.AgentsConfigProvider = (*AgentsConfigProvider)(nil)
