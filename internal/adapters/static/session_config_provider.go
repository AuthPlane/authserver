package static

import (
	"context"

	"github.com/authplane/authserver/internal/ports/output"
)

// SessionConfigProvider returns a fixed session-cookie policy captured at
// construction. It performs no I/O.
type SessionConfigProvider struct {
	cfg output.SessionConfig
}

// NewSessionConfigProvider captures the boot-time config.
func NewSessionConfigProvider(cfg output.SessionConfig) *SessionConfigProvider {
	return &SessionConfigProvider{cfg: cfg}
}

// Config returns the captured config.
func (p *SessionConfigProvider) Config(_ context.Context) (output.SessionConfig, error) {
	return p.cfg, nil
}

var _ output.SessionConfigProvider = (*SessionConfigProvider)(nil)
