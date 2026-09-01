package static

import (
	"context"

	"github.com/authplane/authserver/internal/ports/output"
)

// AuditQueryConfigProvider returns a fixed audit-feed lookback bound captured at
// construction. It performs no I/O.
type AuditQueryConfigProvider struct {
	cfg output.AuditQueryConfig
}

// NewAuditQueryConfigProvider captures the boot-time config.
func NewAuditQueryConfigProvider(cfg output.AuditQueryConfig) *AuditQueryConfigProvider {
	return &AuditQueryConfigProvider{cfg: cfg}
}

// Config returns the captured config.
func (p *AuditQueryConfigProvider) Config(_ context.Context) (output.AuditQueryConfig, error) {
	return p.cfg, nil
}

var _ output.AuditQueryConfigProvider = (*AuditQueryConfigProvider)(nil)
