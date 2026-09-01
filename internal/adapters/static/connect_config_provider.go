package static

import (
	"context"

	"github.com/authplane/authserver/internal/ports/output"
)

// ConnectConfigProvider returns a fixed connect-flow config captured at
// construction. It defensively copies the return-URL allowlist and does no I/O.
type ConnectConfigProvider struct {
	cfg output.ConnectConfig
}

// NewConnectConfigProvider captures the boot-time config, copying the slice so
// the caller's buffer cannot mutate it. Nil is preserved as nil.
func NewConnectConfigProvider(cfg output.ConnectConfig) *ConnectConfigProvider {
	cfg.AllowedReturnURLs = copyStrings(cfg.AllowedReturnURLs)
	return &ConnectConfigProvider{cfg: cfg}
}

// Config returns the captured config.
func (p *ConnectConfigProvider) Config(_ context.Context) (output.ConnectConfig, error) {
	return p.cfg, nil
}

// copyStrings returns a defensive copy of s; nil is preserved as nil.
func copyStrings(s []string) []string {
	if s == nil {
		return nil
	}
	out := make([]string, len(s))
	copy(out, s)
	return out
}

var _ output.ConnectConfigProvider = (*ConnectConfigProvider)(nil)
