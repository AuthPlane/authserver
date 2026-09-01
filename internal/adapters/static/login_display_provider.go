package static

import (
	"context"

	"github.com/authplane/authserver/internal/config"
	"github.com/authplane/authserver/internal/ports/output"
)

// LoginDisplayProvider is the captured-at-construction adapter for
// output.LoginDisplayProvider. It projects the two login fields of
// config.OIDCConfig — the OIDC button label and the local-login switch —
// into output.LoginDisplay at construction and returns that projection on
// every LoginDisplay call, ignoring context.
type LoginDisplayProvider struct {
	out output.LoginDisplay
}

// NewLoginDisplayProvider constructs a LoginDisplayProvider that projects
// the login fields of cfg (DisplayName, ShowLocalLogin) into
// output.LoginDisplay. Note that the zero value of config.OIDCConfig has
// ShowLocalLogin=false, which disables local password login; the true
// default lives in config.DefaultConfig().
func NewLoginDisplayProvider(cfg config.OIDCConfig) *LoginDisplayProvider {
	return &LoginDisplayProvider{
		out: output.LoginDisplay{
			DisplayName:    cfg.DisplayName,
			ShowLocalLogin: cfg.ShowLocalLogin,
		},
	}
}

// LoginDisplay returns the captured output.LoginDisplay and a nil error,
// regardless of ctx. The captured-at-construction strategy has no I/O and
// therefore no failure mode.
func (p *LoginDisplayProvider) LoginDisplay(_ context.Context) (output.LoginDisplay, error) {
	return p.out, nil
}

// Compile-time conformance check.
var _ output.LoginDisplayProvider = (*LoginDisplayProvider)(nil)
