package static

import (
	"context"

	"github.com/authplane/authserver/internal/ports/output"
)

// SessionSecretProvider is the default output.SessionSecretProvider: it returns
// the secret captured at construction for every call, with no lock or copy, so
// the session-cookie hot path stays allocation-free. Callers MUST NOT mutate the
// returned slice. The minimum secret length is enforced by config validation
// (config.Validate requires >=16 characters), not here, so a misconfigured
// secret surfaces as a clean config error rather than a constructor panic. Wired
// in cmd/ and injected via public.Deps.SessionSecretProvider; an alternative
// provider can source the secret per deployment.
type SessionSecretProvider struct {
	secret []byte
}

var _ output.SessionSecretProvider = (*SessionSecretProvider)(nil)

// NewSessionSecretProvider captures the boot session secret.
func NewSessionSecretProvider(secret []byte) *SessionSecretProvider {
	return &SessionSecretProvider{secret: secret}
}

// Secret returns the captured secret. It never errors.
func (p *SessionSecretProvider) Secret(context.Context) ([]byte, error) {
	return p.secret, nil
}
