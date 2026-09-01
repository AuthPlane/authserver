package static

import (
	"context"

	"github.com/authplane/authserver/internal/ports/output"
)

// StateCodecConfigProvider returns a fixed HMAC signing key captured at
// construction. It performs no I/O and returns the same value on every call.
type StateCodecConfigProvider struct {
	cfg output.StateCodecConfig
}

// NewStateCodecConfigProvider captures a fixed signing key. It panics on an
// empty key so operator misconfiguration surfaces at boot rather than the
// first OIDC callback, and defensively copies the key so the caller's buffer
// cannot mutate it.
func NewStateCodecConfigProvider(key []byte) *StateCodecConfigProvider {
	if len(key) == 0 {
		panic("static.NewStateCodecConfigProvider: key must be non-empty")
	}
	k := make([]byte, len(key))
	copy(k, key)
	return &StateCodecConfigProvider{cfg: output.StateCodecConfig{Key: k}}
}

// Config returns the captured signing material.
func (p *StateCodecConfigProvider) Config(_ context.Context) (output.StateCodecConfig, error) {
	return p.cfg, nil
}

var _ output.StateCodecConfigProvider = (*StateCodecConfigProvider)(nil)
