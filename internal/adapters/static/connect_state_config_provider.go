package static

import (
	"context"

	"github.com/authplane/authserver/internal/ports/output"
)

// ConnectStateConfigProvider returns a fixed HMAC signing key captured at
// construction. It performs no I/O and returns the same value on every call.
type ConnectStateConfigProvider struct {
	cfg output.ConnectStateConfig
}

// NewConnectStateConfigProvider captures a fixed signing key. It panics on an
// empty key so operator misconfiguration surfaces at boot rather than the
// first connect callback, and defensively copies the key so the caller's
// buffer cannot mutate it.
func NewConnectStateConfigProvider(key []byte) *ConnectStateConfigProvider {
	if len(key) == 0 {
		panic("static.NewConnectStateConfigProvider: key must be non-empty")
	}
	k := make([]byte, len(key))
	copy(k, key)
	return &ConnectStateConfigProvider{cfg: output.ConnectStateConfig{Key: k}}
}

// Config returns the captured signing material. It copies the key so a caller
// that mutates the returned slice cannot corrupt the provider's stored key.
func (p *ConnectStateConfigProvider) Config(_ context.Context) (output.ConnectStateConfig, error) {
	k := make([]byte, len(p.cfg.Key))
	copy(k, p.cfg.Key)
	return output.ConnectStateConfig{Key: k}, nil
}

var _ output.ConnectStateConfigProvider = (*ConnectStateConfigProvider)(nil)
