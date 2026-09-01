package output

import (
	"context"
	"time"
)

// DPoPConfig is the per-request DPoP (RFC 9449) config.
type DPoPConfig struct {
	Enabled       bool
	NonceTTL      time.Duration
	ProofLifetime time.Duration
	RequireNonce  bool
}

// DPoPConfigProvider supplies DPoP config for a request.
type DPoPConfigProvider interface {
	Config(ctx context.Context) (DPoPConfig, error)
}
