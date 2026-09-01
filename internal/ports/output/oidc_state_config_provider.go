package output

import (
	"context"
	"time"
)

// OIDCStateConfig is the per-request OIDC state-cookie / replay-window policy.
type OIDCStateConfig struct {
	// MaxAge bounds BOTH the state cookie's Max-Age attribute AND the
	// server-side freshness check at callback (time.Since(state.IssuedAt)).
	// The default deployment uses cfg.OAuth.StateMaxAge (10m). A zero/negative
	// value falls back to DefaultOIDCStateMaxAge via EffectiveMaxAge — always
	// read it through that method, never directly.
	MaxAge time.Duration
}

// DefaultOIDCStateMaxAge is the defense-in-depth state-cookie window applied
// when a provider yields a zero/negative MaxAge. Without it a zero window would
// make the callback freshness check reject every login. Matches the OSS boot
// default (config oauth.state_max_age).
const DefaultOIDCStateMaxAge = 10 * time.Minute

// EffectiveMaxAge is the window callers must use — see SessionConfig.EffectiveMaxAge
// for why the clamp lives on the DTO rather than at each consumer.
func (c OIDCStateConfig) EffectiveMaxAge() time.Duration {
	if c.MaxAge <= 0 {
		return DefaultOIDCStateMaxAge
	}
	return c.MaxAge
}

// OIDCStateConfigProvider supplies the OIDC state-cookie policy for a request.
//
// Hot path: Config runs on every /oidc/start and /oidc/callback. The default
// static adapter is O(1) with no I/O; an implementation resolving per request
// from an I/O-backed source MUST cache internally so it does not add a lookup
// per call. Callers do not memoize.
type OIDCStateConfigProvider interface {
	Config(ctx context.Context) (OIDCStateConfig, error)
}
