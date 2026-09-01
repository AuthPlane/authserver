package output

import (
	"context"
	// net/http is imported deliberately: SameSite reuses the stdlib
	// http.SameSite enum rather than reinventing a typed string, so no
	// conversion is needed at the cookie-writing call sites. This is a value
	// enum, not a transport dependency — it does not pull net/http machinery
	// into the port.
	"net/http"
	"time"
)

// SessionConfig is the per-request session-cookie policy.
//
// The signing secret is deliberately NOT here — it has its own seam,
// SessionSecretProvider. This port covers cookie *policy*; that port covers
// signing *material*.
//
// CookieName is intentionally excluded: it is a boot-time field on the
// middleware (read directly by consent/login handlers in their hot path). If a
// deployment ever needs a per-request cookie name, extend this struct then.
type SessionConfig struct {
	// MaxAge is the session-cookie lifetime. A zero (or negative) value falls
	// back to DefaultSessionMaxAge via EffectiveMaxAge rather than minting a
	// cookie that expires the instant it is issued — always read it through
	// that method, never directly.
	MaxAge     time.Duration
	Secure     bool
	SameSite   http.SameSite
	FailClosed bool
}

// DefaultSessionMaxAge is the defense-in-depth session-cookie lifetime applied
// when a provider yields a zero/negative MaxAge. It matches the OSS boot default
// (config session.max_age), so the fallback never changes shipped behavior.
const DefaultSessionMaxAge = 24 * time.Hour

// EffectiveMaxAge is the lifetime callers must use. Keeping the clamp on the DTO
// makes the guarantee structural: a new consumer cannot forget it and silently
// reintroduce the already-expired-cookie footgun.
func (c SessionConfig) EffectiveMaxAge() time.Duration {
	if c.MaxAge <= 0 {
		return DefaultSessionMaxAge
	}
	return c.MaxAge
}

// EffectiveSameSite is the SameSite callers must use. Like EffectiveMaxAge, the
// clamp lives on the DTO so a new consumer can't forget it: the zero value is
// http.SameSiteDefaultMode, which http.SetCookie renders by OMITTING the
// SameSite attribute — weakening CSRF posture with no signal. A provider that
// leaves the field unset therefore gets a safe Lax default rather than a
// bare cookie. (cfg-driven wiring never yields 0; ParseSameSite maps "" → Lax.)
func (c SessionConfig) EffectiveSameSite() http.SameSite {
	if c.SameSite == http.SameSiteDefaultMode {
		return http.SameSiteLaxMode
	}
	return c.SameSite
}

// SessionConfigProvider supplies the session-cookie policy for a request.
//
// Hot path: Config runs on every request that sets, clears, or reads a session
// cookie — and more than once within some flows (the OIDC callback resolves it
// for the state-cookie burn and again to set the session). The default static
// adapter is O(1) with no I/O; an implementation that resolves per request from
// an I/O-backed source MUST cache internally (e.g. a short-TTL per-key cache) so
// it does not add a lookup per call. Callers do not memoize.
type SessionConfigProvider interface {
	Config(ctx context.Context) (SessionConfig, error)
}
