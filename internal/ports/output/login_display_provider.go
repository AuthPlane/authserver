package output

import "context"

// LoginDisplay is the slice of configuration the login endpoints consult
// per request: the OIDC button label and whether local password login is
// on. It is not presentation-only — ShowLocalLogin is read by GET /login to
// decide whether to render the password form and by POST /login to decide
// whether to accept credentials at all.
//
// It deliberately excludes the upstream federation identity (Issuer,
// ClientID, ClientSecret, …). Resolving LoginDisplay must not resolve or
// decrypt those — a DB-backed implementation can answer it from a cheap
// per-request lookup without touching secret material.
type LoginDisplay struct {
	DisplayName string // OIDC button label; empty → no OIDC button rendered

	// ShowLocalLogin switches local password login for the request. true
	// renders the password form and lets POST /login authenticate; false
	// omits the form and makes POST /login answer 404 before reading the
	// body, so no local account — including a break-glass admin — can sign
	// in with a password. Implementations must not return false for a
	// purely cosmetic reason.
	ShowLocalLogin bool
}

// LoginDisplayProvider returns the login-endpoint config that applies to
// the current request. Handlers consult it at request time rather than
// capturing fields from cfg.OIDC at boot, so callers running multiple
// deployment environments behind a single binary (e.g., blue/green,
// dev/staging/prod fronted by a shared edge) can vary the login fields
// without re-deploying.
//
// LoginDisplay may fail when the underlying source is unreachable (e.g., a
// DB-backed implementation that loses its connection). Callers must treat a
// non-nil error as a fatal condition for the current request — the login
// handlers respond with 500 — rather than substituting a default, because
// silently degrading hides misconfiguration from operators.
//
// The default static adapter
// (internal/adapters/static.LoginDisplayProvider) returns a fixed value
// with a nil error on every call, ignoring ctx.
type LoginDisplayProvider interface {
	LoginDisplay(ctx context.Context) (LoginDisplay, error)
}
