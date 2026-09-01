package output

import "context"

// URLBuilder maps the authserver's own root-relative paths to the paths the
// deployment actually serves them under. The OSS static adapter returns paths
// unchanged (root deployment); an alternative implementation MAY prepend a
// mount prefix (for example, an authserver served behind a reverse-proxy path
// prefix on a shared host).
//
// Contract:
//   - Resolve is the single substitution point for login-flow URLs. Callers
//     never concatenate a mount prefix themselves.
//   - A caller resolving a USER-DERIVED redirect target MUST run
//     shared.SafeRedirect on it BEFORE calling Resolve — Resolve applies the
//     mount only; it performs no redirect-safety validation.
//   - Resolve MUST NOT widen the destination set: given a root-relative path it
//     MUST return a root-relative path (mount applied). It MUST NOT produce an
//     absolute or external URL (scheme/host, "//host", scheme-relative). Its
//     output is used verbatim as a redirect Location and as a rendered
//     href/action, so an impl that emitted "https://evil.example" would defeat
//     the SafeRedirect check that ran on the input. SafeRedirect runs BEFORE
//     Resolve, not after — the no-widening guarantee is the impl's to keep.
//   - Resolve MUST respect ctx cancellation; if ctx is done, returning
//     (zero, ctx.Err()) is acceptable.
//   - Implementations SHOULD NOT return an error for a well-formed path; the
//     OSS static impl never does. If Resolve DOES error, the error policy is
//     the CALLER's and varies by use: a redirect Location or a rendered
//     href/action in the login flow fails closed (the handler returns HTTP 500
//     rather than emit an unprefixed URL that would silently break the mount),
//     whereas a cookie Path or other best-effort mount falls back to the
//     unresolved path via shared.ResolvePath (mount not applied). The interface
//     itself guarantees neither fail-open nor fail-closed; pick the policy at
//     the callsite per that rule.
//   - Implementations SHOULD be safe for concurrent use.
type URLBuilder interface {
	// Resolve maps a root-relative authserver path to the path the AS is
	// actually served under, applying the deployment's mount. The OSS default
	// returns path unchanged (empty mount); an alternative prepends its
	// (ctx-derived) mount prefix. The join/slash rule lives here, once:
	//
	//   - internal redirect → Resolve(ctx, "/login")  → "/login" | "/api/v2/auth/login"
	//   - cookie Path        → Resolve(ctx, "/")       → "/"      | "/api/v2/auth/"
	//   - template action    → Resolve(ctx, "/consent")
	//   - with query string  → Resolve(ctx, "/oidc/start?redirect=...")
	//
	// path may carry a query string (the "?..." form above); the impl applies
	// the mount to the path segment only and MUST preserve the query byte-for-
	// byte — do not re-escape, collapse, or reorder it. The caller has already
	// escaped query values, so a normalizing impl (url.JoinPath, path.Clean)
	// MUST NOT touch anything past the first "?".
	//
	// The cookie's trailing slash falls out of the "/" input. Cookie callers
	// MUST NOT imply a Domain; host isolation relies on cookies staying
	// host-only.
	Resolve(ctx context.Context, path string) (string, error)
}
