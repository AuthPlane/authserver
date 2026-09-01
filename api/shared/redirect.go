package shared

import (
	"context"
	"log/slog"
	"net/http"
	"net/url"
	"strings"

	"github.com/authplane/authserver/internal/ports/output"
)

// SafeRedirect confines a user-supplied redirect target to the authorization
// server's own origin. It returns path when path is a rooted, same-origin
// path, and fallback otherwise.
//
// Callers pass values taken straight from a query parameter, a form field, or
// a decoded OIDC state, and use the result as an HTTP Location. Every call
// site is reached with a session cookie already set, so a target that escapes
// this origin hands a freshly authenticated user to whoever chose it.
//
// The layers below are deliberately independent, because the string is
// interpreted by more than one grammar before it becomes a destination:
//
//   - Control bytes. net/http emits a Location it cannot parse verbatim
//     (url.Parse rejects control bytes, so the normalisation branch is
//     skipped), and hexEscapeNonASCII only escapes bytes >= 0x80. The WHATWG
//     URL parser browsers implement strips TAB, LF and CR before resolving —
//     so a control byte here can shift the authority the browser resolves.
//   - Backslash, in the path portion only. url.Parse follows RFC 3986, where
//     "\" is an ordinary path character; the WHATWG URL parser treats it as
//     "/". Delegating to url.Parse alone would accept "/\evil.com". The check
//     stops at the first "?" or "#" because the authority is already resolved
//     by then, and the query is not ours: the post-login target is the whole
//     authorize URL (see the /oauth/authorize login-required branch), so it
//     carries a client's query verbatim, backslashes and all. Rejecting those
//     would strand a user at the fallback after a successful login, with the
//     authorization silently abandoned.
//   - A leading "//", whatever follows it. url.Parse reports Host "" for three
//     or more leading slashes — the authority between the second and third is
//     empty — so the parse layer below does not catch them, while WHATWG's
//     special-authority-ignore-slashes state consumes the whole run and takes
//     the next segment as the host. Same shape as the backslash rule: where
//     the two parsers disagree, the explicit check is the one that holds.
//   - url.Parse, whose error branch rejects a malformed percent escape in the
//     path or fragment ("/50%off"; RawQuery is not escape-validated). That is
//     this layer's real contribution, and it is a narrowing, so it is stated
//     here rather than left to be discovered. Its IsAbs and Host tests are
//     kept as belt and braces only: given the rejections above, an absolute
//     or authority-bearing target is already caught by the rooted-prefix test
//     below. Do not read them as the reason "https://evil.com" is refused.
//
// Control bytes are checked over the whole string — they break the Location
// header itself, not just the origin — while the backslash rule is scoped to
// the region that can still change where the browser goes.
//
// What SafeRedirect returns is not what the browser receives. http.Redirect
// splits the target at the first "?" and runs path.Clean over everything
// before it — a fragment included, since a fragment holds no "?". So
// "/foo://bar" is emitted as "/foo:/bar", "/a#x//y" as "/a#x/y", and
// "/a#..//..//evil" as "/evil", a fragment rewriting the path it rides on.
// A query string is preserved verbatim. Callers wanting a target to survive
// unchanged should keep "//" and dot segments out of its path and fragment;
// this function decides only whether a target stays on this origin, which
// path.Clean cannot change.
//
// The layers do not lean on the caller to normalise the result. http.Redirect
// happens to run path.Clean over a relative Location, which would collapse
// "///evil.com" on its own, but only on the branch it takes when url.Parse
// succeeds — and a target this guard exists to stop is frequently one
// url.Parse rejects, which is the branch where the Location is emitted
// verbatim instead. A guard whose correctness depends on which branch its
// consumer happens to take is not one you can reason about.
func SafeRedirect(path, fallback string) string {
	if path == "" {
		return fallback
	}
	for i := 0; i < len(path); i++ {
		if path[i] < 0x20 || path[i] == 0x7f {
			return fallback
		}
	}
	pathPart := path
	if i := strings.IndexAny(pathPart, "?#"); i >= 0 {
		pathPart = pathPart[:i]
	}
	if strings.ContainsRune(pathPart, '\\') {
		return fallback
	}
	if strings.HasPrefix(path, "//") {
		return fallback
	}
	u, err := url.Parse(path)
	if err != nil || u.IsAbs() || u.Host != "" {
		return fallback
	}
	// Checked on the raw string, not u.Path: parsing may normalise away the
	// very prefix being validated.
	if !strings.HasPrefix(path, "/") {
		return fallback
	}
	return path
}

// ResolvePath maps a root-relative authorserver path to the path the AS is
// served under, via urls.Resolve. It is the single place every consumer
// (internal redirects, cookies, template actions) resolves a mount path, so the
// join/slash rule lives in the URLBuilder, once. A nil urls or a resolution
// error falls back to the unresolved path (root behavior, byte-identical to
// pre-patch) and warn-logs when a logger is supplied.
func ResolvePath(ctx context.Context, urls output.URLBuilder, path string, logger *slog.Logger) string {
	if urls == nil {
		return path
	}
	resolved, err := urls.Resolve(ctx, path)
	if err != nil {
		if logger != nil {
			logger.WarnContext(ctx, "resolve AS path failed; using unresolved path", "path", path, "error", err)
		}
		return path
	}
	return resolved
}

// RedirectInternal issues an HTTP redirect to a path on the authorization
// server's own URL surface, resolved through urls so the redirect stays correct
// when the AS is served behind a reverse-proxy mount. At the root the path is
// unchanged — byte-identical to http.Redirect.
//
// Use ONLY for the AS's own paths (e.g. "/login", "/consent"). External
// destinations — an OAuth client's redirect_uri, an upstream IdP authorize
// URL — MUST use http.Redirect directly so they are never resolved.
func RedirectInternal(w http.ResponseWriter, r *http.Request, urls output.URLBuilder, path string, code int, logger *slog.Logger) {
	http.Redirect(w, r, ResolvePath(r.Context(), urls, path, logger), code)
}
