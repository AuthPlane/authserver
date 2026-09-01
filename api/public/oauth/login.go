package oauth

import (
	"context"
	"errors"
	"fmt"
	"html/template"
	"math"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/authplane/authserver/api/shared"
	"github.com/authplane/authserver/internal/domain"
	"github.com/authplane/authserver/internal/domain/audit"
	"github.com/authplane/authserver/internal/observability"
	"github.com/authplane/authserver/internal/ports/output"
)

const (
	// loginNonceCookieName carries the pre-session nonce that binds a
	// POST /login to a browser that performed GET /login. A page on a foreign
	// registrable domain cannot write it (Set-Cookie domain-match, RFC 6265
	// §5.3), which is what makes it a usable CSRF input before a session
	// exists.
	//
	// The value is "<nonce>|<mac>", not a bare nonce: the server keeps no
	// record of what it issued, so without the MAC it cannot tell its own nonce
	// from one a client invented — see parseLoginNonce.
	loginNonceCookieName = "authserver_login_nonce"

	// loginNoncePurpose domain-separates the nonce MAC from the CSRF-token
	// namespace, so the two are derived from different keys. See MACFor.
	loginNoncePurpose = "login-nonce"

	// loginNonceMaxAge bounds how long a rendered login form stays submittable.
	// This is a UX bound, not a security one: the nonce is not a credential,
	// and no server-side freshness check reads it — unlike the OIDC state
	// window, which also bounds time.Since(state.IssuedAt) and therefore has
	// its own provider seam. Kept generous so a login page left open
	// does not fail with "Invalid request"; the industry norm errs the same way
	// (Django CSRF_COOKIE_AGE 1y, gorilla/csrf 12h). This is why it is a
	// constant and not a per-request provider knob.
	loginNonceMaxAge = 12 * time.Hour
)

// loginHandler handles login and logout endpoints.
type loginHandler struct {
	auth    UserAuthProvider
	session *shared.SessionMiddleware
	obs     *observability.Provider
	lockout *shared.AuthLockout
	display output.LoginDisplayProvider
	urls    output.URLBuilder
	audit   AuditRecorder
}

func (h *loginHandler) handleGetLogin(w http.ResponseWriter, r *http.Request) {
	disp, err := h.display.LoginDisplay(r.Context())
	if err != nil {
		h.obs.Logger.ErrorContext(r.Context(), "resolve login display config for GET /login", "error", err)
		http.Error(w, "Internal error", http.StatusInternalServerError)
		return
	}
	redirect := r.URL.Query().Get("redirect")

	data := loginPageData{
		Redirect:       redirect,
		ShowLocalLogin: disp.ShowLocalLogin,
	}
	// Only mint the nonce when the local-login form will actually render it.
	// The template gates the form on ShowLocalLogin, so an OIDC-only deployment
	// would otherwise set a cookie and pay the CookiePolicy resolution for a
	// token nothing consumes. Nothing turns on the mint happening here: with
	// the form hidden, handlePostLogin answers 404 before it reads any cookie.
	if disp.ShowLocalLogin {
		csrfToken, err := h.csrfForRequest(w, r)
		if err != nil {
			h.obs.Logger.ErrorContext(r.Context(), "login: CSRF token generation failed", "error", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		data.CSRFToken = csrfToken
	}
	if disp.DisplayName != "" {
		data.OIDCDisplayName = disp.DisplayName
		oidcStart, err := h.urls.Resolve(r.Context(), "/oidc/start?redirect="+template.URLQueryEscaper(redirect))
		if err != nil {
			h.obs.Logger.ErrorContext(r.Context(), "build OIDC start URL", "error", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		data.OIDCStartURL = oidcStart
	}

	data.FormAction = shared.ResolvePath(r.Context(), h.urls, "/login", h.obs.Logger)
	shared.RenderTemplate(r.Context(), w, http.StatusOK, loginTmpl, data)
}

func (h *loginHandler) handlePostLogin(w http.ResponseWriter, r *http.Request) {
	// Local login off closes the endpoint outright — 404, as if unregistered,
	// the same answer as the introspection gate when its provider says off. A
	// provider error is 500, not 404: the port contract and GET /login both
	// fail closed loudly, so an outage never looks like an intentional disable.
	// Checked before the body, the nonce and the lockout so a disabled
	// endpoint costs nothing and records nothing.
	// The nonce does not stand in for this: it never expires and is not bound
	// to the flag, so a cookie minted while the form was shown would still pass.
	disp, err := h.display.LoginDisplay(r.Context())
	if err != nil {
		h.obs.Logger.ErrorContext(r.Context(), "resolve login display config for POST /login", "error", err)
		http.Error(w, "Internal error", http.StatusInternalServerError)
		return
	}
	if !disp.ShowLocalLogin {
		http.NotFound(w, r)
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, 1<<16) // 64KB
	if err = r.ParseForm(); err != nil {
		h.renderLoginError(w, r, disp, "Invalid form data")
		return
	}

	// Validate CSRF against the pre-session nonce cookie. Under SameSite Lax
	// or Strict a cross-site POST cannot carry it, so its absence stops the
	// attack. Under SameSite None the cookie does ride along, so the defense
	// instead rests on the submitted token not matching the nonce it is bound
	// to — an attacker can harvest their own valid pair, but not the
	// victim's.
	//
	// The MAC is verified here as well as on GET. Nothing is rendered on this
	// path, so there is no oracle to close; the check is here because a value
	// this server did not mint has no business reaching ValidateCSRF.
	nonceCookie, _ := r.Cookie(loginNonceCookieName)
	if nonceCookie == nil || nonceCookie.Value == "" {
		h.renderLoginError(w, r, disp, "Invalid request. Please try again.")
		return
	}
	nonce, minted, err := h.parseLoginNonce(r.Context(), nonceCookie.Value)
	if err != nil {
		h.obs.Logger.ErrorContext(r.Context(), "login: nonce verification failed to resolve secret", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if !minted {
		h.renderLoginError(w, r, disp, "Invalid request. Please try again.")
		return
	}
	valid, err := h.session.ValidateCSRF(r.Context(), nonce, r.FormValue("csrf_token"))
	if err != nil {
		h.obs.Logger.ErrorContext(r.Context(), "login: CSRF validation failed to resolve secret", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if !valid {
		h.renderLoginError(w, r, disp, "Invalid request. Please try again.")
		return
	}

	email := r.FormValue("email")
	password := r.FormValue("password")
	redirect := r.FormValue("redirect")
	ip := shared.ClientIP(r)

	// Reject an over-length identity before it reaches anything that keeps it.
	// The body cap is 64KB and nothing between the form and here shortens this
	// field, so an unbounded value would land in the lockout's map key, the log
	// line and the audit row. One check at the boundary closes all three. No
	// address this long can belong to an account (RFC 5321 caps at 254), so the
	// generic credential error is the honest answer and costs the attacker a
	// round trip with nothing retained.
	if len(email) > shared.MaxIdentityLen {
		h.obs.Logger.WarnContext(r.Context(), "login rejected: identity exceeds the maximum length",
			"length", len(email), "max", shared.MaxIdentityLen, "ip", ip)
		h.renderLoginError(w, r, disp, "Invalid email or password")
		return
	}

	// Reject a locked-out identity before bcrypt. Checking afterwards would
	// make every blocked attempt keep paying the ~100ms hash the lockout exists
	// to stop an attacker from spending.
	//
	// Nothing is logged here, on purpose. The lockout is already reported once
	// where it engages — a WARN and the auth.locked_out audit event, both in
	// recordLockout. Repeating it per blocked request would write a line
	// carrying up to MaxIdentityLen bytes of caller-chosen text for the whole
	// lockout window, which is a log-flood primitive at one request each, and
	// it would undo the point of putting this gate ahead of bcrypt: a blocked
	// attempt is supposed to cost nothing. That attempts keep arriving during a
	// lockout is not separately actionable — the transition already said so.
	if h.lockout != nil {
		if until, locked := h.lockout.LockedUntil(email, ip); locked {
			// Set after the render, not before: renderLoginError can bail to a
			// 500 when CSRF generation fails, and a
			// Retry-After on a 500 tells the client to retry a server fault on
			// a schedule it has no reason to trust.
			h.renderLoginErrorWithRetryAfter(w, r, disp, http.StatusTooManyRequests,
				"Too many failed attempts. Please try again later.", retryAfterSeconds(until))
			return
		}
	}

	u, err := h.auth.Authenticate(r.Context(), email, password)
	switch {
	// Only a rejected credential counts against the lockout. Authenticate also
	// returns wrapped store errors, and counting those turns a database blip
	// into a lockout for every user who retried during it — held for the full
	// auth_lockout AFTER the database recovers, with auth.locked_out rows
	// describing an outage as an attack. The old IP-keyed lockout had the same
	// shape; keying per identity and emitting an audit event is what makes it
	// an operator-visible incident.
	case errors.Is(err, domain.ErrInvalidCredentials):
		// No log line here. Authenticate already emits one WARN per denial
		// carrying this address and the reason behind it, so a second line
		// naming only the address is strictly redundant.
		//
		// This does not make a failed login cheap on the log pipeline: the
		// audit event Authenticate now records on every denial is written
		// synchronously and logged at INFO with the same address, so a probe
		// still costs a WARN, an INFO and a row. Removing the redundant line is
		// worth doing on its own terms; the volume a sweep can generate is a
		// deployment concern, covered in the threat model.
		if h.lockout != nil {
			if until, engaged := h.lockout.RecordFailure(email, ip); engaged {
				h.recordLockout(r.Context(), email, ip, until)
			}
		}
		h.renderLoginError(w, r, disp, "Invalid email or password")
		return

	// Anything else is the server's fault, and saying "invalid email or
	// password" would both lie and invite a retry against a backend already in
	// trouble. Every other internal failure on this path answers 500; so does
	// this one.
	case err != nil:
		h.obs.Logger.ErrorContext(r.Context(), "login: authentication failed on an internal error",
			"email", email, "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	if h.lockout != nil {
		h.lockout.Reset(email, ip)
	}

	if err = h.session.SetSessionCookie(r.Context(), w, u.ID); err != nil {
		h.obs.Logger.ErrorContext(r.Context(), "login: set session cookie failed", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	h.obs.Logger.InfoContext(r.Context(), "user logged in", "user_id", u.ID, "email", email)

	safe := shared.SafeRedirect(redirect, "/")
	dest, err := h.urls.Resolve(r.Context(), safe)
	if err != nil {
		h.obs.Logger.ErrorContext(r.Context(), "build post-login URL", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, dest, http.StatusSeeOther)
}

func (h *loginHandler) handlePostLogout(w http.ResponseWriter, r *http.Request) {
	// Not gated on ShowLocalLogin: the session is auth-method agnostic and this
	// also ends OIDC-federated sessions.
	h.session.ClearSessionCookie(r.Context(), w)
	// Burn the nonce too. It is not a credential, so leaving it would not be a
	// defect — but on a shared browser the next person would be served the same
	// CSRF token for the rest of the 12h window, and logout is the one point
	// where no other tab can still be mid-login.
	h.clearLoginNonceCookie(r.Context(), w)
	shared.RedirectInternal(w, r, h.urls, "/login", http.StatusSeeOther, h.obs.Logger)
}

// recordLockout records the audit event for a lockout that just engaged.
//
// Called only on the transition, never on the blocked requests that follow: a
// fifteen-minute lockout under traffic would otherwise write one event per
// request.
//
// ActorID is left empty and the submitted address goes in Detail. The sibling
// event user.login_failed — fired from the same form field on the same request
// — keeps the address out of ActorID for the same reasons, though it does fill
// ActorID with the resolved user id on the causes where the address matched an
// account, which this event cannot do: a lockout engages on a submitted
// identity that need not resolve to anything. Three reasons that shape is right
// here: ActorID is contracted as a user ID, client ID or "system", and an
// address that need not correspond to any account is none of those; Detail is
// the cataloged `key=value` payload operators grep; and actor_id is an indexed
// exact-match filter on the admin audit feed, which is the wrong home for
// unbounded text chosen by whoever posted the form.
func (h *loginHandler) recordLockout(ctx context.Context, email, ip string, until time.Time) {
	h.obs.Logger.WarnContext(ctx, "auth lockout engaged",
		"email", email, "ip", ip, "until", until.Format(time.RFC3339))
	if h.audit == nil {
		return
	}
	h.audit.Record(ctx, audit.NewEvent(
		audit.ActionAuthLockedOut,
		"",
		"",
		ip,
		fmt.Sprintf("until=%s email=%q", until.Format(time.RFC3339), email),
	))
}

// renderLoginError re-renders the login form under 422 — the status every
// rejected submission carries: bad form, bad CSRF token, bad credentials.
//
// It renders HTML because the caller is a browser posting a form, not an OAuth
// client, so an OAuth error body would be the wrong shape for it. The lockout
// path answers 429 and goes through renderLoginErrorWithRetryAfter.
func (h *loginHandler) renderLoginError(w http.ResponseWriter, r *http.Request, disp output.LoginDisplay, errMsg string) {
	h.renderLoginErrorWithRetryAfter(w, r, disp, http.StatusUnprocessableEntity, errMsg, "")
}

// renderLoginErrorWithRetryAfter is renderLoginError plus a Retry-After header.
//
// The header is written immediately before the body, after every path that can
// still bail to a 500. Setting it at the call site instead would leave a
// Retry-After on an internal error — telling the client to retry a server fault
// on a schedule derived from something unrelated to it. An empty value writes
// no header.
func (h *loginHandler) renderLoginErrorWithRetryAfter(w http.ResponseWriter, r *http.Request, disp output.LoginDisplay, status int, errMsg, retryAfter string) {
	redirect := r.FormValue("redirect")

	data := loginPageData{
		Error:          errMsg,
		Redirect:       redirect,
		ShowLocalLogin: disp.ShowLocalLogin,
	}
	// Mint only when the form will render the token — see handleGetLogin.
	if disp.ShowLocalLogin {
		csrfToken, err := h.csrfForRequest(w, r)
		if err != nil {
			h.obs.Logger.ErrorContext(r.Context(), "login: CSRF token generation failed", "error", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		data.CSRFToken = csrfToken
	}
	if disp.DisplayName != "" {
		data.OIDCDisplayName = disp.DisplayName
		oidcStart, err := h.urls.Resolve(r.Context(), "/oidc/start?redirect="+template.URLQueryEscaper(redirect))
		if err != nil {
			h.obs.Logger.ErrorContext(r.Context(), "build OIDC start URL", "error", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		data.OIDCStartURL = oidcStart
	}

	data.FormAction = shared.ResolvePath(r.Context(), h.urls, "/login", h.obs.Logger)
	if retryAfter != "" {
		w.Header().Set("Retry-After", retryAfter)
	}
	shared.RenderTemplate(r.Context(), w, status, loginTmpl, data)
}

// retryAfterSeconds renders a Retry-After value from a deadline, floored at 1 so
// a sub-second remainder never becomes "0" (which a client reads as "retry now").
func retryAfterSeconds(until time.Time) string {
	secs := int(math.Ceil(time.Until(until).Seconds()))
	if secs < 1 {
		secs = 1
	}
	return strconv.Itoa(secs)
}

// loginNoncePath returns the Path attribute for the login nonce cookie: the AS
// mount resolved from the root path, matching the session and OIDC state
// cookies. Any future clear MUST go through this same helper or the browser
// will not match the cookie.
func (h *loginHandler) loginNoncePath(ctx context.Context) string {
	return shared.ResolvePath(ctx, h.urls, "/", h.obs.Logger)
}

// setLoginNonceCookie writes the pre-session nonce cookie. value is the full
// "<nonce>|<mac>" pair, not the bare nonce. Attributes mirror
// setOIDCStateCookie: the boot Secure floor means a provider may tighten Secure
// but never downgrade an HTTPS deployment, and EffectiveSameSite maps
// SameSiteDefaultMode to Lax.
//
// EffectiveSameSite's backstop does NOT catch the Go zero value of the field
// (SameSiteDefaultMode is 1, the field's zero value is 0) — a known gap tracked
// separately. It does not bite here: every shipped SessionConfigProvider yields
// a concrete SameSite, so this cookie is Lax under all current wiring. Stated so
// the next reader does not treat the omitted-attribute case as impossible.
func (h *loginHandler) setLoginNonceCookie(ctx context.Context, w http.ResponseWriter, value string, policy output.SessionConfig) {
	http.SetCookie(w, &http.Cookie{
		Name:     loginNonceCookieName,
		Value:    value,
		Path:     h.loginNoncePath(ctx),
		MaxAge:   shared.CookieMaxAgeSeconds(loginNonceMaxAge),
		HttpOnly: true,
		Secure:   policy.Secure || h.session.SecureFloor(),
		SameSite: policy.EffectiveSameSite(),
	})
}

// clearLoginNonceCookie expires the nonce cookie. The Path MUST come from the
// same helper as the set or the browser will not match it — it would add a
// second, empty cookie instead of removing the first.
//
// The policy is resolved best-effort: SameSite governs whether the browser
// accepts a Set-Cookie in a cross-site context, so the delete carries the
// configured value when it resolves and a safe Lax plus the boot Secure floor
// when it does not. A policy-provider outage must never wedge logout. This
// mirrors clearOIDCStateCookie.
func (h *loginHandler) clearLoginNonceCookie(ctx context.Context, w http.ResponseWriter) {
	sameSite := http.SameSiteLaxMode
	secure := h.session.SecureFloor()
	if policy, err := h.session.CookiePolicy(ctx); err == nil {
		sameSite = policy.EffectiveSameSite()
		secure = policy.Secure || h.session.SecureFloor()
	}
	http.SetCookie(w, &http.Cookie{
		Name:     loginNonceCookieName,
		Value:    "",
		Path:     h.loginNoncePath(ctx),
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   secure,
		SameSite: sameSite,
	})
}

// parseLoginNonce splits a login-nonce cookie value and verifies its MAC,
// returning the bare nonce.
//
// minted=false means this server did not issue the value. A client may put
// anything in a cookie, and the server keeps no record of what it handed out,
// so the MAC is the only way to tell its own nonce from an invented one.
// Without this check GET /login would sign caller-chosen input and hand the
// signature straight back — a signing oracle. Callers MUST remint on
// minted=false; reusing the value is what the oracle was.
//
// A non-nil error is a secret-resolution failure and is FATAL. Collapsing it
// into minted=false would remint on every request during a provider outage,
// so no login could ever complete and nothing would say why.
//
// The value must be exactly two fields. A legitimate one always is: the nonce
// is hex and the MAC is base64url, neither of which can contain the separator.
// This mirrors validateCookie's strict field count rather than tolerating an
// odd split and leaning on the MAC to reject it.
func (h *loginHandler) parseLoginNonce(ctx context.Context, raw string) (string, bool, error) {
	parts := strings.Split(raw, "|")
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return "", false, nil
	}
	nonce, mac := parts[0], parts[1]
	minted, err := h.session.VerifyMAC(ctx, loginNoncePurpose, nonce, mac)
	if err != nil {
		return "", false, err
	}
	return nonce, minted, nil
}

// ensureLoginNonce returns the browser's existing login nonce, or mints one and
// sets the cookie. Reuse is deliberate: minting on every GET would let a second
// login tab overwrite the first tab's cookie, orphaning its rendered token.
//
// This anti-orphan property is browser-cooperative, not a hard invariant: a
// hostile cross-site POST arrives (under SameSite=Lax) with the cookie stripped,
// takes the mint path in renderLoginError, and its Set-Cookie still overwrites
// the victim's nonce — orphaning any open login tab and forcing one retry. No
// auth or disclosure impact (HttpOnly, opaque cross-origin body); the deferred
// Origin / Sec-Fetch-Site check is what would make the property hold against a
// hostile origin.
//
// Only a value this server minted is reused — see parseLoginNonce.
// The cookie policy is resolved only on the minting path, so the common
// reuse case does not call a documented hot-path provider.
func (h *loginHandler) ensureLoginNonce(w http.ResponseWriter, r *http.Request) (string, error) {
	if c, _ := r.Cookie(loginNonceCookieName); c != nil && c.Value != "" {
		nonce, minted, err := h.parseLoginNonce(r.Context(), c.Value)
		if err != nil {
			return "", err
		}
		if minted {
			return nonce, nil
		}
		// Forged, tampered, or issued before the value carried a MAC. Fall
		// through to mint a fresh one; never reuse it.
	}
	nonce := randomHex(16)
	mac, err := h.session.MACFor(r.Context(), loginNoncePurpose, nonce)
	if err != nil {
		return "", err
	}
	policy, err := h.session.CookiePolicy(r.Context())
	if err != nil {
		return "", err
	}
	h.setLoginNonceCookie(r.Context(), w, nonce+"|"+mac, policy)
	return nonce, nil
}

// csrfForRequest derives the login form's CSRF token from the pre-session
// nonce. It takes the ResponseWriter because resolving the nonce may have to
// mint and set the cookie.
func (h *loginHandler) csrfForRequest(w http.ResponseWriter, r *http.Request) (string, error) {
	nonce, err := h.ensureLoginNonce(w, r)
	if err != nil {
		return "", err
	}
	return h.session.CSRFToken(r.Context(), nonce)
}

var loginTmpl = template.Must(template.New("login").Parse(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Sign In — Authplane</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:system-ui,-apple-system,'Segoe UI',Roboto,sans-serif;
background:#f8fafc;display:flex;justify-content:center;align-items:center;
min-height:100vh;padding:24px;color:#0f172a}
.wrapper{width:100%;max-width:420px}
.logo{text-align:center;margin-bottom:32px}
.logo svg{width:40px;height:40px}
.logo-text{font-size:0.85em;font-weight:600;color:#64748b;letter-spacing:0.05em;
text-transform:uppercase;margin-top:8px}
.card{background:#fff;border-radius:16px;
box-shadow:0 1px 3px rgba(0,0,0,0.04),0 8px 24px rgba(0,0,0,0.06);
padding:40px 36px;border:1px solid #e2e8f0}
h1{font-size:1.5em;font-weight:700;margin-bottom:4px;color:#0f172a;letter-spacing:-0.01em}
.subtitle{color:#64748b;margin-bottom:28px;font-size:0.92em;line-height:1.5}
.error{background:#fef2f2;border:1px solid #fecaca;color:#b91c1c;padding:12px 16px;
border-radius:10px;margin-bottom:20px;font-size:0.88em;line-height:1.5;display:flex;align-items:center;gap:8px}
.error::before{content:"";display:block;width:18px;height:18px;flex-shrink:0;
background:currentColor;-webkit-mask:url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 20 20' fill='currentColor'%3E%3Cpath fill-rule='evenodd' d='M18 10a8 8 0 11-16 0 8 8 0 0116 0zm-7 4a1 1 0 11-2 0 1 1 0 012 0zm-1-9a1 1 0 00-1 1v4a1 1 0 102 0V6a1 1 0 00-1-1z' clip-rule='evenodd'/%3E%3C/svg%3E") center/contain no-repeat;
mask:url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 20 20' fill='currentColor'%3E%3Cpath fill-rule='evenodd' d='M18 10a8 8 0 11-16 0 8 8 0 0116 0zm-7 4a1 1 0 11-2 0 1 1 0 012 0zm-1-9a1 1 0 00-1 1v4a1 1 0 102 0V6a1 1 0 00-1-1z' clip-rule='evenodd'/%3E%3C/svg%3E") center/contain no-repeat}
.field{margin-bottom:20px}
.field label{display:block;font-weight:500;margin-bottom:6px;font-size:0.875em;color:#334155}
.field input{width:100%;padding:11px 14px;border:1px solid #cbd5e1;border-radius:10px;
font-size:0.95em;background:#f8fafc;transition:all 0.2s ease;color:#0f172a}
.field input:focus{outline:none;border-color:#6366f1;box-shadow:0 0 0 3px rgba(99,102,241,0.12);
background:#fff}
.field input::placeholder{color:#94a3b8}
.btn-primary{width:100%;padding:12px;background:#4f46e5;color:#fff;border:none;
border-radius:10px;font-size:0.95em;font-weight:600;cursor:pointer;
transition:all 0.2s ease;letter-spacing:0.01em}
.btn-primary:hover{background:#4338ca;box-shadow:0 4px 12px rgba(79,70,229,0.3)}
.btn-primary:active{transform:scale(0.99)}
.oidc-btn{display:flex;align-items:center;justify-content:center;gap:8px;
width:100%;padding:12px;background:#fff;color:#1e293b;border:1px solid #cbd5e1;
border-radius:10px;font-size:0.95em;font-weight:600;cursor:pointer;text-align:center;
text-decoration:none;transition:all 0.2s ease}
.oidc-btn:hover{background:#f8fafc;border-color:#94a3b8;box-shadow:0 2px 8px rgba(0,0,0,0.06)}
.oidc-btn::before{content:"";display:block;width:20px;height:20px;
background:#64748b;-webkit-mask:url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24' fill='none' stroke='currentColor' stroke-width='2' stroke-linecap='round' stroke-linejoin='round'%3E%3Cpath d='M15 3h4a2 2 0 012 2v14a2 2 0 01-2 2h-4'/%3E%3Cpolyline points='10 17 15 12 10 7'/%3E%3Cline x1='15' y1='12' x2='3' y2='12'/%3E%3C/svg%3E") center/contain no-repeat;
mask:url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24' fill='none' stroke='currentColor' stroke-width='2' stroke-linecap='round' stroke-linejoin='round'%3E%3Cpath d='M15 3h4a2 2 0 012 2v14a2 2 0 01-2 2h-4'/%3E%3Cpolyline points='10 17 15 12 10 7'/%3E%3Cline x1='15' y1='12' x2='3' y2='12'/%3E%3C/svg%3E") center/contain no-repeat}
.divider{display:flex;align-items:center;margin:24px 0;color:#94a3b8;font-size:0.82em;
text-transform:uppercase;letter-spacing:0.05em;font-weight:500}
.divider::before,.divider::after{content:"";flex:1;border-bottom:1px solid #e2e8f0}
.divider::before{margin-right:16px}
.divider::after{margin-left:16px}
.footer{text-align:center;margin-top:24px;font-size:0.8em;color:#94a3b8}
</style>
</head>
<body>
<div class="wrapper">
<div class="logo">
<svg viewBox="0 0 40 40" fill="none" xmlns="http://www.w3.org/2000/svg">
<rect width="40" height="40" rx="10" fill="#4f46e5"/>
<path d="M12 20.5L17.5 26L28 15" stroke="#fff" stroke-width="3" stroke-linecap="round" stroke-linejoin="round"/>
</svg>
<div class="logo-text">Authplane</div>
</div>
<div class="card">
<h1>Welcome back</h1>
<p class="subtitle">Sign in to your account to continue</p>
{{if .Error}}<div class="error">{{.Error}}</div>{{end}}
{{if .OIDCDisplayName}}<a class="oidc-btn" href="{{.OIDCStartURL}}">Continue with {{.OIDCDisplayName}}</a>
{{if .ShowLocalLogin}}<div class="divider">or</div>{{end}}{{end}}
{{if .ShowLocalLogin}}<form method="POST" action="{{.FormAction}}">
<input type="hidden" name="csrf_token" value="{{.CSRFToken}}">
<input type="hidden" name="redirect" value="{{.Redirect}}">
<div class="field">
<label for="email">Email address</label>
<input type="email" id="email" name="email" placeholder="you@example.com" required autofocus>
</div>
<div class="field">
<label for="password">Password</label>
<input type="password" id="password" name="password" placeholder="Enter your password" required>
</div>
<button type="submit" class="btn-primary">Sign in</button>
</form>{{end}}
</div>
<div class="footer">Secured by Authplane</div>
</div>
</body>
</html>`))
