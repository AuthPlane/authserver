package oauth

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"html/template"
	"net/http"
	"time"

	"github.com/authplane/authserver/api/shared"
	"github.com/authplane/authserver/internal/crypto"
	"github.com/authplane/authserver/internal/domain"
	"github.com/authplane/authserver/internal/observability"
	"github.com/authplane/authserver/internal/ports/output"
)

const (
	oidcStateCookieName = "authserver_oidc_state"
	// oidcStateClockSkew tolerates client/server clock drift in the
	// "future" direction. Migrated from verifyState pre-refactor.
	oidcStateClockSkew = -1 * time.Minute
)

// oidcHandler handles OIDC start + callback endpoints.
type oidcHandler struct {
	oidc     OIDCFlowProvider
	session  *shared.SessionMiddleware
	obs      *observability.Provider
	codec    output.StateCodec
	urls     output.URLBuilder
	stateCfg output.OIDCStateConfigProvider
}

// handleOIDCStart initiates the OIDC flow by redirecting to the upstream IdP.
func (h *oidcHandler) handleOIDCStart(w http.ResponseWriter, r *http.Request) {
	redirect := r.URL.Query().Get("redirect")
	if redirect == "" {
		redirect = "/"
	}

	nonce := randomHex(32)
	verifier := crypto.GenerateVerifier()
	challenge := crypto.ComputeS256Challenge(verifier)

	stateCfg, err := h.stateCfg.Config(r.Context())
	if err != nil {
		h.obs.Logger.ErrorContext(r.Context(), "OIDC state config resolution failed", "error", err)
		shared.RenderTemplate(r.Context(), w, http.StatusInternalServerError, oidcErrorTmpl, h.oidcError(r, "Sign-in is temporarily unavailable. Please try again later."))
		return
	}
	policy, err := h.session.CookiePolicy(r.Context())
	if err != nil {
		h.obs.Logger.ErrorContext(r.Context(), "OIDC state cookie policy resolution failed", "error", err)
		shared.RenderTemplate(r.Context(), w, http.StatusInternalServerError, oidcErrorTmpl, h.oidcError(r, "Sign-in is temporarily unavailable. Please try again later."))
		return
	}

	// Bind state to the browser via a one-time nonce cookie. Written BEFORE the
	// state is encoded, so a failed Encode leaves an orphan cookie: that is a
	// deliberate, accepted trade-off (the cookie carries only the binding nonce
	// and self-expires via MaxAge). TestOIDCStart_CodecEncodeError_Returns500
	// pins this ordering — do not "fix" it without revisiting that contract.
	browserNonce := randomHex(16)
	h.setOIDCStateCookie(r.Context(), w, browserNonce, stateCfg.EffectiveMaxAge(), policy)

	state := output.State{
		Redirect:     redirect,
		Nonce:        nonce,
		Verifier:     verifier,
		BrowserNonce: browserNonce,
		IssuedAt:     time.Now().UTC(),
	}

	stateBytes, err := h.codec.Encode(r.Context(), state)
	if err != nil || len(stateBytes) == 0 {
		// The default codec never fails; the contract permits failure
		// for impls that resolve signing material dynamically. A nil/empty
		// return violates the StateCodec contract (port godoc: "On success,
		// the returned slice MUST be non-nil and non-empty") — treat as
		// server-side error.
		h.obs.Logger.ErrorContext(r.Context(), "OIDC state encode failed or returned empty",
			"error", err, "bytes_len", len(stateBytes))
		shared.RenderTemplate(r.Context(), w, http.StatusInternalServerError, oidcErrorTmpl, h.oidcError(r, "Authentication failed. Please try again."))
		return
	}

	authURL, err := h.oidc.AuthorizationURL(r.Context(), string(stateBytes), nonce, challenge)
	if err != nil {
		h.obs.Logger.ErrorContext(r.Context(), "build OIDC authorization URL for /oidc/start", "error", err)
		shared.RenderTemplate(r.Context(), w, http.StatusInternalServerError, oidcErrorTmpl, h.oidcError(r, "Sign-in is temporarily unavailable. Please try again later."))
		return
	}

	h.obs.Logger.DebugContext(r.Context(), "OIDC start redirect")

	http.Redirect(w, r, authURL, http.StatusFound)
}

// handleOIDCCallback handles the return from the upstream IdP.
func (h *oidcHandler) handleOIDCCallback(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	if errParam := r.URL.Query().Get("error"); errParam != "" {
		desc := r.URL.Query().Get("error_description")
		h.obs.Logger.WarnContext(ctx, "OIDC upstream error",
			"error", errParam,
			"description", desc,
		)
		shared.RenderTemplate(ctx, w, http.StatusBadRequest, oidcErrorTmpl, h.oidcError(r, "Authentication failed. Please try again."))
		return
	}

	code := r.URL.Query().Get("code")
	stateRaw := r.URL.Query().Get("state")
	if code == "" || stateRaw == "" {
		shared.RenderTemplate(ctx, w, http.StatusBadRequest, oidcErrorTmpl, h.oidcError(r, "Missing authorization code or state."))
		return
	}

	state, err := h.codec.Decode(ctx, []byte(stateRaw))
	if err != nil {
		h.obs.Logger.WarnContext(ctx, "OIDC state decode failed", "error", err)
		shared.RenderTemplate(ctx, w, http.StatusBadRequest, oidcErrorTmpl, h.oidcError(r, "Invalid or expired state. Please try again."))
		return
	}

	// Resolve the state TTL only after a malformed state has been rejected, so
	// an undecodable callback never pays for provider resolution (which may do
	// I/O in an alternative provider). Freshness genuinely needs it, so a
	// resolution failure here is fatal — we cannot fail-open the replay window.
	stateCfg, err := h.stateCfg.Config(ctx)
	if err != nil {
		h.obs.Logger.ErrorContext(ctx, "OIDC state config resolution failed", "error", err)
		shared.RenderTemplate(ctx, w, http.StatusInternalServerError, oidcErrorTmpl, h.oidcError(r, "Sign-in is temporarily unavailable. Please try again later."))
		return
	}

	// Freshness — migrated out of verifyState into the handler.
	if age := time.Since(state.IssuedAt); age > stateCfg.EffectiveMaxAge() || age < oidcStateClockSkew {
		h.obs.Logger.WarnContext(ctx, "OIDC state expired", "age", age)
		shared.RenderTemplate(ctx, w, http.StatusBadRequest, oidcErrorTmpl, h.oidcError(r, "Invalid or expired state. Please try again."))
		return
	}

	// Browser binding — unchanged in behavior; reads state.BrowserNonce now.
	stateCookie, err := r.Cookie(oidcStateCookieName)
	if err != nil || !hmac.Equal([]byte(stateCookie.Value), []byte(state.BrowserNonce)) {
		h.obs.Logger.WarnContext(ctx, "OIDC state cookie mismatch")
		shared.RenderTemplate(ctx, w, http.StatusBadRequest, oidcErrorTmpl, h.oidcError(r, "Invalid or expired state. Please try again."))
		return
	}
	// Once binding passes the one-time cookie is ALWAYS burned. The delete needs
	// no policy (Secure/SameSite don't participate in the overwrite match), so it
	// never resolves the provider and can't be wedged into leaving the (state,
	// nonce) pair replayable.
	h.clearOIDCStateCookie(ctx, w)

	u, err := h.oidc.AuthenticateOIDC(ctx, code, state.Nonce, state.Verifier)
	if err != nil {
		if errors.Is(err, domain.ErrOIDCUnavailable) {
			// Upstream is unreachable — a server-side problem, not a failed
			// user authentication. Report 500 + ERROR so it surfaces in
			// monitoring instead of looking like the user mistyped something.
			h.obs.Logger.ErrorContext(ctx, "OIDC upstream unavailable on callback", "error", err)
			shared.RenderTemplate(ctx, w, http.StatusInternalServerError, oidcErrorTmpl, h.oidcError(r, "Sign-in is temporarily unavailable. Please try again later."))
			return
		}
		h.obs.Logger.WarnContext(ctx, "OIDC authentication failed", "error", err)
		shared.RenderTemplate(ctx, w, http.StatusUnauthorized, oidcErrorTmpl, h.oidcError(r, "Authentication failed. Please try again."))
		return
	}

	if err = h.session.SetSessionCookie(ctx, w, u.ID); err != nil {
		h.obs.Logger.ErrorContext(ctx, "OIDC: set session cookie failed", "error", err)
		shared.RenderTemplate(ctx, w, http.StatusInternalServerError, oidcErrorTmpl, h.oidcError(r, "Sign-in is temporarily unavailable. Please try again later."))
		return
	}
	h.obs.Logger.InfoContext(ctx, "OIDC user logged in", "user_id", u.ID, "email", u.Email)

	safe := shared.SafeRedirect(state.Redirect, "/")
	dest, err := h.urls.Resolve(ctx, safe)
	if err != nil {
		h.obs.Logger.ErrorContext(ctx, "build post-login URL", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, dest, http.StatusSeeOther)
}

// stateCookiePath scopes the OIDC state cookie to the AS mount (or "/" at the
// root) via the URLBuilder, matching the session cookie. A resolution error
// falls back to "/" (warn-logged, not fatal). Set and Clear MUST agree.
func (h *oidcHandler) stateCookiePath(ctx context.Context) string {
	return shared.ResolvePath(ctx, h.urls, "/", h.obs.Logger)
}

func (h *oidcHandler) setOIDCStateCookie(ctx context.Context, w http.ResponseWriter, nonce string, maxAge time.Duration, policy output.SessionConfig) {
	http.SetCookie(w, &http.Cookie{
		Name:     oidcStateCookieName,
		Value:    nonce,
		Path:     h.stateCookiePath(ctx),
		MaxAge:   shared.CookieMaxAgeSeconds(maxAge),
		HttpOnly: true,
		// Same boot Secure floor as the session cookie: a provider may tighten
		// Secure but never downgrade an HTTPS deployment. EffectiveSameSite
		// applies the zero-value (omitted-attribute) backstop.
		Secure:   policy.Secure || h.session.SecureFloor(),
		SameSite: policy.EffectiveSameSite(),
	})
}

// clearOIDCStateCookie burns the one-time state cookie. SameSite doesn't
// participate in the browser's overwrite match, but it does govern whether the
// browser accepts the Set-Cookie cross-site — so the delete carries the
// configured SameSite when the policy resolves best-effort, and a safe Lax +
// boot Secure floor when it doesn't (the burn still can't be wedged by a
// provider outage).
func (h *oidcHandler) clearOIDCStateCookie(ctx context.Context, w http.ResponseWriter) {
	sameSite := http.SameSiteLaxMode
	secure := h.session.SecureFloor()
	if policy, err := h.session.CookiePolicy(ctx); err == nil {
		sameSite = policy.EffectiveSameSite()
		secure = policy.Secure || h.session.SecureFloor()
	}
	http.SetCookie(w, &http.Cookie{
		Name:     oidcStateCookieName,
		Value:    "",
		Path:     h.stateCookiePath(ctx),
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   secure,
		SameSite: sameSite,
	})
}

// oidcError builds the OIDC error page data with the mount prefix populated.
func (h *oidcHandler) oidcError(r *http.Request, msg string) oidcErrorData {
	return oidcErrorData{
		Error:    msg,
		LoginURL: shared.ResolvePath(r.Context(), h.urls, "/login", h.obs.Logger),
	}
}

var oidcErrorTmpl = template.Must(template.New("oidc_error").Parse(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Authentication Error — Authplane</title>
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
padding:40px 36px;border:1px solid #e2e8f0;text-align:center}
.icon{margin-bottom:20px}
.icon svg{width:48px;height:48px}
h1{font-size:1.35em;font-weight:700;margin-bottom:12px;color:#0f172a;letter-spacing:-0.01em}
.error{background:#fef2f2;border:1px solid #fecaca;color:#b91c1c;padding:14px 18px;
border-radius:10px;margin-bottom:24px;font-size:0.9em;line-height:1.5}
a{display:inline-flex;align-items:center;gap:6px;color:#4f46e5;text-decoration:none;
font-weight:600;font-size:0.92em;transition:color 0.15s ease}
a:hover{color:#4338ca}
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
<div class="icon">
<svg viewBox="0 0 48 48" fill="none" xmlns="http://www.w3.org/2000/svg">
<circle cx="24" cy="24" r="20" fill="#fef2f2" stroke="#fecaca" stroke-width="1.5"/>
<path d="M24 16v10" stroke="#dc2626" stroke-width="2.5" stroke-linecap="round"/>
<circle cx="24" cy="32" r="1.5" fill="#dc2626"/>
</svg>
</div>
<h1>Authentication failed</h1>
<div class="error">{{.Error}}</div>
<a href="{{.LoginURL}}">Back to sign in</a>
</div>
<div class="footer">Secured by Authplane</div>
</div>
</body>
</html>`))

func randomHex(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic("crypto/rand: " + err.Error())
	}
	return hex.EncodeToString(b)
}
