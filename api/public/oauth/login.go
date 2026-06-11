package oauth

import (
	"html/template"
	"net/http"

	"github.com/authplane/authserver/api/shared"
	"github.com/authplane/authserver/internal/observability"
)

// loginHandler handles login and logout endpoints.
type loginHandler struct {
	auth            UserAuthProvider
	session         *shared.SessionMiddleware
	obs             *observability.Provider
	rl              *shared.RateLimiter
	oidcDisplayName string
	showLocalLogin  bool
}

func (h *loginHandler) handleGetLogin(w http.ResponseWriter, r *http.Request) {
	redirect := r.URL.Query().Get("redirect")
	csrfToken := h.csrfForRequest(r)

	data := loginPageData{
		Redirect:       redirect,
		CSRFToken:      csrfToken,
		ShowLocalLogin: h.showLocalLogin,
	}
	if h.oidcDisplayName != "" {
		data.OIDCDisplayName = h.oidcDisplayName
		data.OIDCStartURL = "/oidc/start?redirect=" + template.URLQueryEscaper(redirect)
	}

	shared.RenderTemplate(r.Context(), w, http.StatusOK, loginTmpl, data)
}

func (h *loginHandler) handlePostLogin(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<16) // 64KB
	if err := r.ParseForm(); err != nil {
		h.renderLoginError(w, r, "Invalid form data")
		return
	}

	// Validate CSRF — always enforced, even without a session cookie.
	// CSRFToken("") produces a deterministic token for no-cookie state,
	// which the login form includes via csrfForRequest.
	csrfToken := r.FormValue("csrf_token")
	cookie, _ := r.Cookie(h.session.CookieName)
	cookieVal := ""
	if cookie != nil {
		cookieVal = cookie.Value
	}
	if !h.session.ValidateCSRF(cookieVal, csrfToken) {
		h.renderLoginError(w, r, "Invalid request. Please try again.")
		return
	}

	email := r.FormValue("email")
	password := r.FormValue("password")
	redirect := r.FormValue("redirect")

	u, err := h.auth.Authenticate(r.Context(), email, password)
	if err != nil {
		h.obs.Logger.WarnContext(r.Context(), "login failed", "email", email, "error", err)
		if h.rl != nil {
			h.rl.RecordAuthFailure(shared.ClientIP(r))
		}
		h.renderLoginError(w, r, "Invalid email or password")
		return
	}

	h.session.SetSessionCookie(w, u.ID)
	h.obs.Logger.InfoContext(r.Context(), "user logged in", "user_id", u.ID, "email", email)

	http.Redirect(w, r, shared.SafeRedirect(redirect, "/"), http.StatusSeeOther)
}

func (h *loginHandler) handlePostLogout(w http.ResponseWriter, r *http.Request) {
	h.session.ClearSessionCookie(w)
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

func (h *loginHandler) renderLoginError(w http.ResponseWriter, r *http.Request, errMsg string) {
	redirect := r.FormValue("redirect")
	csrfToken := h.csrfForRequest(r)

	data := loginPageData{
		Error:          errMsg,
		Redirect:       redirect,
		CSRFToken:      csrfToken,
		ShowLocalLogin: h.showLocalLogin,
	}
	if h.oidcDisplayName != "" {
		data.OIDCDisplayName = h.oidcDisplayName
		data.OIDCStartURL = "/oidc/start?redirect=" + template.URLQueryEscaper(redirect)
	}

	shared.RenderTemplate(r.Context(), w, http.StatusUnprocessableEntity, loginTmpl, data)
}

func (h *loginHandler) csrfForRequest(r *http.Request) string {
	cookie, _ := r.Cookie(h.session.CookieName)
	if cookie != nil && cookie.Value != "" {
		return h.session.CSRFToken(cookie.Value)
	}
	return h.session.CSRFToken("")
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
{{if .ShowLocalLogin}}<form method="POST" action="/login">
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
