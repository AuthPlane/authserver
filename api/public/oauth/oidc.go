package oauth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"html/template"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/authplane/authserver/api/shared"
	"github.com/authplane/authserver/internal/crypto"
	"github.com/authplane/authserver/internal/observability"
)

const oidcStateCookieName = "authserver_oidc_state"

// oidcHandler handles OIDC start + callback endpoints.
type oidcHandler struct {
	oidc        OIDCFlowProvider
	session     *shared.SessionMiddleware
	obs         *observability.Provider
	redirectURI string
	stateKey    []byte
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

	// Bind state to the browser via a one-time nonce cookie.
	browserNonce := randomHex(16)
	h.setOIDCStateCookie(w, browserNonce)

	timestamp := strconv.FormatInt(time.Now().UTC().Unix(), 10)
	payload := redirect + "|" + nonce + "|" + verifier + "|" + browserNonce + "|" + timestamp
	sig := h.signState(payload)
	state := base64.RawURLEncoding.EncodeToString([]byte(payload + "|" + sig))

	authURL := h.oidc.AuthorizationURL(state, nonce, challenge, h.redirectURI)

	h.obs.Logger.DebugContext(r.Context(), "OIDC start redirect",
		"redirect_uri", h.redirectURI,
	)

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
		shared.RenderTemplate(ctx, w, http.StatusBadRequest, oidcErrorTmpl, oidcErrorData{
			Error: "Authentication failed. Please try again.",
		})
		return
	}

	code := r.URL.Query().Get("code")
	stateRaw := r.URL.Query().Get("state")
	if code == "" || stateRaw == "" {
		shared.RenderTemplate(ctx, w, http.StatusBadRequest, oidcErrorTmpl, oidcErrorData{
			Error: "Missing authorization code or state.",
		})
		return
	}

	stateBytes, err := base64.RawURLEncoding.DecodeString(stateRaw)
	if err != nil {
		shared.RenderTemplate(ctx, w, http.StatusBadRequest, oidcErrorTmpl, oidcErrorData{
			Error: "Invalid state parameter.",
		})
		return
	}

	redirect, nonce, verifier, browserNonce, err := h.verifyState(string(stateBytes))
	if err != nil {
		h.obs.Logger.WarnContext(ctx, "OIDC state verification failed", "error", err)
		shared.RenderTemplate(ctx, w, http.StatusBadRequest, oidcErrorTmpl, oidcErrorData{
			Error: "Invalid or expired state. Please try again.",
		})
		return
	}

	// Verify state is bound to this browser via the nonce cookie.
	stateCookie, err := r.Cookie(oidcStateCookieName)
	if err != nil || !hmac.Equal([]byte(stateCookie.Value), []byte(browserNonce)) {
		h.obs.Logger.WarnContext(ctx, "OIDC state cookie mismatch")
		shared.RenderTemplate(ctx, w, http.StatusBadRequest, oidcErrorTmpl, oidcErrorData{
			Error: "Invalid or expired state. Please try again.",
		})
		return
	}
	h.clearOIDCStateCookie(w)

	u, err := h.oidc.AuthenticateOIDC(ctx, code, nonce, verifier, h.redirectURI)
	if err != nil {
		h.obs.Logger.WarnContext(ctx, "OIDC authentication failed", "error", err)
		shared.RenderTemplate(ctx, w, http.StatusUnauthorized, oidcErrorTmpl, oidcErrorData{
			Error: "Authentication failed. Please try again.",
		})
		return
	}

	h.session.SetSessionCookie(w, u.ID)
	h.obs.Logger.InfoContext(ctx, "OIDC user logged in", "user_id", u.ID, "email", u.Email)

	http.Redirect(w, r, shared.SafeRedirect(redirect, "/"), http.StatusSeeOther)
}

func (h *oidcHandler) signState(payload string) string {
	mac := hmac.New(sha256.New, h.stateKey)
	mac.Write([]byte(payload))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

func (h *oidcHandler) verifyState(state string) (redirect, nonce, verifier, browserNonce string, err error) {
	parts := strings.SplitN(state, "|", 6)
	if len(parts) != 6 {
		return "", "", "", "", fmt.Errorf("invalid state format")
	}

	redirect = parts[0]
	nonce = parts[1]
	verifier = parts[2]
	browserNonce = parts[3]
	timestampStr := parts[4]
	sig := parts[5]

	payload := redirect + "|" + nonce + "|" + verifier + "|" + browserNonce + "|" + timestampStr
	expected := h.signState(payload)
	if !hmac.Equal([]byte(sig), []byte(expected)) {
		return "", "", "", "", fmt.Errorf("state signature mismatch")
	}

	timestamp, err := strconv.ParseInt(timestampStr, 10, 64)
	if err != nil {
		return "", "", "", "", fmt.Errorf("invalid state timestamp")
	}
	age := time.Since(time.Unix(timestamp, 0))
	if age > 10*time.Minute || age < -time.Minute {
		return "", "", "", "", fmt.Errorf("state expired (age: %v)", age)
	}

	return redirect, nonce, verifier, browserNonce, nil
}

func (h *oidcHandler) setOIDCStateCookie(w http.ResponseWriter, nonce string) {
	http.SetCookie(w, &http.Cookie{
		Name:     oidcStateCookieName,
		Value:    nonce,
		Path:     "/",
		MaxAge:   600,
		HttpOnly: true,
		Secure:   h.session.Secure(),
		SameSite: h.session.SameSite(),
	})
}

func (h *oidcHandler) clearOIDCStateCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     oidcStateCookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   h.session.Secure(),
		SameSite: h.session.SameSite(),
	})
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
<a href="/login">Back to sign in</a>
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
