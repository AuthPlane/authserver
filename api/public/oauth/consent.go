package oauth

import (
	"errors"
	"html/template"
	"net/http"
	"net/url"

	"github.com/authplane/authserver/api/shared"
	"github.com/authplane/authserver/internal/domain"
	"github.com/authplane/authserver/internal/observability"
	"github.com/authplane/authserver/internal/ports/input"
)

// consentHandler handles GET/POST /consent.
type consentHandler struct {
	consent ConsentProvider
	session *shared.SessionMiddleware
	obs     *observability.Provider
}

func (h *consentHandler) handleGetConsent(w http.ResponseWriter, r *http.Request) {
	sessionID := r.URL.Query().Get("session_id")
	if sessionID == "" {
		shared.WriteErrorPage(w, r, http.StatusBadRequest, "Missing Session", "No session_id provided.")
		return
	}

	_, ok := shared.UserIDFromContext(r.Context())
	if !ok {
		http.Redirect(w, r, "/login?redirect="+url.QueryEscape(r.URL.String()), http.StatusSeeOther)
		return
	}

	view, err := h.consent.GetPendingConsent(r.Context(), sessionID)
	if err != nil {
		h.obs.Logger.ErrorContext(r.Context(), "get pending consent failed", "error", err)
		switch {
		case errors.Is(err, domain.ErrConsentResourceNotMint):
			shared.WriteErrorPage(w, r, http.StatusBadRequest, "Invalid Resource", "Consent is only available for MCP resources, not upstream broker resources.")
		case errors.Is(err, domain.ErrResourceNotFound):
			shared.WriteErrorPage(w, r, http.StatusBadRequest, "Unknown Resource", "The requested resource is not registered with this authorization server.")
		case errors.Is(err, domain.ErrAmbiguousResource):
			shared.WriteErrorPage(w, r, http.StatusBadRequest, "Ambiguous Resource", "The resource identifier matches more than one resource. Use the resource slug to disambiguate.")
		default:
			shared.WriteErrorPage(w, r, http.StatusBadRequest, "Invalid Session", "The authorization session is invalid or expired.")
		}
		return
	}

	cookie, _ := r.Cookie(h.session.CookieName)
	csrfToken := ""
	if cookie != nil {
		csrfToken = h.session.CSRFToken(cookie.Value)
	}

	shared.RenderTemplate(r.Context(), w, http.StatusOK, consentTmpl, consentPageData{
		SessionID:           view.SessionID,
		ClientName:          view.ClientName,
		ClientID:            view.ClientID,
		Resource:            view.Resource,
		ResourceDisplayName: view.ResourceDisplayName,
		ResourceSlug:        view.ResourceSlug,
		Scopes:              view.Scopes,
		CSRFToken:           csrfToken,
	})
}

func (h *consentHandler) handlePostConsent(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		shared.WriteErrorPage(w, r, http.StatusBadRequest, "Invalid Form", "Could not parse form data.")
		return
	}

	userID, ok := shared.UserIDFromContext(r.Context())
	if !ok {
		shared.WriteErrorPage(w, r, http.StatusUnauthorized, "Not Authenticated", "Please log in first.")
		return
	}

	// Validate CSRF.
	cookie, _ := r.Cookie(h.session.CookieName)
	if cookie == nil || !h.session.ValidateCSRF(cookie.Value, r.FormValue("csrf_token")) {
		shared.WriteErrorPage(w, r, http.StatusForbidden, "Invalid Request", "CSRF validation failed. Please try again.")
		return
	}

	sessionID := r.FormValue("session_id")
	action := r.FormValue("action")

	if action == "deny" {
		if err := h.consent.DenyConsent(r.Context(), sessionID, userID); err != nil {
			h.obs.Logger.ErrorContext(r.Context(), "deny consent failed", "error", err)
		}
		shared.WriteErrorPage(w, r, http.StatusOK, "Access Denied", "You denied access to the application.")
		return
	}

	// Grant consent. The "Remember" wire flag is preserved for shape parity
	// but is now a no-op — the unified ConsentGrantStore.Upsert is
	// unconditional.
	approvedScopes := r.Form["scopes"]
	remember := r.FormValue("remember") == "on"

	// Guard at the handler: the form template renders requested scopes as
	// pre-checked boxes, so zero approved scopes can only come from a user
	// who actively unchecked everything and clicked allow. That is not
	// "approve everything" — surface a friendly error rather than letting
	// the service log invalid_scope as an opaque failure.
	if len(approvedScopes) == 0 {
		shared.WriteErrorPage(w, r, http.StatusBadRequest, "No Permissions Selected",
			"You must approve at least one permission to continue. Use the Deny button if you do not want to grant access.")
		return
	}

	result, err := h.consent.GrantConsent(r.Context(), input.GrantConsentRequest{
		SessionID:      sessionID,
		UserID:         userID,
		ApprovedScopes: approvedScopes,
		Remember:       remember,
	})
	if err != nil {
		h.obs.Logger.ErrorContext(r.Context(), "grant consent failed", "error", err)
		switch {
		case errors.Is(err, domain.ErrConsentResourceNotMint):
			shared.WriteErrorPage(w, r, http.StatusBadRequest, "Invalid Resource", "Consent is only available for MCP resources, not upstream broker resources.")
		case errors.Is(err, domain.ErrResourceNotFound):
			shared.WriteErrorPage(w, r, http.StatusBadRequest, "Unknown Resource", "The requested resource is not registered with this authorization server.")
		case errors.Is(err, domain.ErrAmbiguousResource):
			shared.WriteErrorPage(w, r, http.StatusBadRequest, "Ambiguous Resource", "The resource identifier matches more than one resource. Use the resource slug to disambiguate.")
		default:
			shared.WriteErrorPage(w, r, http.StatusBadRequest, "Consent Error", "Failed to process consent. The session may have expired.")
		}
		return
	}

	redirectWithCode(w, r, result.RedirectURI, result.Code, result.State)
}

// consentTmpl renders the per-MCP consent screen ( / DESIGN_v4 §7).
// Header reads "<ClientName> wants permission to access <ResourceDisplayName>";
// each scope item shows its human-readable description as the primary
// label with the scope name as a secondary monospace identifier.
var consentTmpl = template.Must(template.New("consent").Parse(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Authorize — Authplane</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:system-ui,-apple-system,'Segoe UI',Roboto,sans-serif;
background:#f8fafc;display:flex;justify-content:center;align-items:center;
min-height:100vh;padding:24px;color:#0f172a}
.wrapper{width:100%;max-width:480px}
.logo{text-align:center;margin-bottom:32px}
.logo svg{width:40px;height:40px}
.logo-text{font-size:0.85em;font-weight:600;color:#64748b;letter-spacing:0.05em;
text-transform:uppercase;margin-top:8px}
.card{background:#fff;border-radius:16px;
box-shadow:0 1px 3px rgba(0,0,0,0.04),0 8px 24px rgba(0,0,0,0.06);
padding:40px 36px;border:1px solid #e2e8f0}
.header{text-align:center;margin-bottom:28px}
h1{font-size:1.4em;font-weight:700;margin-bottom:8px;color:#0f172a;letter-spacing:-0.01em;line-height:1.35}
.target{color:#4f46e5}
.info{color:#475569;font-size:0.92em;line-height:1.6}
.client{font-weight:700;color:#0f172a}
.resource{display:inline-flex;align-items:center;gap:8px;background:#f1f5f9;
color:#475569;font-size:0.82em;padding:6px 12px;border-radius:8px;margin-top:12px;
font-family:ui-monospace,SFMono-Regular,Menlo,monospace;border:1px solid #e2e8f0}
.resource .slug{font-weight:600;color:#1e293b}
.resource .sep{color:#cbd5e1}
.section-label{font-size:0.8em;font-weight:600;text-transform:uppercase;
letter-spacing:0.05em;color:#64748b;margin-bottom:10px}
.scopes{margin:0 0 24px;padding:0;list-style:none}
.scopes li{padding:14px 16px;background:#f8fafc;border:1px solid #e2e8f0;
border-radius:12px;margin-bottom:8px;display:flex;align-items:flex-start;gap:12px;
transition:all 0.15s ease}
.scopes li:hover{border-color:#c7d2fe;background:#fafafe}
.scopes input[type=checkbox]{width:18px;height:18px;margin-top:2px;accent-color:#4f46e5;
border-radius:4px;flex-shrink:0;cursor:pointer}
.scopes .desc{font-weight:600;font-size:0.9em;color:#1e293b;line-height:1.4}
.scopes .name{color:#64748b;font-size:0.82em;margin-top:3px;
font-family:ui-monospace,SFMono-Regular,Menlo,monospace}
.remember{display:flex;align-items:center;gap:10px;margin-bottom:24px;
font-size:0.88em;color:#64748b;cursor:pointer}
.remember input{accent-color:#4f46e5;width:16px;height:16px;cursor:pointer}
.buttons{display:flex;gap:12px}
.buttons button{flex:1;padding:12px 20px;border:none;border-radius:10px;font-size:0.95em;
font-weight:600;cursor:pointer;transition:all 0.2s ease;letter-spacing:0.01em}
.btn-allow{background:#4f46e5;color:#fff}
.btn-allow:hover{background:#4338ca;box-shadow:0 4px 12px rgba(79,70,229,0.3)}
.btn-allow:active{transform:scale(0.99)}
.btn-deny{background:#fff;color:#475569;border:1px solid #cbd5e1}
.btn-deny:hover{background:#f8fafc;border-color:#94a3b8;color:#1e293b}
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
<div class="header">
{{if .ResourceDisplayName}}
<h1><span class="client">{{.ClientName}}</span> wants permission to access <span class="target">{{.ResourceDisplayName}}</span></h1>
{{else}}
<h1>Authorize access</h1>
<p class="info"><span class="client">{{.ClientName}}</span> wants to access your account</p>
{{end}}
{{if .ResourceSlug}}<div class="resource"><span class="slug">{{.ResourceSlug}}</span><span class="sep">·</span><span>{{.Resource}}</span></div>{{else if .Resource}}<div class="resource">{{.Resource}}</div>{{end}}
</div>
<form method="POST" action="/consent">
<input type="hidden" name="session_id" value="{{.SessionID}}">
<input type="hidden" name="csrf_token" value="{{.CSRFToken}}">
<div class="section-label">Permissions requested</div>
<ul class="scopes">
{{range .Scopes}}
<li>
<input type="checkbox" name="scopes" value="{{.Name}}" id="scope-{{.Name}}" checked>
<label for="scope-{{.Name}}" style="cursor:pointer">
{{if .Description}}<div class="desc">{{.Description}}</div>{{end}}
<div class="name">{{.Name}}</div>
</label>
</li>
{{end}}
</ul>
<label class="remember">
<input type="checkbox" name="remember"> Remember this decision
</label>
<div class="buttons">
<button type="submit" name="action" value="deny" class="btn-deny">Deny</button>
<button type="submit" name="action" value="allow" class="btn-allow">Allow access</button>
</div>
</form>
</div>
<div class="footer">Secured by Authplane</div>
</div>
</body>
</html>`))
