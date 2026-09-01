package shared

import (
	"bytes"
	"context"
	"encoding/json"
	"html/template"
	"log/slog"
	"net/http"
)

// WriteOAuthError writes an RFC 6749 / RFC 9457 hybrid error response.
// Includes both OAuth error fields and RFC 9457 Problem Details fields.
func WriteOAuthError(w http.ResponseWriter, status int, errCode, description string) {
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(OAuthErrorResponse{
		Error:            errCode,
		ErrorDescription: description,
		Type:             "https://docs.authplane.ai/errors/" + errCode,
		Title:            http.StatusText(status),
		Detail:           description,
		Status:           status,
	})
}

// OAuthErrorResponse is the combined OAuth + RFC 9457 error response.
type OAuthErrorResponse struct {
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description"`
	Type             string `json:"type"`
	Title            string `json:"title"`
	Detail           string `json:"detail"`
	Status           int    `json:"status"`
	// ConsentURL is a URL to a consent page where the user can authorize the
	// AS to access an upstream provider. Populated only by
	// WriteOAuthErrorWithConsent / WriteOAuthErrorWithConsentAndCause; omitted
	// from all other error responses.
	ConsentURL string `json:"consent_url,omitempty"`
	// Cause is a sub-discriminator for consent_required errors.
	// Values currently in use: "consent_missing" (user never authorized this
	// agent for this resource), "scope_insufficient" (user authorized a
	// strict subset of the requested scopes). Empty for non-consent errors
	// and for legacy consent errors that predate the field. Wire format is
	// `cause` (lowercase, omitempty).
	Cause string `json:"cause,omitempty"`
}

// WriteOAuthErrorWithConsent writes an OAuth error response that includes a
// `consent_url` field pointing to the AS consent page for a vault-backed
// upstream service. Used only by the token endpoint when it detects a
// *domain.ConsentRequiredError.
//
// : this is now a thin wrapper around WriteOAuthErrorWithConsentAndCause
// that omits the `cause` field on the wire (caller did not supply one).
func WriteOAuthErrorWithConsent(w http.ResponseWriter, status int, errCode, description, consentURL string) {
	WriteOAuthErrorWithConsentAndCause(w, status, errCode, description, consentURL, "")
}

// WriteOAuthErrorWithConsentAndCause writes an OAuth error response that
// includes a `consent_url` field and a `cause` sub-discriminator. The cause
// value is one of domain.CauseConsentMissing / domain.CauseScopeInsufficient;
// empty omits the field on the wire.
func WriteOAuthErrorWithConsentAndCause(w http.ResponseWriter, status int, errCode, description, consentURL, cause string) {
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(OAuthErrorResponse{
		Error:            errCode,
		ErrorDescription: description,
		Type:             "https://docs.authplane.ai/errors/" + errCode,
		Title:            http.StatusText(status),
		Detail:           description,
		Status:           status,
		ConsentURL:       consentURL,
		Cause:            cause,
	})
}

// WriteErrorPage renders a minimal HTML error page for non-redirectable errors
// (e.g., invalid client_id or redirect_uri where we must NOT redirect).
func WriteErrorPage(w http.ResponseWriter, r *http.Request, status int, title, message string) {
	RenderTemplate(r.Context(), w, status, ErrorPageTmpl, struct {
		Title   string
		Message string
	}{title, message})
}

// RenderTemplate executes a template into a buffer and writes the result to w.
// If the template fails, it writes a plain 500 error instead of partial HTML.
func RenderTemplate(ctx context.Context, w http.ResponseWriter, status int, tmpl *template.Template, data any) {
	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, data); err != nil {
		slog.ErrorContext(ctx, "template execute error", "error", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	if _, err := buf.WriteTo(w); err != nil {
		slog.ErrorContext(ctx, "failed to write response", "error", err)
	}
}

// WriteJSON writes a JSON response.
func WriteJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// ErrorPageTmpl is the shared error page template.
var ErrorPageTmpl = template.Must(template.New("error").Parse(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{{.Title}} — Authplane</title>
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
p{color:#475569;font-size:0.92em;line-height:1.6}
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
<h1>{{.Title}}</h1>
<p>{{.Message}}</p>
</div>
<div class="footer">Secured by Authplane</div>
</div>
</body>
</html>`))
