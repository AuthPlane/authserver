package shared

import (
	"log/slog"
	"net/http"
	"strings"

	"github.com/authplane/authserver/internal/ports/output"
)

// SecurityHeaders returns middleware that sets standard HTTP security headers.
func SecurityHeaders(secure bool) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			h := w.Header()
			h.Set("X-Content-Type-Options", "nosniff")
			h.Set("X-Frame-Options", "DENY")
			h.Set("Referrer-Policy", "no-referrer")
			h.Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'none'")

			if secure {
				h.Set("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
			}

			// Cache-Control for HTML pages (login, consent, error).
			// Token endpoint sets its own Cache-Control: no-store.
			if isHTMLRequest(r) {
				h.Set("Cache-Control", "no-store")
			}

			next.ServeHTTP(w, r)
		})
	}
}

// isHTMLRequest heuristically detects HTML page requests (GET on non-API paths).
func isHTMLRequest(r *http.Request) bool {
	if r.Method != http.MethodGet {
		return false
	}
	p := r.URL.Path
	return p == "/login" || p == "/consent" || strings.HasPrefix(p, "/error")
}

// CORSMiddleware returns middleware that handles CORS preflight and response
// headers. Only endpoints that need cross-origin access (token, DCR, discovery,
// revoke) get CORS headers; login/consent are same-origin only.
//
// The allowed-origins allowlist is resolved from the provider per request
// rather than snapshotted at construction, so a deployment can vary origin
// policy per request. Resolution failures fail closed: no CORS headers are
// emitted for that request, never a fallback to a stale or process-wide list.
// The provider must be non-nil; api/public wires the static boot default when
// no alternative is supplied.
//
// A non-nil logger is used to record provider resolution failures at Error —
// otherwise a persistently failing alternative provider would disable CORS with
// no signal. The error is never written to the response. A nil logger disables
// this logging (used by tests that don't assert on it).
func CORSMiddleware(provider output.CORSConfigProvider, logger *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Restrict per-request resolution to the CORS-eligible endpoints
			// with an Origin header — everything else (login/consent, same-origin
			// calls) short-circuits before touching the provider.
			if !isCORSEndpoint(r.URL.Path) {
				next.ServeHTTP(w, r)
				return
			}

			origin := r.Header.Get("Origin")
			if origin == "" {
				next.ServeHTTP(w, r)
				return
			}

			allowedOrigins, err := provider.AllowedOrigins(r.Context())
			if err != nil {
				// Fail closed: emit no CORS headers for this request. Surface
				// the failure so a persistently broken provider is not silent;
				// never leak the error into the response.
				if logger != nil {
					logger.ErrorContext(r.Context(),
						"cors: allowed-origins resolution failed; failing closed (no CORS headers)",
						"error", err, "path", r.URL.Path)
				}
				next.ServeHTTP(w, r)
				return
			}

			allowAll := false
			allowed := false
			for _, o := range allowedOrigins {
				if o == "*" {
					allowAll = true
				}
				if o == origin {
					allowed = true
				}
			}
			if !allowed && !allowAll {
				next.ServeHTTP(w, r)
				return
			}

			respondOrigin := origin
			if allowAll {
				respondOrigin = "*"
			}

			h := w.Header()
			h.Set("Access-Control-Allow-Origin", respondOrigin)
			if !allowAll {
				h.Set("Vary", "Origin")
			}

			// Preflight.
			if r.Method == http.MethodOptions {
				h.Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
				h.Set("Access-Control-Allow-Headers", "Content-Type, Authorization, DPoP")
				h.Set("Access-Control-Max-Age", "86400")
				w.WriteHeader(http.StatusNoContent)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// isCORSEndpoint returns true for endpoints that browser-based MCP clients may call cross-origin.
func isCORSEndpoint(path string) bool {
	switch {
	case path == "/oauth/token",
		path == "/oauth/register",
		path == "/oauth/revoke",
		path == "/oauth/introspect",
		strings.HasPrefix(path, "/.well-known/"):
		return true
	default:
		return false
	}
}
