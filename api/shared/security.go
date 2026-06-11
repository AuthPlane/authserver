package shared

import (
	"net/http"
	"strings"
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

// CORSConfig controls Cross-Origin Resource Sharing.
type CORSConfig struct {
	AllowedOrigins []string // Exact origins to allow. Empty = no CORS headers.
}

// CORSMiddleware returns middleware that handles CORS preflight and response headers.
// Only endpoints that need cross-origin access (token, DCR, discovery, revoke)
// get CORS headers. Login/consent are same-origin only.
func CORSMiddleware(cfg CORSConfig) func(http.Handler) http.Handler {
	origins := make(map[string]struct{}, len(cfg.AllowedOrigins))
	allowAll := false
	for _, o := range cfg.AllowedOrigins {
		if o == "*" {
			allowAll = true
		}
		origins[o] = struct{}{}
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if len(origins) == 0 {
				next.ServeHTTP(w, r)
				return
			}

			if !isCORSEndpoint(r.URL.Path) {
				next.ServeHTTP(w, r)
				return
			}

			origin := r.Header.Get("Origin")
			if origin == "" {
				next.ServeHTTP(w, r)
				return
			}

			_, allowed := origins[origin]
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
