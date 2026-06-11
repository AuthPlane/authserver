package shared

import (
	"net/http"
	"strings"
)

// ExtractBearerToken returns the token value from an "Authorization: Bearer <token>"
// header. Returns empty string if the header is missing or malformed.
func ExtractBearerToken(r *http.Request) string {
	auth := r.Header.Get("Authorization")
	if auth == "" {
		return ""
	}
	const prefix = "Bearer "
	if len(auth) < len(prefix) || !strings.EqualFold(auth[:len(prefix)], prefix) {
		return ""
	}
	return auth[len(prefix):]
}

// ExtractAuthToken extracts the access token from the Authorization header.
// Supports both "Bearer <token>" and "DPoP <token>" schemes (RFC 9449 §7.1).
// Returns the raw token and the scheme name ("Bearer" or "DPoP").
// Returns empty strings if the header is missing or uses an unsupported scheme.
func ExtractAuthToken(r *http.Request) (token, scheme string) {
	auth := r.Header.Get("Authorization")
	if auth == "" {
		return "", ""
	}
	const bearerPrefix = "Bearer "
	if len(auth) >= len(bearerPrefix) && strings.EqualFold(auth[:len(bearerPrefix)], bearerPrefix) {
		return auth[len(bearerPrefix):], "Bearer"
	}
	const dpopPrefix = "DPoP "
	if len(auth) >= len(dpopPrefix) && strings.EqualFold(auth[:len(dpopPrefix)], dpopPrefix) {
		return auth[len(dpopPrefix):], "DPoP"
	}
	return "", ""
}

// RequestURL reconstructs the effective request URL (scheme + host + path)
// for DPoP htu validation (RFC 9449 §4.3). Respects X-Forwarded-Proto
// for reverse proxy deployments. Query string and fragment are stripped.
func RequestURL(r *http.Request) string {
	scheme := "https"
	if fwd := r.Header.Get("X-Forwarded-Proto"); fwd != "" {
		scheme = fwd
	} else if r.TLS == nil {
		scheme = "http"
	}
	return scheme + "://" + r.Host + r.URL.Path
}
