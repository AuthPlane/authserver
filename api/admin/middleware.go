package admin

import (
	"crypto/subtle"
	"net/http"
	"strings"
)

// apiKeyMiddleware validates the API key on every request.
type apiKeyMiddleware struct {
	key []byte
}

func newAPIKeyMiddleware(key string) *apiKeyMiddleware {
	return &apiKeyMiddleware{key: []byte(key)}
}

// Wrap returns a handler that requires a valid API key.
func (m *apiKeyMiddleware) Wrap(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Reject all requests when no API key is configured.
		if len(m.key) == 0 {
			w.Header().Set("WWW-Authenticate", `Bearer realm="admin"`)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"error":"unauthorized","error_description":"admin API key not configured"}`))
			return
		}

		token := extractBearerToken(r)
		if token == "" {
			w.Header().Set("WWW-Authenticate", `Bearer realm="admin"`)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"error":"unauthorized","error_description":"missing API key"}`))
			return
		}

		if subtle.ConstantTimeCompare(m.key, []byte(token)) != 1 {
			w.Header().Set("WWW-Authenticate", `Bearer realm="admin"`)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"error":"unauthorized","error_description":"invalid API key"}`))
			return
		}

		next.ServeHTTP(w, r)
	})
}

func extractBearerToken(r *http.Request) string {
	auth := r.Header.Get("Authorization")
	if !strings.HasPrefix(auth, "Bearer ") {
		return ""
	}
	return auth[7:]
}
