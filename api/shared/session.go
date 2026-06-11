// Package shared provides middleware and error helpers used by both
// the public and admin HTTP servers.
package shared

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/authplane/authserver/internal/domain"
	"github.com/authplane/authserver/internal/ports/output"
)

type contextKey string

const userIDKey contextKey = "userID"

// UserIDFromContext returns the authenticated user ID from the request context.
func UserIDFromContext(ctx context.Context) (string, bool) {
	id, ok := ctx.Value(userIDKey).(string)
	return id, ok
}

// SessionMiddleware manages HMAC-signed stateless session cookies.
// Cookie format: userID|expiryUnix|base64(hmac-sha256(userID|expiryUnix))
type SessionMiddleware struct {
	secret     []byte
	CookieName string
	MaxAge     time.Duration
	secure     bool
	sameSite   http.SameSite
	users      output.UserStore
	logger     *slog.Logger
	failClosed bool
}

// NewSessionMiddleware creates a new session middleware.
func NewSessionMiddleware(secret []byte, cookieName string, maxAge time.Duration, secure bool, sameSite http.SameSite) *SessionMiddleware {
	return &SessionMiddleware{
		secret:     secret,
		CookieName: cookieName,
		MaxAge:     maxAge,
		secure:     secure,
		sameSite:   sameSite,
	}
}

// SetUserStore installs the UserStore consulted by Wrap to reject session
// cookies whose userID no longer exists in the database. The store
// is expected to be the same one used elsewhere in the app — typically the
// cache-fronted version produced by storage.WithUserCache so this lookup
// does not become a DB query per request.
//
// When nil (the default), Wrap preserves the legacy behavior of accepting
// any cookie that passes HMAC + expiry. Tests may rely on the nil default.
func (m *SessionMiddleware) SetUserStore(u output.UserStore) {
	m.users = u
}

// SetLogger installs a logger used to record stale-session and transient-error
// events. If unset, those events are silent.
func (m *SessionMiddleware) SetLogger(l *slog.Logger) {
	m.logger = l
}

// SetFailClosed selects the policy for transient user-store lookup errors
// in Wrap. When true, any non-ErrUserNotFound error from UserStore.GetByID
// clears the cookie and continues anonymously. When false (default), the
// cookie is kept on transient errors so a brief DB outage does not log
// every user out.
func (m *SessionMiddleware) SetFailClosed(failClosed bool) {
	m.failClosed = failClosed
}

// Wrap returns middleware that extracts the user ID from the session cookie.
//
// When a UserStore is installed, the middleware additionally verifies the
// userID still resolves in the database. A cookie that points at a deleted
// user is cleared and the request continues anonymously (downstream handlers
// see no userID and redirect to /login as if no cookie were present).
//
// On a transient store error, behavior depends on SetFailClosed:
//   - fail-open (default): the userID is kept on the context and the cookie
//     is preserved, so a DB blip does not log every user out
//   - fail-closed: the cookie is cleared and the request continues
//     anonymously, so a disabled / deleted user cannot ride out a DB
//     outage with a still-valid cookie. Recommended for admin-adjacent
//     and high-assurance deployments
func (m *SessionMiddleware) Wrap(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie(m.CookieName)
		if err != nil || cookie.Value == "" {
			next.ServeHTTP(w, r)
			return
		}

		userID, err := m.validateCookie(cookie.Value)
		if err != nil {
			next.ServeHTTP(w, r)
			return
		}

		if m.users != nil {
			_, lookupErr := m.users.GetByID(r.Context(), userID)
			switch {
			case lookupErr == nil:
				// User exists; fall through to put userID on context.
			case errors.Is(lookupErr, domain.ErrUserNotFound):
				if m.logger != nil {
					m.logger.WarnContext(r.Context(),
						"session: rejecting stale session cookie",
						"stale_session", true,
						"user_id", userID,
					)
				}
				m.ClearSessionCookie(w)
				next.ServeHTTP(w, r)
				return
			default:
				// Transient store error. Fail policy controlled by
				// SetFailClosed; default is fail-open so a DB blip
				// doesn't log everyone out.
				mode := "open"
				if m.failClosed {
					mode = "closed"
				}
				if m.logger != nil {
					m.logger.ErrorContext(r.Context(),
						"session: user existence check failed",
						"error", lookupErr,
						"user_id", userID,
						"fail_mode", mode,
					)
				}
				if m.failClosed {
					m.ClearSessionCookie(w)
					next.ServeHTTP(w, r)
					return
				}
			}
		}

		ctx := context.WithValue(r.Context(), userIDKey, userID)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// SetSessionCookie creates and sets an HMAC-signed session cookie.
func (m *SessionMiddleware) SetSessionCookie(w http.ResponseWriter, userID string) {
	expiry := time.Now().UTC().Add(m.MaxAge).Unix()
	payload := fmt.Sprintf("%s|%d", userID, expiry)
	sig := m.sign(payload)

	value := fmt.Sprintf("%s|%s", payload, sig)

	http.SetCookie(w, &http.Cookie{
		Name:     m.CookieName,
		Value:    value,
		Path:     "/",
		MaxAge:   int(m.MaxAge.Seconds()),
		HttpOnly: true,
		Secure:   m.secure,
		SameSite: m.sameSite,
	})
}

// ClearSessionCookie expires the session cookie.
func (m *SessionMiddleware) ClearSessionCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     m.CookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   m.secure,
		SameSite: m.sameSite,
	})
}

// CSRFToken generates a CSRF token from the session cookie value.
// Token = base64(hmac-sha256(cookieValue, secret+"csrf")).
func (m *SessionMiddleware) CSRFToken(cookieValue string) string {
	mac := hmac.New(sha256.New, append(m.secret, []byte("csrf")...))
	mac.Write([]byte(cookieValue))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

// ValidateCSRF checks that the CSRF token matches the cookie value.
func (m *SessionMiddleware) ValidateCSRF(cookieValue, token string) bool {
	expected := m.CSRFToken(cookieValue)
	return hmac.Equal([]byte(expected), []byte(token))
}

func (m *SessionMiddleware) validateCookie(value string) (string, error) {
	parts := strings.SplitN(value, "|", 3)
	if len(parts) != 3 {
		return "", fmt.Errorf("invalid cookie format")
	}

	userID := parts[0]
	expiryStr := parts[1]
	sig := parts[2]

	// Verify signature.
	payload := fmt.Sprintf("%s|%s", userID, expiryStr)
	expected := m.sign(payload)
	if !hmac.Equal([]byte(sig), []byte(expected)) {
		return "", fmt.Errorf("invalid cookie signature")
	}

	// Check expiry.
	expiry, err := strconv.ParseInt(expiryStr, 10, 64)
	if err != nil {
		return "", fmt.Errorf("invalid expiry")
	}
	if time.Now().UTC().Unix() > expiry {
		return "", fmt.Errorf("cookie expired")
	}

	return userID, nil
}

func (m *SessionMiddleware) sign(payload string) string {
	mac := hmac.New(sha256.New, m.secret)
	mac.Write([]byte(payload))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

// Secure returns whether cookies should have the Secure flag.
func (m *SessionMiddleware) Secure() bool {
	return m.secure
}

// SameSite returns the SameSite policy for cookies.
func (m *SessionMiddleware) SameSite() http.SameSite {
	return m.sameSite
}

// DeriveKey derives a purpose-specific key from the session secret via HMAC.
// Used for OIDC state signing so the raw session secret is not shared.
func (m *SessionMiddleware) DeriveKey(purpose string) []byte {
	mac := hmac.New(sha256.New, m.secret)
	mac.Write([]byte(purpose))
	return mac.Sum(nil)
}

// ParseSameSite converts a string to http.SameSite.
func ParseSameSite(s string) http.SameSite {
	switch strings.ToLower(s) {
	case "strict":
		return http.SameSiteStrictMode
	case "none":
		return http.SameSiteNoneMode
	default:
		return http.SameSiteLaxMode
	}
}
