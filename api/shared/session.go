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

// Values of the "reason" field Wrap logs when it rejects a session cookie whose
// signature and expiry were valid. Add new causes as values here, not as new
// fields, so operator queries keep working.
const (
	// The store no longer has this user. Expected after a deletion.
	reasonUserNotFound = "user_not_found"

	// The user exists but is not active. Expected: an admin disable taking
	// effect.
	reasonUserDisabled = "user_disabled"

	// The UserStore returned neither a user nor an error, which its contract
	// forbids. A defect in the store rather than an account state.
	reasonStoreReturnedNil = "store_returned_nil"
)

// levelFor pairs each reason with the level it is logged at, so the two cannot
// drift: the routine rejections are WARN, a store breaking its contract is
// ERROR. An unmapped reason is a programming error and is logged loudly.
func levelFor(reason string) slog.Level {
	switch reason {
	case reasonUserNotFound, reasonUserDisabled:
		return slog.LevelWarn
	default:
		return slog.LevelError
	}
}

// errSecretUnavailable tags a FATAL failure to resolve the session secret, so
// Wrap can tell it apart from a benign cookie-validation failure (bad signature,
// malformed payload, expiry). A secret-resolution failure must never fall
// through to the anonymous path — that would let an attacker who can induce a
// resolution error bypass the signed cookie.
var errSecretUnavailable = errors.New("session secret unavailable")

// errConfigUnavailable tags a FATAL failure to resolve the session config.
// Like errSecretUnavailable, it must never fall through to the anonymous path.
var errConfigUnavailable = errors.New("session config unavailable")

// CookieMaxAgeSeconds converts a lifetime to the integer seconds an http.Cookie
// Max-Age attribute takes, rounding UP so a positive sub-second lifetime never
// truncates to 0. That matters because http.Cookie treats MaxAge 0 as "omit the
// attribute" — i.e. a session cookie the browser keeps indefinitely — which is
// the opposite of the near-immediate expiry the caller asked for.
func CookieMaxAgeSeconds(d time.Duration) int {
	if d <= 0 {
		return 0
	}
	secs := int(d / time.Second)
	if d%time.Second != 0 {
		secs++
	}
	return secs
}

// SessionMiddleware manages HMAC-signed stateless session cookies.
// Cookie format: userID|expiryUnix|base64(hmac-sha256(userID|expiryUnix))
type SessionMiddleware struct {
	secrets     output.SessionSecretProvider
	cfg         output.SessionConfigProvider
	CookieName  string
	secureFloor bool
	users       output.UserStore
	urls        output.URLBuilder
	logger      *slog.Logger
}

// NewSessionMiddleware creates a new session middleware. secretProvider supplies
// the HMAC secret per request; cfgProvider supplies the cookie policy
// (MaxAge/Secure/SameSite/FailClosed) per request. cookieName and secureFloor
// are boot-time. secureFloor is the deployment's Secure (HTTPS) posture: cookies
// are issued with Secure = provider.Secure || secureFloor, so an alternative
// provider can only *tighten* Secure, never downgrade an HTTPS/HSTS deployment.
// It is a constructor arg rather than a setter precisely because forgetting it
// would silently lose the floor — a security-relevant default.
func NewSessionMiddleware(secretProvider output.SessionSecretProvider, cfgProvider output.SessionConfigProvider, cookieName string, secureFloor bool) *SessionMiddleware {
	return &SessionMiddleware{
		secrets:     secretProvider,
		cfg:         cfgProvider,
		CookieName:  cookieName,
		secureFloor: secureFloor,
	}
}

// config resolves the per-request cookie policy, tagging any failure with
// errConfigUnavailable so callers can map it to a 500 (never anonymous).
func (m *SessionMiddleware) config(ctx context.Context) (output.SessionConfig, error) {
	c, err := m.cfg.Config(ctx)
	if err != nil {
		return output.SessionConfig{}, fmt.Errorf("%w: %w", errConfigUnavailable, err)
	}
	return c, nil
}

// failClosed resolves SessionConfig.FailClosed for this request. It answers the
// one question the policy exists for: the store did not tell us the account's
// status, so does this deployment prefer revocation freshness or availability?
//
// True when the policy itself cannot be resolved — an unreadable policy means
// the operator's intent is unknown, and the conservative reading is the one to
// take on a branch that exists for high-assurance revocation.
func (m *SessionMiddleware) failClosed(ctx context.Context) bool {
	c, err := m.config(ctx)
	if err != nil {
		if m.logger != nil {
			m.logger.ErrorContext(ctx, "session config resolution failed; failing closed", "error", err)
		}
		return true
	}
	return c.FailClosed
}

// SecureFloor reports the boot Secure floor so other cookie writers (the OIDC
// state cookie) can apply the same "provider may only tighten" clamp.
func (m *SessionMiddleware) SecureFloor() bool { return m.secureFloor }

// secureFor clamps a resolved policy's Secure up to the boot floor.
func (m *SessionMiddleware) secureFor(c output.SessionConfig) bool {
	return c.Secure || m.secureFloor
}

// secret resolves the per-request HMAC key via the provider, tagging any failure
// with errSecretUnavailable. Every HMAC operation routes through here so the
// fatal-on-error contract holds uniformly across sign / CSRF / validate.
func (m *SessionMiddleware) secret(ctx context.Context) ([]byte, error) {
	s, err := m.secrets.Secret(ctx)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", errSecretUnavailable, err)
	}
	return s, nil
}

// SetUserStore installs the UserStore that Wrap consults to reject cookies
// naming a deleted or disabled user. Pass the cache-fronted store
// (storage.WithUserCache), or this becomes a DB query per request.
//
// Required in production: /authorize and /consent perform no user check of
// their own, so this is the only thing that makes a disable take effect on the
// front channel. When nil (the default) Wrap accepts any cookie that passes
// HMAC and expiry, which some tests rely on.
func (m *SessionMiddleware) SetUserStore(u output.UserStore) {
	m.users = u
}

// SetLogger installs a logger used to record rejected session cookies (see the
// reason constants above) and transient-error events. If unset, those events
// are silent.
func (m *SessionMiddleware) SetLogger(l *slog.Logger) {
	m.logger = l
}

// Wrap returns middleware that extracts the user ID from the session cookie.
//
// With a UserStore installed it also checks that the user still resolves and is
// still active. A cookie naming a deleted or disabled user is cleared and the
// request continues anonymously, so downstream handlers behave as if no cookie
// were present. Without a store, neither check runs — see SetUserStore.
//
// Two things to know before relying on this for revocation:
//
//   - With the expected cache-fronted store it is bounded by the cache TTL,
//     not immediate — on every instance, including the one serving the change,
//     and for deletes as well as disables. See WrapUserStore in
//     internal/adapters/storage for the two windows and why they differ. With a
//     raw store the check is immediate and there is no TTL.
//
//   - A transient store error is resolved by SessionConfig.FailClosed, which
//     defaults to true: the cookie is cleared and the request continues
//     anonymously, so a disabled user cannot ride out a DB outage. Set it to
//     false to keep the session instead, when a blip logging everyone out is
//     worse than a stale session surviving one.
func (m *SessionMiddleware) Wrap(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie(m.CookieName)
		if err != nil || cookie.Value == "" {
			next.ServeHTTP(w, r)
			return
		}

		userID, err := m.validateCookie(r.Context(), cookie.Value)
		if err != nil {
			// Fatal: the secret could not be resolved. Never fall through to
			// the anonymous path — that would let an attacker bypass the signed
			// cookie by inducing a resolution error. Respond 500 and stop.
			if errors.Is(err, errSecretUnavailable) {
				if m.logger != nil {
					m.logger.ErrorContext(r.Context(), "session secret resolution failed", "error", err)
				}
				http.Error(w, "internal server error", http.StatusInternalServerError)
				return
			}
			// Benign: malformed / bad-signature / expired cookie. Treat as if
			// no cookie were present.
			next.ServeHTTP(w, r)
			return
		}

		if m.users != nil {
			u, lookupErr := m.users.GetByID(r.Context(), userID)
			// An unwrapped store spells "neither user nor error" as (nil, nil);
			// storage.WithUserCache spells it as an error. Normalizing here is
			// what makes the two take the same arm below, rather than two
			// branches that have to be kept in step by hand — whether a store is
			// wrapped decides the spelling, not the meaning. It also leaves
			// `lookupErr == nil` guaranteeing a non-nil user, so the arm below
			// cannot dereference one.
			if lookupErr == nil && u == nil {
				lookupErr = domain.ErrStoreReturnedNoUser
			}
			switch {
			case lookupErr == nil:
				if !u.IsActive() {
					m.rejectCookie(w, r, next, reasonUserDisabled, userID)
					return
				}
				// User exists and is active; fall through to put userID on context.
			case errors.Is(lookupErr, domain.ErrUserNotFound):
				m.rejectCookie(w, r, next, reasonUserNotFound, userID)
				return
			case errors.Is(lookupErr, domain.ErrStoreReturnedNoUser):
				// Both spellings of the defect land here, wrapped and raw. It
				// leaves the account's status exactly as unknown as a timeout
				// does, so the operator's FailClosed choice governs it too:
				// which of the two it is cannot be told apart from here, since
				// a permanently broken store and a replica answering empty
				// through a failover both arrive as this. Kept separate from
				// the transient arm below only so the cause still reaches
				// operators under its own reason, at ERROR.
				if m.failClosed(r.Context()) {
					m.rejectCookie(w, r, next, reasonStoreReturnedNil, userID)
					return
				}
				if m.logger != nil {
					m.logger.ErrorContext(r.Context(),
						"session: user store returned no user",
						"reason", reasonStoreReturnedNil,
						"user_id", userID,
						"fail_mode", "open",
					)
				}
			default:
				// Transient store error, resolved by SessionConfig.FailClosed
				// (see Wrap). Never 500s.
				failClosed := m.failClosed(r.Context())
				mode := "open"
				if failClosed {
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
				if failClosed {
					m.clearCookie(r.Context(), w)
					next.ServeHTTP(w, r)
					return
				}
			}
		}

		ctx := context.WithValue(r.Context(), userIDKey, userID)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// rejectCookie clears the session cookie and lets the request continue
// anonymously.
//
// The three branches that decided something about the account go through here
// and must stay identical: /authorize and /consent are guarded only by the
// absence of a userID on the context, so a divergence silently reopens both.
//
// The transient-store branch does not. It clears and continues inline because
// it also has to report the fail-open/fail-closed decision, which is not a
// rejection reason, so it logs its own event with error and fail_mode instead
// of a reason. Anything added here — a metric, a header — has to be added
// there too.
//
// reason is one of the constants above; levelFor decides how loudly it is logged.
func (m *SessionMiddleware) rejectCookie(
	w http.ResponseWriter, r *http.Request, next http.Handler,
	reason, userID string,
) {
	if m.logger != nil {
		m.logger.Log(r.Context(), levelFor(reason), "session: rejecting session cookie",
			"reason", reason, "user_id", userID)
	}
	// A delete needs no policy (Secure/SameSite don't participate in the
	// browser's overwrite match), so clear best-effort and continue
	// anonymous — a policy-provider outage must never leave a stale cookie
	// uncleared or turn this into a 500.
	m.clearCookie(r.Context(), w)
	next.ServeHTTP(w, r)
}

// SetURLBuilder installs the URLBuilder used to scope the session cookie's
// Path to the mount the AS is served under. When nil (the default), the
// cookie Path is "/" — byte-identical to the pre-patch behavior.
func (m *SessionMiddleware) SetURLBuilder(u output.URLBuilder) {
	m.urls = u
}

// cookiePath returns the Path attribute for the session cookie: the AS mount
// resolved from the root path ("/"), or "/" at the root. Set and Clear MUST use
// the same Path or the browser will not clear the cookie — both go through this
// one helper. A nil URLBuilder or resolution error falls back to "/" (warn-
// logged via ResolvePath), byte-identical to the pre-patch behavior.
func (m *SessionMiddleware) cookiePath(ctx context.Context) string {
	return ResolvePath(ctx, m.urls, "/", m.logger)
}

// SetSessionCookie creates and sets an HMAC-signed session cookie. It returns an
// error only when the session secret cannot be resolved; callers MUST surface
// that as a 500 rather than proceed without a signed cookie.
func (m *SessionMiddleware) SetSessionCookie(ctx context.Context, w http.ResponseWriter, userID string) error {
	c, err := m.config(ctx)
	if err != nil {
		return err
	}
	// One resolved lifetime drives BOTH the signed-payload expiry and the
	// Max-Age attribute so they can never disagree (which would mint a cookie
	// the browser keeps but the server rejects). EffectiveMaxAge applies the
	// zero-value backstop.
	maxAge := c.EffectiveMaxAge()
	expiry := time.Now().UTC().Add(maxAge).Unix()
	payload := fmt.Sprintf("%s|%d", userID, expiry)
	sig, err := m.sign(ctx, payload)
	if err != nil {
		return err
	}

	value := fmt.Sprintf("%s|%s", payload, sig)

	http.SetCookie(w, &http.Cookie{
		Name:     m.CookieName,
		Value:    value,
		Path:     m.cookiePath(ctx),
		MaxAge:   CookieMaxAgeSeconds(maxAge),
		HttpOnly: true,
		Secure:   m.secureFor(c),
		SameSite: c.EffectiveSameSite(),
	})
	return nil
}

// ClearSessionCookie expires the session cookie. It resolves the policy
// best-effort: the delete's SameSite must match the set so the browser accepts
// it in a cross-site context (a same_site=none embedded deployment where logout
// is a cross-site fetch — a hardcoded Lax delete would be dropped), but a
// resolution failure must never wedge logout, so it falls back to a safe Lax.
func (m *SessionMiddleware) ClearSessionCookie(ctx context.Context, w http.ResponseWriter) {
	m.clearCookie(ctx, w)
}

// clearCookie writes the expiring (delete) cookie. Secure/SameSite do not
// participate in the browser's overwrite match (name/path/domain), but SameSite
// does govern whether the browser ACCEPTS the Set-Cookie cross-site — so the
// delete carries the configured SameSite when the policy resolves, and a safe
// Lax + boot Secure floor when it doesn't (logout still can't be wedged).
func (m *SessionMiddleware) clearCookie(ctx context.Context, w http.ResponseWriter) {
	sameSite := http.SameSiteLaxMode
	secure := m.secureFloor
	if c, err := m.config(ctx); err == nil {
		sameSite = c.EffectiveSameSite()
		secure = m.secureFor(c)
	}
	http.SetCookie(w, &http.Cookie{
		Name:     m.CookieName,
		Value:    "",
		Path:     m.cookiePath(ctx),
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   secure,
		SameSite: sameSite,
	})
}

// CSRFToken generates a CSRF token from the session cookie value.
// Token = base64(hmac-sha256(cookieValue, secret+"csrf")). It returns an error
// only when the session secret cannot be resolved.
func (m *SessionMiddleware) CSRFToken(ctx context.Context, cookieValue string) (string, error) {
	secret, err := m.secret(ctx)
	if err != nil {
		return "", err
	}
	// Build the CSRF HMAC key as secret||"csrf" in a fresh buffer. Do NOT
	// append onto the provider's slice: it may share backing storage (see the
	// SessionSecretProvider contract) and append would mutate that array when
	// cap > len, racing across concurrent requests.
	key := make([]byte, 0, len(secret)+len("csrf"))
	key = append(key, secret...)
	key = append(key, "csrf"...)
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(cookieValue))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil)), nil
}

// ValidateCSRF checks that the CSRF token matches the cookie value. The error is
// non-nil only when the session secret cannot be resolved; callers MUST treat
// that as a 500, distinct from a (false, nil) mismatch.
func (m *SessionMiddleware) ValidateCSRF(ctx context.Context, cookieValue, token string) (bool, error) {
	expected, err := m.CSRFToken(ctx, cookieValue)
	if err != nil {
		return false, err
	}
	return hmac.Equal([]byte(expected), []byte(token)), nil
}

// MACFor returns base64(HMAC(DeriveKey(secret, purpose), input)) over the
// per-request session secret.
//
// purpose domain-separates callers: a MAC minted under one purpose never
// verifies under another, and none of them collide with the CSRF-token
// namespace (secret||"csrf"). That matters for any caller that signs input it
// does not fully control — without separation, such a caller would be a signing
// oracle for every other consumer of the same key.
//
// The error is non-nil only when the session secret cannot be resolved; callers
// MUST surface that as a 500 rather than treat it as a verification failure.
func (m *SessionMiddleware) MACFor(ctx context.Context, purpose, input string) (string, error) {
	secret, err := m.secret(ctx)
	if err != nil {
		return "", err
	}
	mac := hmac.New(sha256.New, DeriveKey(secret, purpose))
	mac.Write([]byte(input))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil)), nil
}

// VerifyMAC recomputes MACFor and compares in constant time.
//
// (false, nil) means the MAC does not match. A non-nil error means the secret
// could not be resolved and is FATAL. Never collapse the two: treating a
// resolution failure as a mismatch turns a provider outage into "this value is
// not ours" for every caller, silently and with no operator signal.
func (m *SessionMiddleware) VerifyMAC(ctx context.Context, purpose, input, mac string) (bool, error) {
	expected, err := m.MACFor(ctx, purpose, input)
	if err != nil {
		return false, err
	}
	return hmac.Equal([]byte(expected), []byte(mac)), nil
}

func (m *SessionMiddleware) validateCookie(ctx context.Context, value string) (string, error) {
	parts := strings.SplitN(value, "|", 3)
	if len(parts) != 3 {
		return "", fmt.Errorf("invalid cookie format")
	}

	userID := parts[0]
	expiryStr := parts[1]
	sig := parts[2]

	// Verify signature. sign may fail with errSecretUnavailable (fatal),
	// which propagates as-is so Wrap can tell it apart from a bad signature.
	payload := fmt.Sprintf("%s|%s", userID, expiryStr)
	expected, err := m.sign(ctx, payload)
	if err != nil {
		return "", err
	}
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

func (m *SessionMiddleware) sign(ctx context.Context, payload string) (string, error) {
	secret, err := m.secret(ctx)
	if err != nil {
		return "", err
	}
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(payload))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil)), nil
}

// CookiePolicy resolves the per-request session-cookie policy. The OIDC handler
// uses it so the state cookie inherits the same Secure/SameSite as the session
// cookie. Returns errConfigUnavailable-tagged errors on resolution failure.
func (m *SessionMiddleware) CookiePolicy(ctx context.Context) (output.SessionConfig, error) {
	return m.config(ctx)
}

// DeriveKey derives a purpose-specific key from a session secret via
// HMAC-SHA256. Exported so top-level wiring can derive purpose-bound
// keys (e.g., to construct a StateCodec from cfg.Session.Secret) before
// SessionMiddleware is instantiated.
func DeriveKey(secret []byte, purpose string) []byte {
	mac := hmac.New(sha256.New, secret)
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
