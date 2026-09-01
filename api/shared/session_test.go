package shared

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/authplane/authserver/internal/adapters/static"
	"github.com/authplane/authserver/internal/domain"
	"github.com/authplane/authserver/internal/domain/user"
	"github.com/authplane/authserver/internal/ports/output"
)

// fakeUserStore is the smallest output.UserStore the SessionMiddleware tests
// need. Only GetByID is exercised; everything else is stubbed.
type fakeUserStore struct {
	getByID func(ctx context.Context, id string) (*user.User, error)
}

func (s fakeUserStore) Create(_ context.Context, _ *user.User) error { return nil }
func (s fakeUserStore) GetByID(ctx context.Context, id string) (*user.User, error) {
	return s.getByID(ctx, id)
}
func (s fakeUserStore) GetByEmail(_ context.Context, _ string) (*user.User, error) { return nil, nil }
func (s fakeUserStore) GetByProviderSub(_ context.Context, _ user.Provider, _ string) (*user.User, error) {
	return nil, nil
}
func (s fakeUserStore) Update(_ context.Context, _ *user.User) error { return nil }
func (s fakeUserStore) List(_ context.Context) ([]user.User, error)  { return nil, nil }
func (s fakeUserStore) Count(_ context.Context) (int, error)         { return 0, nil }
func (s fakeUserStore) Delete(_ context.Context, _ string) error     { return nil }

var _ output.UserStore = fakeUserStore{}

func newTestSession(t *testing.T) *SessionMiddleware {
	t.Helper()
	return NewSessionMiddleware(
		static.NewSessionSecretProvider([]byte("test-secret-32-bytes-long-enough")),
		static.NewSessionConfigProvider(output.SessionConfig{MaxAge: time.Hour, SameSite: http.SameSiteLaxMode}),
		"sess",
		false,
	)
}

// signedCookie returns a cookie value that the middleware will accept.
func signedCookie(t *testing.T, m *SessionMiddleware, userID string) string {
	t.Helper()
	rec := httptest.NewRecorder()
	if err := m.SetSessionCookie(context.Background(), rec, userID); err != nil {
		t.Fatalf("SetSessionCookie: %v", err)
	}
	for _, c := range rec.Result().Cookies() {
		if c.Name == m.CookieName {
			return c.Value
		}
	}
	t.Fatal("no session cookie set")
	return ""
}

// downstream is a tiny handler that records whether userID was on the context.
type downstream struct {
	sawUserID string
	saw       bool
}

func (d *downstream) ServeHTTP(_ http.ResponseWriter, r *http.Request) {
	d.sawUserID, d.saw = UserIDFromContext(r.Context())
}

func TestSessionMiddleware_NoUserStore_LegacyBehavior(t *testing.T) {
	m := newTestSession(t)
	val := signedCookie(t, m, "user-1")

	d := &downstream{}
	rec := httptest.NewRecorder()
	r := httptest.NewRequestWithContext(context.Background(), "GET", "/", nil)
	r.AddCookie(&http.Cookie{Name: m.CookieName, Value: val})

	m.Wrap(d).ServeHTTP(rec, r)

	if !d.saw || d.sawUserID != "user-1" {
		t.Fatalf("userID on ctx: got (%q, %v), want (user-1, true)", d.sawUserID, d.saw)
	}
}

func TestSessionMiddleware_UserExists_PassesUserID(t *testing.T) {
	m := newTestSession(t)
	m.SetUserStore(fakeUserStore{
		getByID: func(_ context.Context, id string) (*user.User, error) {
			return &user.User{ID: id, Status: user.StatusActive}, nil
		},
	})
	val := signedCookie(t, m, "user-1")

	d := &downstream{}
	rec := httptest.NewRecorder()
	r := httptest.NewRequestWithContext(context.Background(), "GET", "/", nil)
	r.AddCookie(&http.Cookie{Name: m.CookieName, Value: val})

	m.Wrap(d).ServeHTTP(rec, r)

	if !d.saw || d.sawUserID != "user-1" {
		t.Fatalf("userID on ctx: got (%q, %v), want (user-1, true)", d.sawUserID, d.saw)
	}
}

func TestSessionMiddleware_UserMissing_DropsUserAndClearsCookie(t *testing.T) {
	m := newTestSession(t)
	m.SetUserStore(fakeUserStore{
		getByID: func(_ context.Context, _ string) (*user.User, error) {
			return nil, domain.ErrUserNotFound
		},
	})
	val := signedCookie(t, m, "user-1")

	d := &downstream{}
	rec := httptest.NewRecorder()
	r := httptest.NewRequestWithContext(context.Background(), "GET", "/", nil)
	r.AddCookie(&http.Cookie{Name: m.CookieName, Value: val})

	m.Wrap(d).ServeHTTP(rec, r)

	if d.saw {
		t.Fatalf("userID on ctx: got (%q, true), want absent", d.sawUserID)
	}

	cookies := rec.Result().Cookies()
	var cleared bool
	for _, c := range cookies {
		if c.Name == m.CookieName && c.Value == "" && c.MaxAge < 0 {
			cleared = true
			break
		}
	}
	if !cleared {
		t.Fatalf("expected session cookie to be cleared; got cookies=%v", cookies)
	}
}

func TestSessionMiddleware_UserDisabled_DropsUserAndClearsCookie(t *testing.T) {
	m := newTestSession(t)
	m.SetUserStore(fakeUserStore{
		getByID: func(_ context.Context, id string) (*user.User, error) {
			return &user.User{ID: id, Status: user.StatusDisabled}, nil
		},
	})
	val := signedCookie(t, m, "user-1")

	d := &downstream{}
	rec := httptest.NewRecorder()
	r := httptest.NewRequestWithContext(context.Background(), "GET", "/", nil)
	r.AddCookie(&http.Cookie{Name: m.CookieName, Value: val})

	m.Wrap(d).ServeHTTP(rec, r)

	// The userID assertion is the load-bearing one: /authorize and /consent are
	// guarded only by its absence, so a disabled user reaching the context
	// reopens them even if the cookie was cleared.
	if d.saw {
		t.Fatalf("userID on ctx: got (%q, true), want absent", d.sawUserID)
	}

	cookies := rec.Result().Cookies()
	var cleared bool
	for _, c := range cookies {
		if c.Name == m.CookieName && c.Value == "" && c.MaxAge < 0 {
			cleared = true
			break
		}
	}
	if !cleared {
		t.Fatalf("expected session cookie to be cleared; got cookies=%v", cookies)
	}
}

// A UserStore returning (nil, nil) breaks its contract. Wrap must refuse the
// cookie rather than dereference the nil — a panic here is a 500 on every
// authenticated request — and must report it as a store defect, not as one
// more disabled account, so an operator seeing a wave of logouts looks at the
// store instead of hunting for admin disable events that never happened.
func TestSessionMiddleware_StoreReturnsNilUser_RejectsAndReportsStoreDefect(t *testing.T) {
	// FailClosed spelled out rather than taken from newTestSession, whose zero
	// value is false — the opposite of the production default. This test is
	// about the fail-closed side; its fail-open twin is below.
	m := NewSessionMiddleware(
		static.NewSessionSecretProvider([]byte("test-secret-32-bytes-long-enough")),
		static.NewSessionConfigProvider(output.SessionConfig{
			MaxAge: time.Hour, SameSite: http.SameSiteLaxMode, FailClosed: true,
		}),
		"sess",
		false,
	)
	m.SetUserStore(fakeUserStore{
		getByID: func(_ context.Context, _ string) (*user.User, error) {
			return nil, nil
		},
	})
	var buf bytes.Buffer
	m.SetLogger(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})))
	val := signedCookie(t, m, "user-1")

	d := &downstream{}
	rec := httptest.NewRecorder()
	r := httptest.NewRequestWithContext(context.Background(), "GET", "/", nil)
	r.AddCookie(&http.Cookie{Name: m.CookieName, Value: val})

	m.Wrap(d).ServeHTTP(rec, r)

	if d.saw {
		t.Fatalf("userID on ctx: got (%q, true), want absent", d.sawUserID)
	}

	logged := buf.String()
	if !strings.Contains(logged, "reason=store_returned_nil") {
		t.Errorf("log = %q, want reason=store_returned_nil so a broken store is not\n"+
			"filed under routine disablements", logged)
	}
	if !strings.Contains(logged, "level=ERROR") {
		t.Errorf("log = %q, want level=ERROR: a store breaking its contract is a\n"+
			"defect, not an expected security event", logged)
	}
}

// A raw (nil, nil) — the defect from a store that never went through
// storage.WithUserCache — follows the same FailClosed policy as the wrapped
// form. Whether a store is wrapped decides how the defect is spelled, not what
// it means, so it must not decide whether an operator keeps their sessions.
func TestSessionMiddleware_StoreReturnsNilUser_FollowsFailClosedPolicy(t *testing.T) {
	m := NewSessionMiddleware(
		static.NewSessionSecretProvider([]byte("test-secret-32-bytes-long-enough")),
		static.NewSessionConfigProvider(output.SessionConfig{
			MaxAge: time.Hour, SameSite: http.SameSiteLaxMode, FailClosed: false,
		}),
		"sess",
		false,
	)
	m.SetUserStore(fakeUserStore{
		getByID: func(_ context.Context, _ string) (*user.User, error) {
			return nil, nil
		},
	})
	var buf bytes.Buffer
	m.SetLogger(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})))
	val := signedCookie(t, m, "user-1")

	d := &downstream{}
	rec := httptest.NewRecorder()
	r := httptest.NewRequestWithContext(context.Background(), "GET", "/", nil)
	r.AddCookie(&http.Cookie{Name: m.CookieName, Value: val})

	m.Wrap(d).ServeHTTP(rec, r)

	if !d.saw || d.sawUserID != "user-1" {
		t.Fatalf("userID on ctx: got (%q, %v), want (user-1, true) — the wrapped form of "+
			"this defect preserves the session under fail-open, and the raw form has to agree",
			d.sawUserID, d.saw)
	}
	for _, c := range rec.Result().Cookies() {
		if c.Name == m.CookieName && c.MaxAge < 0 {
			t.Fatal("cookie cleared under fail-open; should be preserved")
		}
	}
	if !strings.Contains(buf.String(), "reason=store_returned_nil") {
		t.Errorf("log = %q, want the defect reported even when the session survives", buf.String())
	}
}

// The two routine rejections share one queryable field so an operator alerting
// on session rejections does not have to OR a list of boolean field names that
// grows with every new branch.
func TestSessionMiddleware_RejectionReasonsShareOneField(t *testing.T) {
	cases := []struct {
		name       string
		getByID    func(context.Context, string) (*user.User, error)
		wantReason string
	}{
		{
			name: "disabled",
			getByID: func(_ context.Context, id string) (*user.User, error) {
				return &user.User{ID: id, Status: user.StatusDisabled}, nil
			},
			wantReason: "reason=user_disabled",
		},
		{
			name: "not found",
			getByID: func(_ context.Context, _ string) (*user.User, error) {
				return nil, domain.ErrUserNotFound
			},
			wantReason: "reason=user_not_found",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m := newTestSession(t)
			m.SetUserStore(fakeUserStore{getByID: tc.getByID})
			var buf bytes.Buffer
			m.SetLogger(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})))
			val := signedCookie(t, m, "user-1")

			d := &downstream{}
			rec := httptest.NewRecorder()
			r := httptest.NewRequestWithContext(context.Background(), "GET", "/", nil)
			r.AddCookie(&http.Cookie{Name: m.CookieName, Value: val})

			m.Wrap(d).ServeHTTP(rec, r)

			logged := buf.String()
			if !strings.Contains(logged, tc.wantReason) {
				t.Errorf("log = %q, want %s", logged, tc.wantReason)
			}
			if !strings.Contains(logged, "level=WARN") {
				t.Errorf("log = %q, want level=WARN for a routine rejection", logged)
			}
		})
	}
}

// A store answering with neither user nor error leaves the account's status as
// unknown as a timeout does, so it follows the same FailClosed policy. The
// default is FailClosed=true, so the cookie still goes — an operator who chose
// availability for a database blip gets it here too, rather than having every
// live session destroyed by a store they cannot tune around.
func TestSessionMiddleware_StoreReturnedNoUser_FollowsFailClosedPolicy(t *testing.T) {
	newWith := func(failClosed bool) *SessionMiddleware {
		m := NewSessionMiddleware(
			static.NewSessionSecretProvider([]byte("test-secret-32-bytes-long-enough")),
			static.NewSessionConfigProvider(output.SessionConfig{
				MaxAge: time.Hour, SameSite: http.SameSiteLaxMode, FailClosed: failClosed,
			}),
			"sess",
			false,
		)
		m.SetUserStore(fakeUserStore{
			getByID: func(_ context.Context, _ string) (*user.User, error) {
				return nil, domain.ErrStoreReturnedNoUser
			},
		})
		return m
	}

	t.Run("fail-closed rejects", func(t *testing.T) {
		m := newWith(true)
		var buf bytes.Buffer
		m.SetLogger(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})))
		val := signedCookie(t, m, "user-1")

		d := &downstream{}
		rec := httptest.NewRecorder()
		r := httptest.NewRequestWithContext(context.Background(), "GET", "/", nil)
		r.AddCookie(&http.Cookie{Name: m.CookieName, Value: val})

		m.Wrap(d).ServeHTTP(rec, r)

		if d.saw {
			t.Fatalf("userID on ctx: got (%q, true), want absent under fail-closed", d.sawUserID)
		}
		if !strings.Contains(buf.String(), "reason=store_returned_nil") {
			t.Errorf("log = %q, want reason=store_returned_nil so the cause is not filed as an outage", buf.String())
		}
	})

	t.Run("fail-open preserves the session", func(t *testing.T) {
		m := newWith(false)
		var buf bytes.Buffer
		m.SetLogger(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})))
		val := signedCookie(t, m, "user-1")

		d := &downstream{}
		rec := httptest.NewRecorder()
		r := httptest.NewRequestWithContext(context.Background(), "GET", "/", nil)
		r.AddCookie(&http.Cookie{Name: m.CookieName, Value: val})

		m.Wrap(d).ServeHTTP(rec, r)

		if !d.saw || d.sawUserID != "user-1" {
			t.Fatalf("userID on ctx: got (%q, %v), want (user-1, true) — an operator who chose "+
				"availability should not lose sessions to a store defect either",
				d.sawUserID, d.saw)
		}
		for _, c := range rec.Result().Cookies() {
			if c.Name == m.CookieName && c.MaxAge < 0 {
				t.Fatal("cookie cleared under fail-open; should be preserved")
			}
		}
		if !strings.Contains(buf.String(), "reason=store_returned_nil") {
			t.Errorf("log = %q, want the cause reported even when the session survives", buf.String())
		}
	})
}

func TestSessionMiddleware_TransientError_FailsOpen(t *testing.T) {
	m := newTestSession(t)
	m.SetUserStore(fakeUserStore{
		getByID: func(_ context.Context, _ string) (*user.User, error) {
			return nil, errors.New("db unavailable")
		},
	})
	val := signedCookie(t, m, "user-1")

	d := &downstream{}
	rec := httptest.NewRecorder()
	r := httptest.NewRequestWithContext(context.Background(), "GET", "/", nil)
	r.AddCookie(&http.Cookie{Name: m.CookieName, Value: val})

	m.Wrap(d).ServeHTTP(rec, r)

	if !d.saw || d.sawUserID != "user-1" {
		t.Fatalf("userID on ctx: got (%q, %v), want (user-1, true) — fail-open broken",
			d.sawUserID, d.saw)
	}
	for _, c := range rec.Result().Cookies() {
		if c.Name == m.CookieName && c.MaxAge < 0 {
			t.Fatalf("cookie cleared on transient error; should be preserved")
		}
	}
}

func TestSessionMiddleware_TransientError_FailClosed(t *testing.T) {
	m := NewSessionMiddleware(
		static.NewSessionSecretProvider([]byte("test-secret-32-bytes-long-enough")),
		static.NewSessionConfigProvider(output.SessionConfig{MaxAge: time.Hour, SameSite: http.SameSiteLaxMode, FailClosed: true}),
		"sess",
		false,
	)
	m.SetUserStore(fakeUserStore{
		getByID: func(_ context.Context, _ string) (*user.User, error) {
			return nil, errors.New("db unavailable")
		},
	})
	val := signedCookie(t, m, "user-1")

	d := &downstream{}
	rec := httptest.NewRecorder()
	r := httptest.NewRequestWithContext(context.Background(), "GET", "/", nil)
	r.AddCookie(&http.Cookie{Name: m.CookieName, Value: val})

	m.Wrap(d).ServeHTTP(rec, r)

	if d.saw {
		t.Fatalf("userID on ctx with fail-closed: got (%q, true), want (\"\", false)", d.sawUserID)
	}
	cookieCleared := false
	for _, c := range rec.Result().Cookies() {
		if c.Name == m.CookieName && c.MaxAge < 0 {
			cookieCleared = true
		}
	}
	if !cookieCleared {
		t.Fatalf("cookie not cleared on transient error under fail-closed")
	}
}

// fakeURLBuilder resolves paths under a fixed mount prefix ("" = root).
type fakeURLBuilder struct {
	mount string // mount prefix, no trailing slash; "" = root
}

func (b fakeURLBuilder) Resolve(_ context.Context, p string) (string, error) { return b.mount + p, nil }

var _ output.URLBuilder = fakeURLBuilder{}

func TestSessionCookie_PathScoping(t *testing.T) {
	cases := []struct {
		name     string
		urls     output.URLBuilder // nil => not set (default root)
		wantPath string
	}{
		{"no URLBuilder (root default)", nil, "/"},
		{"root cookie path", fakeURLBuilder{}, "/"},
		{"reverse-proxy mount", fakeURLBuilder{mount: "/api/v2/auth"}, "/api/v2/auth/"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m := newTestSession(t)
			if tc.urls != nil {
				m.SetURLBuilder(tc.urls)
			}
			rec := httptest.NewRecorder()
			if err := m.SetSessionCookie(context.Background(), rec, "user-1"); err != nil {
				t.Fatalf("SetSessionCookie: %v", err)
			}
			var c *http.Cookie
			for _, ck := range rec.Result().Cookies() {
				if ck.Name == m.CookieName {
					c = ck
				}
			}
			if c == nil {
				t.Fatal("no session cookie set")
			}
			if c.Path != tc.wantPath {
				t.Errorf("Path = %q, want %q", c.Path, tc.wantPath)
			}
			if c.Domain != "" {
				t.Errorf("Domain = %q, want empty (host-only cookie)", c.Domain)
			}
		})
	}
}

// ClearSessionCookie must use the same Path as SetSessionCookie, or the browser
// will not drop the cookie.
func TestClearSessionCookie_MatchesSetPath(t *testing.T) {
	m := newTestSession(t)
	m.SetURLBuilder(fakeURLBuilder{mount: "/api/v2/auth"})
	rec := httptest.NewRecorder()
	m.ClearSessionCookie(context.Background(), rec)
	c := rec.Result().Cookies()[0]
	if c.Path != "/api/v2/auth/" {
		t.Errorf("clear Path = %q, want %q", c.Path, "/api/v2/auth/")
	}
	if c.MaxAge >= 0 {
		t.Errorf("clear MaxAge = %d, want negative (expired)", c.MaxAge)
	}
}

// --- SessionSecretProvider seam ---

// ctxSecretKey carries a per-request secret on the context for ctxKeyedProvider.
type ctxSecretKey struct{}

// ctxKeyedProvider resolves a distinct secret per request from the context — a
// stand-in for a per-deployment secret source (KMS / env-keyed rotation).
type ctxKeyedProvider struct{}

func (ctxKeyedProvider) Secret(ctx context.Context) ([]byte, error) {
	if s, ok := ctx.Value(ctxSecretKey{}).([]byte); ok {
		return s, nil
	}
	return nil, errors.New("no secret on context")
}

// errProvider always fails to resolve a secret.
type errProvider struct{}

func (errProvider) Secret(context.Context) ([]byte, error) {
	return nil, errors.New("backend unreachable")
}

// Test-B (substitution): a provider returning different secrets per ctx proves a
// cookie signed under one ctx cannot be verified under another.
func TestSessionMiddleware_Substitution_SecretIsPerContext(t *testing.T) {
	m := NewSessionMiddleware(ctxKeyedProvider{}, static.NewSessionConfigProvider(output.SessionConfig{MaxAge: time.Hour, SameSite: http.SameSiteLaxMode}), "sess", false)

	secretA := bytes.Repeat([]byte("A"), 32)
	secretB := bytes.Repeat([]byte("B"), 32)
	ctxA := context.WithValue(context.Background(), ctxSecretKey{}, secretA)
	ctxB := context.WithValue(context.Background(), ctxSecretKey{}, secretB)

	// Sign a cookie under ctxA.
	rec := httptest.NewRecorder()
	if err := m.SetSessionCookie(ctxA, rec, "user-1"); err != nil {
		t.Fatalf("SetSessionCookie under ctxA: %v", err)
	}
	var val string
	for _, c := range rec.Result().Cookies() {
		if c.Name == m.CookieName {
			val = c.Value
		}
	}
	if val == "" {
		t.Fatal("no session cookie set")
	}

	// Same secret (ctxA) verifies: downstream sees the user.
	if got := runWrap(m, ctxA, val); got != "user-1" {
		t.Fatalf("under matching ctx: userID = %q, want user-1", got)
	}
	// Different secret (ctxB) rejects the signature: anonymous.
	if got := runWrap(m, ctxB, val); got != "" {
		t.Fatalf("under different ctx: userID = %q, want anonymous (cross-secret forgery)", got)
	}
}

// Test-C (error path): a provider that errors makes Wrap return 500, log the
// failure, and NOT fall through to the anonymous path.
func TestSessionMiddleware_SecretError_Returns500NoFallback(t *testing.T) {
	m := NewSessionMiddleware(errProvider{}, static.NewSessionConfigProvider(output.SessionConfig{MaxAge: time.Hour, SameSite: http.SameSiteLaxMode}), "sess", false)
	var buf bytes.Buffer
	m.SetLogger(slog.New(slog.NewTextHandler(&buf, nil)))

	d := &downstream{}
	rec := httptest.NewRecorder()
	r := httptest.NewRequestWithContext(context.Background(), "GET", "/", nil)
	// A well-formed (3-part) cookie value so validateCookie reaches secret
	// resolution rather than bailing on the format check.
	r.AddCookie(&http.Cookie{Name: m.CookieName, Value: "user-1|9999999999|deadbeef"})

	m.Wrap(d).ServeHTTP(rec, r)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", rec.Code)
	}
	if d.saw {
		t.Fatalf("downstream ran on secret-resolution failure; must not fall through (got userID %q)", d.sawUserID)
	}
	if !strings.Contains(buf.String(), "session secret resolution failed") {
		t.Fatalf("expected ErrorContext log %q; got: %s", "session secret resolution failed", buf.String())
	}
}

// runWrap drives Wrap with a cookie under ctx and returns the userID downstream
// saw ("" if anonymous).
func runWrap(m *SessionMiddleware, ctx context.Context, cookieValue string) string {
	d := &downstream{}
	rec := httptest.NewRecorder()
	r := httptest.NewRequestWithContext(ctx, "GET", "/", nil)
	r.AddCookie(&http.Cookie{Name: m.CookieName, Value: cookieValue})
	m.Wrap(d).ServeHTTP(rec, r)
	return d.sawUserID
}

// spareCapProvider returns a slice whose cap exceeds its len — like a substitute
// might (e.g. a sub-slice of a pooled buffer). It exposes the full backing array
// so a test can assert callers don't append into the spare capacity.
type spareCapProvider struct{ backing []byte }

func (p spareCapProvider) Secret(context.Context) ([]byte, error) {
	return p.backing[:32], nil // len 32, cap == len(backing)
}

// CSRFToken must not append "csrf" onto the provider's slice: with cap > len that
// mutates shared backing storage (the port forbids it) and races across requests.
func TestCSRFToken_DoesNotMutateProviderSecret(t *testing.T) {
	backing := make([]byte, 64)
	copy(backing, []byte("test-secret-32-bytes-long-enough"))
	for i := 32; i < 64; i++ {
		backing[i] = 0xAB // sentinel in the spare-capacity region
	}
	m := NewSessionMiddleware(spareCapProvider{backing}, static.NewSessionConfigProvider(output.SessionConfig{MaxAge: time.Hour, SameSite: http.SameSiteLaxMode}), "sess", false)

	if _, err := m.CSRFToken(context.Background(), "cookie-value"); err != nil {
		t.Fatalf("CSRFToken: %v", err)
	}
	for i := 32; i < 36; i++ {
		if backing[i] != 0xAB {
			t.Fatalf("CSRFToken mutated the provider's backing array at [%d] = %#x (append wrote into spare capacity)", i, backing[i])
		}
	}
}

// errConfigProvider always fails to resolve the cookie policy.
type errConfigProvider struct{}

func (errConfigProvider) Config(context.Context) (output.SessionConfig, error) {
	return output.SessionConfig{}, errors.New("policy backend unreachable")
}

// Wrap resolves the cookie policy per-branch, not at entry, so a policy-provider
// outage must not affect requests that never act on the policy. Before that
// split, merely carrying a cookie was enough to turn a provider failure into a
// 500 — including for cookies that would have been ignored as anonymous.
func TestSessionMiddleware_ConfigError_PassThroughPathsUnaffected(t *testing.T) {
	secret := static.NewSessionSecretProvider([]byte("test-secret-32-bytes-long-enough"))
	// good mints a valid cookie; the middleware under test shares the secret
	// (so the cookie verifies) but cannot resolve the policy.
	good := NewSessionMiddleware(secret, static.NewSessionConfigProvider(output.SessionConfig{MaxAge: time.Hour, SameSite: http.SameSiteLaxMode}), "sess", false)
	valid := signedCookie(t, good, "u1")

	tests := []struct {
		name       string
		cookie     string
		users      output.UserStore
		wantUserID string // "" = anonymous
	}{
		{
			name:   "unparseable cookie falls through to anonymous",
			cookie: "garbage",
		},
		{
			name:       "valid cookie with no user store",
			cookie:     valid,
			wantUserID: "u1",
		},
		{
			name:   "valid cookie for an existing user",
			cookie: valid,
			users: fakeUserStore{getByID: func(_ context.Context, id string) (*user.User, error) {
				return &user.User{ID: id, Status: user.StatusActive}, nil
			}},
			wantUserID: "u1",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			m := NewSessionMiddleware(secret, errConfigProvider{}, "sess", false)
			if tc.users != nil {
				m.SetUserStore(tc.users)
			}
			var gotUserID string
			h := m.Wrap(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
				gotUserID, _ = UserIDFromContext(r.Context())
			}))
			req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/", nil)
			req.AddCookie(&http.Cookie{Name: "sess", Value: tc.cookie})
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)

			if rec.Code != http.StatusOK {
				t.Fatalf("status = %d, want 200: a policy-provider outage must not break this path", rec.Code)
			}
			if gotUserID != tc.wantUserID {
				t.Errorf("userID = %q, want %q", gotUserID, tc.wantUserID)
			}
		})
	}
}

// The branches that DO consume the policy still fail closed: a stale cookie
// clears the cookie best-effort and continues anonymous — a delete is matched
// on name/path/domain only, so it needs no policy. A provider outage must never
// wedge a stale cookie in place (the user could keep riding a deleted account)
// nor 500 the request.
func TestSessionMiddleware_ConfigError_StaleCookieClearedBestEffort(t *testing.T) {
	secret := static.NewSessionSecretProvider([]byte("test-secret-32-bytes-long-enough"))
	good := NewSessionMiddleware(secret, static.NewSessionConfigProvider(output.SessionConfig{MaxAge: time.Hour, SameSite: http.SameSiteLaxMode}), "sess", false)
	valid := signedCookie(t, good, "u1")

	m := NewSessionMiddleware(secret, errConfigProvider{}, "sess", false)
	m.SetUserStore(fakeUserStore{getByID: func(context.Context, string) (*user.User, error) {
		return nil, domain.ErrUserNotFound
	}})

	var gotUserID string
	handled := false
	h := m.Wrap(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		handled = true
		gotUserID, _ = UserIDFromContext(r.Context())
	}))
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{Name: "sess", Value: valid})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: the stale cookie path must not 500 on a policy outage", rec.Code)
	}
	if !handled || gotUserID != "" {
		t.Errorf("expected the request to continue anonymous (handled=%v, userID=%q)", handled, gotUserID)
	}
	// The stale cookie must actually be cleared.
	var cleared bool
	for _, c := range rec.Result().Cookies() {
		if c.Name == "sess" && c.MaxAge < 0 {
			cleared = true
		}
	}
	if !cleared {
		t.Error("stale session cookie was not cleared")
	}
}

// http.Cookie treats MaxAge 0 as "omit the attribute" — a session cookie the
// browser keeps indefinitely. Truncating a positive sub-second lifetime to 0
// would therefore invert the caller's intent, so the conversion rounds up.
func TestCookieMaxAgeSeconds_RoundsUpSoPositiveNeverBecomesZero(t *testing.T) {
	cases := map[string]struct {
		in   time.Duration
		want int
	}{
		"sub-second rounds up to 1":    {500 * time.Millisecond, 1},
		"just over a second rounds up": {1500 * time.Millisecond, 2},
		"exact second preserved":       {time.Second, 1},
		"exact hour preserved":         {time.Hour, 3600},
		"zero stays zero":              {0, 0},
		"negative stays zero":          {-time.Second, 0},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			if got := CookieMaxAgeSeconds(tc.in); got != tc.want {
				t.Errorf("CookieMaxAgeSeconds(%v) = %d, want %d", tc.in, got, tc.want)
			}
		})
	}
}

// The boot Secure floor clamps a provider's Secure upward: a provider may
// tighten Secure but never downgrade an HTTPS/HSTS deployment to non-Secure
// cookies. The delete resolves the policy best-effort and carries the SAME
// Secure as the set (secureFor), so a Secure cookie is deleted by a Secure
// delete ("Leave Secure Cookies Alone" can't strand it).
func TestSessionMiddleware_SecureFloor_ProviderMayOnlyTighten(t *testing.T) {
	secret := static.NewSessionSecretProvider([]byte("test-secret-32-bytes-long-enough"))

	tests := []struct {
		name           string
		providerSecure bool
		floor          bool
		wantSecure     bool
	}{
		{"floor on, provider off ⇒ Secure (clamped up)", false, true, true},
		{"floor on, provider on ⇒ Secure", true, true, true},
		{"floor off, provider on ⇒ Secure (provider tightens)", true, false, true},
		{"floor off, provider off ⇒ not Secure", false, false, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			m := NewSessionMiddleware(secret, static.NewSessionConfigProvider(output.SessionConfig{
				MaxAge: time.Hour, SameSite: http.SameSiteLaxMode, Secure: tc.providerSecure,
			}), "sess", tc.floor)

			// Set cookie.
			rec := httptest.NewRecorder()
			if err := m.SetSessionCookie(context.Background(), rec, "u1"); err != nil {
				t.Fatalf("SetSessionCookie: %v", err)
			}
			if got := rec.Result().Cookies()[0].Secure; got != tc.wantSecure {
				t.Errorf("set Secure = %v, want %v", got, tc.wantSecure)
			}

			// Delete carries the same Secure as the set (secureFor), so a Secure
			// cookie is cleared by a Secure delete.
			rec2 := httptest.NewRecorder()
			m.ClearSessionCookie(context.Background(), rec2)
			if got := rec2.Result().Cookies()[0].Secure; got != tc.wantSecure {
				t.Errorf("clear Secure = %v, want %v (same as set)", got, tc.wantSecure)
			}
		})
	}
}

// SameSite handling, set + delete. Major 2: a provider leaving SameSite unset
// (0) must not emit a cookie with no SameSite. Major 3: the delete must carry
// the configured SameSite (e.g. None) so an embedded/cross-site logout is
// accepted by the browser — a hardcoded Lax delete would be dropped.
func TestSessionMiddleware_SameSite_SetAndDelete(t *testing.T) {
	secret := static.NewSessionSecretProvider([]byte("test-secret-32-bytes-long-enough"))

	cases := map[string]struct {
		provided http.SameSite
		want     http.SameSite // expected on BOTH set and delete
	}{
		"unset (0) backstops to Lax on set and delete": {http.SameSiteDefaultMode, http.SameSiteLaxMode},
		"none is preserved on delete (not forced Lax)": {http.SameSiteNoneMode, http.SameSiteNoneMode},
		"strict preserved": {http.SameSiteStrictMode, http.SameSiteStrictMode},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			m := NewSessionMiddleware(secret, static.NewSessionConfigProvider(output.SessionConfig{
				MaxAge: time.Hour, SameSite: tc.provided,
			}), "sess", false)

			rec := httptest.NewRecorder()
			if err := m.SetSessionCookie(context.Background(), rec, "u1"); err != nil {
				t.Fatalf("SetSessionCookie: %v", err)
			}
			if got := rec.Result().Cookies()[0].SameSite; got != tc.want {
				t.Errorf("set SameSite = %v, want %v", got, tc.want)
			}

			rec2 := httptest.NewRecorder()
			m.ClearSessionCookie(context.Background(), rec2)
			if got := rec2.Result().Cookies()[0].SameSite; got != tc.want {
				t.Errorf("delete SameSite = %v, want %v (must match set)", got, tc.want)
			}
		})
	}
}

// When the policy can't be resolved, the delete still falls back to a safe Lax
// rather than an omitted attribute, and logout is never wedged.
func TestSessionMiddleware_ClearFallsBackToLaxOnConfigError(t *testing.T) {
	m := NewSessionMiddleware(static.NewSessionSecretProvider([]byte("test-secret-32-bytes-long-enough")), errConfigProvider{}, "sess", false)
	rec := httptest.NewRecorder()
	m.ClearSessionCookie(context.Background(), rec)
	c := rec.Result().Cookies()[0]
	if c.MaxAge >= 0 {
		t.Fatalf("clear MaxAge = %d, want negative (cookie must still be deleted)", c.MaxAge)
	}
	if c.SameSite != http.SameSiteLaxMode {
		t.Errorf("clear SameSite = %v, want Lax fallback", c.SameSite)
	}
}
