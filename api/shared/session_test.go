package shared

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

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
		[]byte("test-secret-32-bytes-long-enough"),
		"sess",
		1*time.Hour,
		false,
		http.SameSiteLaxMode,
	)
}

// signedCookie returns a cookie value that the middleware will accept.
func signedCookie(t *testing.T, m *SessionMiddleware, userID string) string {
	t.Helper()
	rec := httptest.NewRecorder()
	m.SetSessionCookie(rec, userID)
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
			return &user.User{ID: id}, nil
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
	m := newTestSession(t)
	m.SetFailClosed(true)
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
