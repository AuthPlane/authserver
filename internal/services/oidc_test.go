//go:build integration

package services_test

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/authplane/authserver/internal/domain"
	"github.com/authplane/authserver/internal/domain/audit"
	"github.com/authplane/authserver/internal/domain/user"
	"github.com/authplane/authserver/internal/ports/output"
	"github.com/authplane/authserver/internal/services"
	"github.com/authplane/authserver/testdata"
)

// mockOIDCProvider is a controllable stub for output.OIDCProvider.
type mockOIDCProvider struct {
	authURL        string
	exchangeResult *output.OIDCTokenResult
	exchangeErr    error
	userinfoResult *output.OIDCUserInfo
	userinfoErr    error
}

func (m *mockOIDCProvider) AuthorizationURL(_ context.Context, _, _, _ string) (string, error) {
	return m.authURL, nil
}

func (m *mockOIDCProvider) ExchangeCode(_ context.Context, _, _, _ string) (*output.OIDCTokenResult, error) {
	return m.exchangeResult, m.exchangeErr
}

func (m *mockOIDCProvider) GetUserInfo(_ context.Context, _ string) (*output.OIDCUserInfo, error) {
	return m.userinfoResult, m.userinfoErr
}

func newOIDCFacade(t *testing.T, provider output.OIDCProvider) (*services.OIDCFacade, output.UserStore) {
	t.Helper()
	stores := testdata.SetupTestStores(t)
	facade := services.NewOIDCFacade(provider, stores.User, testObs(), nil)
	return facade, stores.User
}

func TestAuthenticateOIDC_NewUser(t *testing.T) {
	mock := &mockOIDCProvider{
		exchangeResult: &output.OIDCTokenResult{
			Subject: "upstream-sub-123",
			Email:   "alice@example.com",
			Issuer:  "https://idp.example.com",
		},
	}
	facade, users := newOIDCFacade(t, mock)
	ctx := context.Background()

	u, err := facade.AuthenticateOIDC(ctx, "code", "nonce", "verifier")
	if err != nil {
		t.Fatalf("AuthenticateOIDC: %v", err)
	}

	if u.ID == "" {
		t.Error("user ID is empty")
	}
	if u.Email != "alice@example.com" {
		t.Errorf("Email = %q, want alice@example.com", u.Email)
	}
	if u.Provider != user.ProviderOIDC {
		t.Errorf("Provider = %q, want oidc", u.Provider)
	}
	if u.ProviderSub != "upstream-sub-123" {
		t.Errorf("ProviderSub = %q, want upstream-sub-123", u.ProviderSub)
	}
	if u.Role != user.RoleUser {
		t.Errorf("Role = %q, want user", u.Role)
	}
	if u.Status != user.StatusActive {
		t.Errorf("Status = %q, want active", u.Status)
	}

	// Verify user was persisted.
	stored, err := users.GetByProviderSub(ctx, user.ProviderOIDC, "upstream-sub-123")
	if err != nil {
		t.Fatalf("GetByProviderSub: %v", err)
	}
	if stored.ID != u.ID {
		t.Error("stored user ID doesn't match returned user")
	}
}

func TestAuthenticateOIDC_ExistingUser(t *testing.T) {
	mock := &mockOIDCProvider{
		exchangeResult: &output.OIDCTokenResult{
			Subject: "upstream-sub-456",
			Email:   "bob@example.com",
			Issuer:  "https://idp.example.com",
		},
	}
	facade, users := newOIDCFacade(t, mock)
	ctx := context.Background()

	// Pre-create the user.
	existing := &user.User{
		ID:          "existing-user-id",
		Email:       "bob@example.com",
		Provider:    user.ProviderOIDC,
		ProviderSub: "upstream-sub-456",
		Role:        user.RoleUser,
		Status:      user.StatusActive,
	}
	if err := users.Create(ctx, existing); err != nil {
		t.Fatalf("create existing user: %v", err)
	}

	// Authenticate — should return the existing user.
	u, err := facade.AuthenticateOIDC(ctx, "code", "nonce", "verifier")
	if err != nil {
		t.Fatalf("AuthenticateOIDC: %v", err)
	}
	if u.ID != "existing-user-id" {
		t.Errorf("user ID = %q, want existing-user-id", u.ID)
	}
}

func TestAuthenticateOIDC_SuspendedUser(t *testing.T) {
	mock := &mockOIDCProvider{
		exchangeResult: &output.OIDCTokenResult{
			Subject: "upstream-sub-789",
			Email:   "suspended@example.com",
			Issuer:  "https://idp.example.com",
		},
	}
	facade, users := newOIDCFacade(t, mock)
	ctx := context.Background()

	// Pre-create a disabled user.
	existing := &user.User{
		ID:          "disabled-user-id",
		Email:       "suspended@example.com",
		Provider:    user.ProviderOIDC,
		ProviderSub: "upstream-sub-789",
		Role:        user.RoleUser,
		Status:      user.StatusDisabled,
	}
	if err := users.Create(ctx, existing); err != nil {
		t.Fatalf("create disabled user: %v", err)
	}

	_, err := facade.AuthenticateOIDC(ctx, "code", "nonce", "verifier")
	if err == nil {
		t.Fatal("expected error for disabled user")
	}
	if !errors.Is(err, domain.ErrOIDCAuthFailed) {
		t.Errorf("error = %v, want ErrOIDCAuthFailed", err)
	}
}

func TestAuthenticateOIDC_EmailUpdate(t *testing.T) {
	mock := &mockOIDCProvider{
		exchangeResult: &output.OIDCTokenResult{
			Subject: "upstream-sub-email",
			Email:   "newemail@example.com",
			Issuer:  "https://idp.example.com",
		},
	}
	facade, users := newOIDCFacade(t, mock)
	ctx := context.Background()

	// Pre-create user with old email.
	existing := &user.User{
		ID:          "email-update-user",
		Email:       "oldemail@example.com",
		Provider:    user.ProviderOIDC,
		ProviderSub: "upstream-sub-email",
		Role:        user.RoleUser,
		Status:      user.StatusActive,
	}
	if err := users.Create(ctx, existing); err != nil {
		t.Fatalf("create user: %v", err)
	}

	u, err := facade.AuthenticateOIDC(ctx, "code", "nonce", "verifier")
	if err != nil {
		t.Fatalf("AuthenticateOIDC: %v", err)
	}
	if u.Email != "newemail@example.com" {
		t.Errorf("Email = %q, want newemail@example.com", u.Email)
	}

	// Verify persistence.
	stored, err := users.GetByID(ctx, "email-update-user")
	if err != nil {
		t.Fatalf("GetByID: %v", err)
	}
	if stored.Email != "newemail@example.com" {
		t.Errorf("stored Email = %q, want newemail@example.com", stored.Email)
	}
}

func TestAuthenticateOIDC_LastLogin(t *testing.T) {
	mock := &mockOIDCProvider{
		exchangeResult: &output.OIDCTokenResult{
			Subject: "upstream-sub-lastlogin",
			Email:   "login@example.com",
			Issuer:  "https://idp.example.com",
		},
	}
	facade, users := newOIDCFacade(t, mock)
	ctx := context.Background()

	// Pre-create user.
	existing := &user.User{
		ID:          "lastlogin-user",
		Email:       "login@example.com",
		Provider:    user.ProviderOIDC,
		ProviderSub: "upstream-sub-lastlogin",
		Role:        user.RoleUser,
		Status:      user.StatusActive,
	}
	if err := users.Create(ctx, existing); err != nil {
		t.Fatalf("create user: %v", err)
	}

	_, err := facade.AuthenticateOIDC(ctx, "code", "nonce", "verifier")
	if err != nil {
		t.Fatalf("AuthenticateOIDC: %v", err)
	}

	// Verify UpdatedAt was refreshed (used as proxy for last_login).
	stored, err := users.GetByID(ctx, "lastlogin-user")
	if err != nil {
		t.Fatalf("GetByID: %v", err)
	}
	if stored.UpdatedAt.IsZero() {
		t.Error("UpdatedAt should be set")
	}
}

func TestAuthenticateOIDC_NameProvisioned(t *testing.T) {
	mock := &mockOIDCProvider{
		exchangeResult: &output.OIDCTokenResult{
			Subject: "upstream-sub-named",
			Email:   "named@example.com",
			Name:    "Alice Named",
			Issuer:  "https://idp.example.com",
		},
	}
	facade, users := newOIDCFacade(t, mock)
	ctx := context.Background()

	u, err := facade.AuthenticateOIDC(ctx, "code", "nonce", "verifier")
	if err != nil {
		t.Fatalf("AuthenticateOIDC: %v", err)
	}
	if u.Name != "Alice Named" {
		t.Errorf("Name = %q, want Alice Named", u.Name)
	}

	// Verify persistence.
	stored, err := users.GetByProviderSub(ctx, user.ProviderOIDC, "upstream-sub-named")
	if err != nil {
		t.Fatalf("GetByProviderSub: %v", err)
	}
	if stored.Name != "Alice Named" {
		t.Errorf("stored Name = %q, want Alice Named", stored.Name)
	}
}

func TestAuthenticateOIDC_NameUpdate(t *testing.T) {
	mock := &mockOIDCProvider{
		exchangeResult: &output.OIDCTokenResult{
			Subject: "upstream-sub-nameupd",
			Email:   "nameupd@example.com",
			Name:    "New Name",
			Issuer:  "https://idp.example.com",
		},
	}
	facade, users := newOIDCFacade(t, mock)
	ctx := context.Background()

	// Pre-create user with old name.
	existing := &user.User{
		ID:          "name-update-user",
		Email:       "nameupd@example.com",
		Name:        "Old Name",
		Provider:    user.ProviderOIDC,
		ProviderSub: "upstream-sub-nameupd",
		Role:        user.RoleUser,
		Status:      user.StatusActive,
	}
	if err := users.Create(ctx, existing); err != nil {
		t.Fatalf("create user: %v", err)
	}

	u, err := facade.AuthenticateOIDC(ctx, "code", "nonce", "verifier")
	if err != nil {
		t.Fatalf("AuthenticateOIDC: %v", err)
	}
	if u.Name != "New Name" {
		t.Errorf("Name = %q, want New Name", u.Name)
	}

	// Verify persistence.
	stored, err := users.GetByID(ctx, "name-update-user")
	if err != nil {
		t.Fatalf("GetByID: %v", err)
	}
	if stored.Name != "New Name" {
		t.Errorf("stored Name = %q, want New Name", stored.Name)
	}
}

func TestAuthenticateOIDC_ExchangeFailure(t *testing.T) {
	mock := &mockOIDCProvider{
		exchangeErr: errors.New("upstream error"),
	}
	facade, _ := newOIDCFacade(t, mock)
	ctx := context.Background()

	_, err := facade.AuthenticateOIDC(ctx, "code", "nonce", "verifier")
	if err == nil {
		t.Fatal("expected error for exchange failure")
	}
	if !errors.Is(err, domain.ErrOIDCAuthFailed) {
		t.Errorf("error = %v, want ErrOIDCAuthFailed", err)
	}
}

// oidcAuditCapture records every audit event the facade emits.
type oidcAuditCapture struct {
	mu     sync.Mutex
	events []audit.Event
}

func (c *oidcAuditCapture) Record(_ context.Context, e audit.Event) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.events = append(c.events, e)
}

func (c *oidcAuditCapture) find(action audit.Action, detailHas string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, e := range c.events {
		if e.Action == action && strings.Contains(e.Detail, detailHas) {
			return true
		}
	}
	return false
}

func newAuditedOIDCFacade(t *testing.T, provider output.OIDCProvider) (*services.OIDCFacade, output.UserStore, *oidcAuditCapture) {
	t.Helper()
	stores := testdata.SetupTestStores(t)
	rec := &oidcAuditCapture{}
	return services.NewOIDCFacade(provider, stores.User, testObs(), rec), stores.User, rec
}

// IdPs do not always release an email. Every email-less user provisions as
// its own account, and a returning one is found by (provider, subject).
func TestAuthenticateOIDC_UsersWithoutEmail(t *testing.T) {
	mock := &mockOIDCProvider{}
	facade, _, _ := newAuditedOIDCFacade(t, mock)
	ctx := context.Background()

	ids := map[string]string{}
	for _, sub := range []string{"noemail-1", "noemail-2", "noemail-1"} {
		mock.exchangeResult = &output.OIDCTokenResult{Subject: sub, Issuer: "https://idp.example.com"}
		u, err := facade.AuthenticateOIDC(ctx, "code", "nonce", "verifier")
		if err != nil {
			t.Fatalf("AuthenticateOIDC(%s): %v", sub, err)
		}
		if u.Email != "" {
			t.Errorf("%s: Email = %q, want none", sub, u.Email)
		}
		if prev, seen := ids[sub]; seen && prev != u.ID {
			t.Errorf("returning user %s resolved to %s, first login was %s", sub, u.ID, prev)
		}
		ids[sub] = u.ID
	}
	if ids["noemail-1"] == ids["noemail-2"] {
		t.Error("two upstream subjects resolved to one local user")
	}
}

// A first federated login whose email belongs to an existing local account
// is refused (no linking by email), audited with a reason, and surfaced as
// ErrOIDCEmailInUse so the callback can say why.
func TestAuthenticateOIDC_EmailOfLocalAccount_RefusedAndAudited(t *testing.T) {
	mock := &mockOIDCProvider{exchangeResult: &output.OIDCTokenResult{
		Subject: "impostor", Email: "boss@example.com", Issuer: "https://idp.example.com",
	}}
	facade, users, rec := newAuditedOIDCFacade(t, mock)
	ctx := context.Background()

	now := time.Now().UTC()
	local := &user.User{
		ID: "local-boss", Email: "boss@example.com", PasswordHash: "x",
		Role: user.RoleAdmin, Status: user.StatusActive, Provider: user.ProviderLocal,
		CreatedAt: now, UpdatedAt: now,
	}
	if err := users.Create(ctx, local); err != nil {
		t.Fatalf("create local: %v", err)
	}

	u, err := facade.AuthenticateOIDC(ctx, "code", "nonce", "verifier")
	if !errors.Is(err, domain.ErrOIDCEmailInUse) {
		t.Fatalf("err = %v (user %v), want ErrOIDCEmailInUse", err, u)
	}
	if !rec.find(audit.ActionUserOIDCLoginFailed, "reason=email_in_use") {
		t.Error("no user.oidc_login_failed audit row with reason=email_in_use")
	}
	if _, err := users.GetByProviderSub(ctx, user.ProviderOIDC, "impostor"); !errors.Is(err, domain.ErrUserNotFound) {
		t.Errorf("refused login provisioned a user: %v", err)
	}
	stored, err := users.GetByID(ctx, "local-boss")
	if err != nil || stored.Provider != user.ProviderLocal || stored.ProviderSub != "" {
		t.Errorf("local account changed: %+v, %v", stored, err)
	}
}

// A returning federated user whose upstream email changed to one another
// account holds still signs in; only the email change is dropped.
func TestAuthenticateOIDC_EmailChangeToTakenAddress_SignsInKeepsEmail(t *testing.T) {
	mock := &mockOIDCProvider{exchangeResult: &output.OIDCTokenResult{
		Subject: "fed-1", Email: "taken@example.com", Issuer: "https://idp.example.com",
	}}
	facade, users, _ := newAuditedOIDCFacade(t, mock)
	ctx := context.Background()

	now := time.Now().UTC()
	for _, u := range []*user.User{
		{ID: "holder", Email: "taken@example.com", PasswordHash: "x", Role: user.RoleUser,
			Status: user.StatusActive, Provider: user.ProviderLocal, CreatedAt: now, UpdatedAt: now},
		{ID: "fed-user", Email: "", Role: user.RoleUser, Status: user.StatusActive,
			Provider: user.ProviderOIDC, ProviderSub: "fed-1", CreatedAt: now, UpdatedAt: now},
	} {
		if err := users.Create(ctx, u); err != nil {
			t.Fatalf("create %s: %v", u.ID, err)
		}
	}

	u, err := facade.AuthenticateOIDC(ctx, "code", "nonce", "verifier")
	if err != nil {
		t.Fatalf("AuthenticateOIDC: %v", err)
	}
	if u.ID != "fed-user" || u.Email != "" {
		t.Errorf("got id=%q email=%q, want fed-user with its email unchanged", u.ID, u.Email)
	}
	stored, err := users.GetByID(ctx, "fed-user")
	if err != nil || stored.Email != "" {
		t.Errorf("stored email = %q (%v), want none", stored.Email, err)
	}
}

// staleFirstLookupUserStore misses on its first GetByProviderSub, as a
// concurrent first sign-in does when the other request has not committed
// yet; later lookups see the store as it is.
type staleFirstLookupUserStore struct {
	output.UserStore
	lookups int
}

func (s *staleFirstLookupUserStore) GetByProviderSub(ctx context.Context, provider user.Provider, sub string) (*user.User, error) {
	s.lookups++
	if s.lookups == 1 {
		return nil, domain.ErrUserNotFound
	}
	return s.UserStore.GetByProviderSub(ctx, provider, sub)
}

// Two concurrent first sign-ins for one federated identity: the loser's
// insert collides on (provider, provider_sub) and it signs in as the account
// the winner created, instead of failing or creating a second account.
func TestAuthenticateOIDC_ConcurrentFirstLogin_UsesWinnersAccount(t *testing.T) {
	stores := testdata.SetupTestStores(t)
	ctx := context.Background()
	winner := &user.User{
		ID: "winner-account", Email: "", Name: "Alice", Role: user.RoleUser, Status: user.StatusActive,
		Provider: user.ProviderOIDC, ProviderSub: "upstream-sub-race",
		CreatedAt: time.Now().UTC(), UpdatedAt: time.Now().UTC(),
	}
	if err := stores.User.Create(ctx, winner); err != nil {
		t.Fatalf("seed winner: %v", err)
	}
	store := &staleFirstLookupUserStore{UserStore: stores.User}
	mock := &mockOIDCProvider{exchangeResult: &output.OIDCTokenResult{
		Subject: "upstream-sub-race", Issuer: "https://idp.example.com",
	}}
	facade := services.NewOIDCFacade(mock, store, testObs(), nil)

	u, err := facade.AuthenticateOIDC(ctx, "code", "nonce", "verifier")
	if err != nil {
		t.Fatalf("losing first sign-in refused: %v", err)
	}
	if u.ID != "winner-account" {
		t.Errorf("signed in as %q, want the winner's account", u.ID)
	}
	if again, err := stores.User.GetByProviderSub(ctx, user.ProviderOIDC, "upstream-sub-race"); err != nil || again.ID != "winner-account" {
		t.Errorf("identity resolves to %v (err %v), want exactly the winner's account", again, err)
	}
}
