//go:build integration

package services_test

import (
	"context"
	"errors"
	"testing"

	"github.com/authplane/authserver/internal/domain"
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
