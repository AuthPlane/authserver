//go:build integration

package services_test

import (
	"context"
	"testing"

	"github.com/authplane/authserver/internal/domain"
	"github.com/authplane/authserver/internal/domain/audit"
	"github.com/authplane/authserver/internal/domain/user"
	"github.com/authplane/authserver/internal/ports/output"
	"github.com/authplane/authserver/internal/services"
	"github.com/authplane/authserver/testdata"
)

func newUserAuthService(t *testing.T) *services.UserAuthService {
	t.Helper()
	stores := testdata.SetupTestStores(t)
	return services.NewUserAuthService(stores.User, testObs(), nil)
}

func TestUserAuth_CreateAndAuthenticate(t *testing.T) {
	svc := newUserAuthService(t)
	ctx := context.Background()

	created, err := svc.CreateUser(ctx, "test@example.com", "", "password123", user.RoleUser)
	if err != nil {
		t.Fatalf("create user: %v", err)
	}
	if created.ID == "" {
		t.Error("user ID is empty")
	}
	if created.Email != "test@example.com" {
		t.Errorf("email: got %q", created.Email)
	}
	if created.Role != user.RoleUser {
		t.Errorf("role: got %q", created.Role)
	}

	// Authenticate with correct password.
	u, err := svc.Authenticate(ctx, "test@example.com", "password123")
	if err != nil {
		t.Fatalf("authenticate: %v", err)
	}
	if u.ID != created.ID {
		t.Errorf("user id mismatch: got %q, want %q", u.ID, created.ID)
	}
}

func TestUserAuth_WrongPassword(t *testing.T) {
	svc := newUserAuthService(t)
	ctx := context.Background()

	_, err := svc.CreateUser(ctx, "test@example.com", "", "correct", user.RoleUser)
	if err != nil {
		t.Fatalf("create: %v", err)
	}

	_, err = svc.Authenticate(ctx, "test@example.com", "wrong")
	if err == nil {
		t.Fatal("expected error for wrong password")
	}
	if err != domain.ErrInvalidCredentials {
		t.Errorf("expected ErrInvalidCredentials, got: %v", err)
	}
}

// Matrix: 15.4 — upgraded from ⚠️: auth.denied/user.login_failed audit event on wrong credentials
func TestUserAuth_FailedAuth_AuditEvent(t *testing.T) {
	stores := testdata.SetupTestStores(t)
	obs := testObs()
	auditSvc := services.NewAuditService(stores.Audit, obs)
	svc := services.NewUserAuthService(stores.User, obs, auditSvc)
	ctx := context.Background()

	_, err := svc.CreateUser(ctx, "audit@example.com", "", "correct", user.RoleUser)
	if err != nil {
		t.Fatalf("create: %v", err)
	}

	// Attempt authentication with wrong password.
	_, err = svc.Authenticate(ctx, "audit@example.com", "wrong")
	if err == nil {
		t.Fatal("expected error")
	}

	// Verify audit event recorded.
	events, err := auditSvc.Query(ctx, output.AuditFilter{
		Action: string(audit.ActionUserLoginFailed),
		Limit:  10,
	})
	if err != nil {
		t.Fatalf("query audit: %v", err)
	}
	if len(events) < 1 {
		t.Error("expected at least 1 user.login_failed audit event")
	}
}

func TestUserAuth_UnknownUser(t *testing.T) {
	svc := newUserAuthService(t)
	ctx := context.Background()

	_, err := svc.Authenticate(ctx, "nobody@example.com", "password")
	if err == nil {
		t.Fatal("expected error for unknown user")
	}
	if err != domain.ErrInvalidCredentials {
		t.Errorf("expected ErrInvalidCredentials, got: %v", err)
	}
}

func TestUserAuth_DisabledUser(t *testing.T) {
	stores := testdata.SetupTestStores(t)
	svc := services.NewUserAuthService(stores.User, testObs(), nil)
	ctx := context.Background()

	created, err := svc.CreateUser(ctx, "disabled@example.com", "", "password", user.RoleUser)
	if err != nil {
		t.Fatalf("create: %v", err)
	}

	// Disable the user via store.
	created.Disable()
	if err := stores.User.Update(ctx, created); err != nil {
		t.Fatalf("update: %v", err)
	}

	_, err = svc.Authenticate(ctx, "disabled@example.com", "password")
	if err == nil {
		t.Fatal("expected error for disabled user")
	}
	if err != domain.ErrInvalidCredentials {
		t.Errorf("expected ErrInvalidCredentials, got: %v", err)
	}
}

func TestUserAuth_GetByID(t *testing.T) {
	svc := newUserAuthService(t)
	ctx := context.Background()

	created, err := svc.CreateUser(ctx, "lookup@example.com", "", "pass", user.RoleAdmin)
	if err != nil {
		t.Fatalf("create: %v", err)
	}

	u, err := svc.GetByID(ctx, created.ID)
	if err != nil {
		t.Fatalf("get by id: %v", err)
	}
	if u.Email != "lookup@example.com" {
		t.Errorf("email: got %q", u.Email)
	}
	if u.Role != user.RoleAdmin {
		t.Errorf("role: got %q", u.Role)
	}
}
