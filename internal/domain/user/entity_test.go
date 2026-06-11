package user

import (
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/authplane/authserver/internal/domain"
)

func newTestUser() *User {
	return &User{
		ID:           "user-1",
		Email:        "admin@example.com",
		PasswordHash: "$2a$10$somehash",
		Role:         RoleAdmin,
		Status:       StatusActive,
		Provider:     ProviderLocal,
		CreatedAt:    time.Now().UTC(),
		UpdatedAt:    time.Now().UTC(),
	}
}

func TestUserIsActive(t *testing.T) {
	u := newTestUser()
	if !u.IsActive() {
		t.Error("new user should be active")
	}
	u.Status = StatusDisabled
	if u.IsActive() {
		t.Error("disabled user should not be active")
	}
}

func TestUserIsAdmin(t *testing.T) {
	u := newTestUser()
	if !u.IsAdmin() {
		t.Error("admin user should be admin")
	}
	u.Role = RoleUser
	if u.IsAdmin() {
		t.Error("regular user should not be admin")
	}
}

func TestUserIsLocal(t *testing.T) {
	u := newTestUser()
	if !u.IsLocal() {
		t.Error("local user should be local")
	}
	u.Provider = ProviderOIDC
	if u.IsLocal() {
		t.Error("OIDC user should not be local")
	}
}

func TestUserDisable(t *testing.T) {
	u := newTestUser()
	if err := u.Disable(); err != nil {
		t.Fatalf("Disable active user: %v", err)
	}
	if u.Status != StatusDisabled {
		t.Errorf("status = %q, want disabled", u.Status)
	}
}

func TestUserDisableAlreadyDisabled(t *testing.T) {
	u := newTestUser()
	u.Status = StatusDisabled
	if err := u.Disable(); err == nil {
		t.Error("disabling already-disabled user should fail")
	}
}

func TestUserEnable(t *testing.T) {
	u := newTestUser()
	u.Status = StatusDisabled
	if err := u.Enable(); err != nil {
		t.Fatalf("Enable disabled user: %v", err)
	}
	if u.Status != StatusActive {
		t.Errorf("status = %q, want active", u.Status)
	}
}

func TestUserEnableAlreadyActive(t *testing.T) {
	u := newTestUser()
	if err := u.Enable(); err == nil {
		t.Error("enabling already-active user should fail")
	}
}

func TestStateErrorMessage(t *testing.T) {
	e := &StateError{From: StatusActive, To: StatusDisabled}
	if e.Error() == "" {
		t.Error("error message should not be empty")
	}
}

// TestStateErrorImplementsDomainError pins Defect B: *StateError
// must satisfy domain.Error so writeDomainOrInternalError maps no-op
// disable / enable transitions to HTTP 409 instead of falling through
// to the 500 default arm.
func TestStateErrorImplementsDomainError(t *testing.T) {
	e := &StateError{From: StatusDisabled, To: StatusDisabled}
	if !domain.IsError(e) {
		t.Fatal("*StateError must satisfy domain.Error")
	}
	if got := domain.ErrorCode(e); got != domain.CodeConflict {
		t.Errorf("Code() = %q, want %q", got, domain.CodeConflict)
	}

	// errors.As must reach the typed error through the wrap chain that
	// AdminService uses (`fmt.Errorf("disable: %w", err)`).
	wrapped := fmt.Errorf("disable: %w", e)
	var se *StateError
	if !errors.As(wrapped, &se) {
		t.Fatal("errors.As did not unwrap *StateError through fmt.Errorf %w")
	}
	if got := domain.ErrorCode(wrapped); got != domain.CodeConflict {
		t.Errorf("ErrorCode(wrapped) = %q, want %q", got, domain.CodeConflict)
	}
}
