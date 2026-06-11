// Package user contains the User domain entity.
package user

import (
	"time"

	"github.com/authplane/authserver/internal/domain"
)

// Role defines what a user can do in the admin context.
type Role string

// User roles.
const (
	RoleAdmin Role = "admin"
	RoleUser  Role = "user"
)

// Status represents the user account state.
type Status string

// User statuses.
const (
	StatusActive   Status = "active"
	StatusDisabled Status = "disabled"
)

// Provider indicates how the user authenticates.
type Provider string

// Authentication providers.
const (
	ProviderLocal Provider = "local" // email + bcrypt password
	ProviderOIDC  Provider = "oidc"  // federated via upstream OIDC (OSS: single provider)
)

// User represents a resource owner in the authorization server.
type User struct {
	ID           string
	Email        string
	Name         string // display name (may be empty)
	PasswordHash string // bcrypt hash; empty for federated users
	Role         Role
	Status       Status
	Provider     Provider
	ProviderSub  string // subject from external IdP; empty for local users
	Version      int64  // optimistic locking — starts at 1, increments on each Update
	CreatedAt    time.Time
	UpdatedAt    time.Time
}

// IsActive reports whether the user can participate in auth flows.
func (u *User) IsActive() bool {
	return u.Status == StatusActive
}

// IsAdmin reports whether the user has admin privileges.
func (u *User) IsAdmin() bool {
	return u.Role == RoleAdmin
}

// IsLocal reports whether the user authenticates with a local password.
func (u *User) IsLocal() bool {
	return u.Provider == ProviderLocal
}

// Disable deactivates the user account.
func (u *User) Disable() error {
	if u.Status != StatusActive {
		return &StateError{From: u.Status, To: StatusDisabled}
	}
	u.Status = StatusDisabled
	u.UpdatedAt = time.Now().UTC()
	return nil
}

// Enable reactivates a disabled user account.
func (u *User) Enable() error {
	if u.Status != StatusDisabled {
		return &StateError{From: u.Status, To: StatusActive}
	}
	u.Status = StatusActive
	u.UpdatedAt = time.Now().UTC()
	return nil
}

// StateError is returned for invalid user state transitions.
type StateError struct {
	From Status
	To   Status
}

func (e *StateError) Error() string {
	return "invalid user state transition from " + string(e.From) + " to " + string(e.To)
}

// Code reports the canonical error code so writeDomainOrInternalError maps
// the no-op transition to HTTP 409 instead of falling through to 500.
func (e *StateError) Code() string { return domain.CodeConflict }
