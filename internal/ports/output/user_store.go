package output

import (
	"context"

	"github.com/authplane/authserver/internal/domain/user"
)

// UserStore persists resource owner accounts.
type UserStore interface {
	// Create stores a new user.
	Create(ctx context.Context, u *user.User) error

	// GetByID returns a user by their ID.
	GetByID(ctx context.Context, id string) (*user.User, error)

	// GetByEmail returns a user by their email address.
	GetByEmail(ctx context.Context, email string) (*user.User, error)

	// GetByProviderSub returns a federated user by (provider, subject).
	GetByProviderSub(ctx context.Context, provider user.Provider, sub string) (*user.User, error)

	// Update persists changes to an existing user.
	Update(ctx context.Context, u *user.User) error

	// List returns all users.
	List(ctx context.Context) ([]user.User, error)

	// Count returns the total number of users.
	Count(ctx context.Context) (int, error)

	// Delete permanently removes a user by ID.
	Delete(ctx context.Context, id string) error
}
