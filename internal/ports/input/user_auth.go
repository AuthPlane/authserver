package input

import (
	"context"

	"github.com/authplane/authserver/internal/domain/user"
)

// UserAuthPort handles user authentication.
type UserAuthPort interface {
	// Authenticate verifies email + password and returns the user.
	Authenticate(ctx context.Context, email, password string) (*user.User, error)

	// GetByID returns a user by their ID.
	GetByID(ctx context.Context, id string) (*user.User, error)
}
