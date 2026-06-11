package output

import (
	"context"

	"github.com/authplane/authserver/internal/domain/xaa"
)

// XAAPolicyStore persists XAA authorization policies.
type XAAPolicyStore interface {
	// Save creates or updates a policy.
	Save(ctx context.Context, p xaa.Policy) error

	// GetByID retrieves a policy by its ID.
	GetByID(ctx context.Context, id string) (*xaa.Policy, error)

	// ListByIDP returns all policies for a given trusted IdP.
	ListByIDP(ctx context.Context, idpID string) ([]xaa.Policy, error)

	// List returns all policies.
	List(ctx context.Context) ([]xaa.Policy, error)

	// Delete removes a policy by ID.
	Delete(ctx context.Context, id string) error
}
