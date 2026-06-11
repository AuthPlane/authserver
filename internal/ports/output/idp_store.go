package output

import (
	"context"

	"github.com/authplane/authserver/internal/domain/idp"
)

// IDPStore manages trusted identity provider records for XAA.
type IDPStore interface {
	// Save creates or updates a trusted IdP.
	Save(ctx context.Context, i idp.TrustedIDP) error

	// GetByID retrieves a trusted IdP by its UUID.
	GetByID(ctx context.Context, id string) (*idp.TrustedIDP, error)

	// GetByIssuer retrieves a trusted IdP by its issuer URL.
	GetByIssuer(ctx context.Context, issuer string) (*idp.TrustedIDP, error)

	// List returns all trusted IdPs.
	List(ctx context.Context) ([]idp.TrustedIDP, error)

	// Delete removes a trusted IdP by ID.
	Delete(ctx context.Context, id string) error
}
