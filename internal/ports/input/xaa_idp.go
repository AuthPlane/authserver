package input

import (
	"context"

	"github.com/authplane/authserver/internal/domain/idp"
)

// XAAIDPPort provides administrative CRUD for trusted identity providers.
type XAAIDPPort interface {
	// RegisterIdP creates or updates a trusted IdP.
	RegisterIDP(ctx context.Context, req RegisterIDPRequest) (*idp.TrustedIDP, error)

	// GetIdP retrieves a trusted IdP by ID.
	GetIDP(ctx context.Context, id string) (*idp.TrustedIDP, error)

	// ListIdPs returns all registered trusted IdPs.
	ListIDPs(ctx context.Context) ([]idp.TrustedIDP, error)

	// UpdateIdP partially updates a trusted IdP.
	UpdateIDP(ctx context.Context, id string, req UpdateIDPRequest) (*idp.TrustedIDP, error)

	// DeleteIdP removes a trusted IdP.
	DeleteIDP(ctx context.Context, id string) error

	// RefreshKeys forces a JWKS cache refresh for a specific IdP.
	RefreshKeys(ctx context.Context, id string) error
}

// RegisterIDPRequest is the input for registering a trusted IdP.
type RegisterIDPRequest struct {
	Name     string `json:"name"`
	Issuer   string `json:"issuer"`
	JWKSUri  string `json:"jwks_uri"` // optional: auto-discovered from OIDC metadata if empty
	Audience string `json:"audience"` // optional: defaults to server issuer
}

// UpdateIDPRequest is the input for updating a trusted IdP.
type UpdateIDPRequest struct {
	Name    *string `json:"name,omitempty"`
	Enabled *bool   `json:"enabled,omitempty"`
}
