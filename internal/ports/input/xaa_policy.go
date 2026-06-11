package input

import (
	"context"

	"github.com/authplane/authserver/internal/domain/xaa"
)

// XAAPolicyPort provides administrative CRUD for XAA policies.
type XAAPolicyPort interface {
	CreatePolicy(ctx context.Context, req CreatePolicyRequest) (*xaa.Policy, error)
	GetPolicy(ctx context.Context, id string) (*xaa.Policy, error)
	ListPolicies(ctx context.Context, idpID string) ([]xaa.Policy, error)
	UpdatePolicy(ctx context.Context, id string, req UpdatePolicyRequest) (*xaa.Policy, error)
	DeletePolicy(ctx context.Context, id string) error
}

// CreatePolicyRequest is the input for creating an XAA policy.
type CreatePolicyRequest struct {
	Name      string   `json:"name"`
	IDPID     string   `json:"idp_id"`
	ClientIDs []string `json:"client_ids,omitempty"`
	Scopes    []string `json:"scopes,omitempty"`
	Resources []string `json:"resources,omitempty"`
}

// UpdatePolicyRequest is the input for updating an XAA policy.
type UpdatePolicyRequest struct {
	Name      *string  `json:"name,omitempty"`
	ClientIDs []string `json:"client_ids,omitempty"`
	Scopes    []string `json:"scopes,omitempty"`
	Resources []string `json:"resources,omitempty"`
	Enabled   *bool    `json:"enabled,omitempty"`
}
