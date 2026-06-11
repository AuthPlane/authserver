package input

import (
	"context"
)

// DCRPort handles Dynamic Client Registration (RFC 7591).
type DCRPort interface {
	// RegisterClient creates a new client via DCR.
	// Mode enforcement (open/approved_redirects/admin_only) is applied.
	RegisterClient(ctx context.Context, req RegisterClientRequest) (*RegisterClientResponse, error)
}

// RegisterClientRequest contains the parameters from POST /oauth/register.
type RegisterClientRequest struct {
	RedirectURIs            []string `json:"redirect_uris"`
	ClientName              string   `json:"client_name"`
	GrantTypes              []string `json:"grant_types"`
	ResponseTypes           []string `json:"response_types"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method"`
	Agent                   bool     `json:"agent,omitempty"`             // Authplane extension: mark as agent client
	AgentDescription        string   `json:"agent_description,omitempty"` // Authplane extension: human-readable description
}

// RegisterClientResponse is the RFC 7591 registration response.
type RegisterClientResponse struct {
	ClientID                string   `json:"client_id"`
	ClientSecret            string   `json:"client_secret,omitempty"`
	ClientIDIssuedAt        int64    `json:"client_id_issued_at"`
	ClientSecretExpiresAt   *int64   `json:"client_secret_expires_at,omitempty"`
	RedirectURIs            []string `json:"redirect_uris"`
	ClientName              string   `json:"client_name"`
	GrantTypes              []string `json:"grant_types"`
	ResponseTypes           []string `json:"response_types"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method"`
	Agent                   bool     `json:"agent,omitempty"`             // Authplane extension
	AgentDescription        string   `json:"agent_description,omitempty"` // Authplane extension
}
