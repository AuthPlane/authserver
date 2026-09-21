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

// Note for maintainers: the omitempty tags below mirror the server's
// obligations (see client.CreateParams.Defaults and
// client.ValidateCreateParams); they don't change what the server accepts.
// This block is deliberately not the type's doc comment — docsgen copies
// the doc comment verbatim into the public API reference.

// RegisterClientRequest contains the parameters from POST /oauth/register.
// Only client_name is unconditionally required; omitted fields default or
// are conditionally required per the field notes below.
type RegisterClientRequest struct {
	RedirectURIs            []string `json:"redirect_uris,omitempty"`              // required when grant_types includes `authorization_code` or `refresh_token` — the default case, since grant_types itself defaults to `["authorization_code"]`. Max 10
	ClientName              string   `json:"client_name"`                          // max 255 bytes; a whitespace-only value is rejected
	GrantTypes              []string `json:"grant_types,omitempty"`                // defaults to `["authorization_code"]` when omitted
	ResponseTypes           []string `json:"response_types,omitempty"`             // defaults to `["code"]` when omitted
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method,omitempty"` // defaults to `none` when omitted
	// ApplicationType is the OIDC application_type (SEP-837): "web" or
	// "native". MCP clients are required to send it — omitting it defaults to
	// "web" under OIDC, which conflicts with the localhost redirect URIs
	// desktop and CLI clients need. Omitted values are stored as-is and read
	// back through client.EffectiveApplicationType.
	ApplicationType  string `json:"application_type,omitempty"`  // OIDC application_type (SEP-837): `web` or `native`; defaults to `web` when omitted
	Agent            bool   `json:"agent,omitempty"`             // Authplane extension: the client declares itself an agent, and its issued tokens then carry an `agent_id` claim. Self-asserted — this endpoint is unauthenticated, so the claim identifies the caller and does not attest that anyone approved it as an agent; see [delegation and agent chains](../concepts/delegation-and-agent-chains.md)
	AgentDescription string `json:"agent_description,omitempty"` // Authplane extension: human-readable description (max 255 bytes)
}

// RegisterClientResponse is the RFC 7591 registration response.
type RegisterClientResponse struct {
	ClientID                string   `json:"client_id"`
	ClientSecret            string   `json:"client_secret,omitempty"`
	ClientIDIssuedAt        int64    `json:"client_id_issued_at"`
	ClientSecretExpiresAt   *int64   `json:"client_secret_expires_at,omitempty"`
	RedirectURIs            []string `json:"redirect_uris"` // echoed verbatim: `null` when the request omitted the member, `[]` when it sent an empty array
	ClientName              string   `json:"client_name"`
	GrantTypes              []string `json:"grant_types"`
	ResponseTypes           []string `json:"response_types"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method"`
	// ApplicationType echoes what the client registered with, resolved through
	// client.EffectiveApplicationType so the response always states a concrete
	// value. RFC 7591 §3.2.1 has the AS return the registered metadata, and a
	// client that sent a field and got nothing back reasonably reads that as
	// rejection.
	ApplicationType string `json:"application_type"`
	// Scope is the ceiling the server assigned to this client, from
	// oauth.default_client_scope. RFC 7591 §3.2.1 returns registered metadata,
	// and a client that cannot see its own ceiling cannot tell an
	// out-of-ceiling request apart from a server fault.
	Scope            string `json:"scope,omitempty"`
	Agent            bool   `json:"agent,omitempty"`             // Authplane extension
	AgentDescription string `json:"agent_description,omitempty"` // Authplane extension
}
