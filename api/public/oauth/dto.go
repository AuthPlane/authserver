package oauth

import "github.com/authplane/authserver/internal/ports/input"

// tokenResponseDTO is the JSON structure for POST /oauth/token responses.
type tokenResponseDTO struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token,omitempty"`
	Scope        string `json:"scope,omitempty"`
}

// tokenExchangeResponseDTO is the JSON response for RFC 8693 token exchange.
// It includes issued_token_type which is not present in standard token responses.
type tokenExchangeResponseDTO struct {
	AccessToken     string `json:"access_token"`
	IssuedTokenType string `json:"issued_token_type"`
	TokenType       string `json:"token_type"`
	ExpiresIn       int    `json:"expires_in"`
	Scope           string `json:"scope,omitempty"`
}

// consentPageData holds the template data for the consent page.
//
// ResourceDisplayName is the operator-friendly name shown in the per-MCP
// header ( / DESIGN_v4 §7). ResourceSlug is rendered as the
// audit-friendly identifier in the resource pill below the header.
type consentPageData struct {
	SessionID           string
	ClientName          string
	ClientID            string
	Resource            string
	ResourceDisplayName string
	ResourceSlug        string
	Scopes              []input.ScopeInfo
	CSRFToken           string
	FormAction          string

	// RedirectHost is the host an approval sends the authorization code to,
	// and RedirectIsLoopback marks it as the user's own machine. Rendered
	// next to the decision buttons rather than in the header, because the
	// header is built from a self-declared client name and this is the part
	// of the request the server actually verified.
	RedirectHost       string
	RedirectIsLoopback bool
}

// loginPageData holds the template data for the login page.
type loginPageData struct {
	Error           string
	Redirect        string
	CSRFToken       string
	OIDCDisplayName string
	OIDCStartURL    string
	ShowLocalLogin  bool
	FormAction      string
}

// oidcErrorData holds the template data for the OIDC error page.
type oidcErrorData struct {
	Error    string
	LoginURL string
}

// registerRequest is the JSON body for POST /oauth/register: the RFC 7591
// client metadata members this authorization server reads. Members outside this
// set are accepted and ignored, per RFC 7591 §3.1.
//
// (Kept as a wire DTO rather than decoding into the input port type so docsgen,
// which reads struct tags from this file, can publish a field table for the
// endpoint.)
type registerRequest struct {
	RedirectURIs            []string `json:"redirect_uris"`
	ClientName              string   `json:"client_name"`
	GrantTypes              []string `json:"grant_types"`
	ResponseTypes           []string `json:"response_types"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method"`
	// ApplicationType is the OIDC application_type: "web" or "native". MCP
	// clients are required to send it — omitting it defaults to "web" under
	// OIDC, which refuses the localhost redirect URIs native clients need.
	ApplicationType string `json:"application_type,omitempty"`
	// Agent marks the client as an agent (Authplane extension, not RFC 7591).
	Agent bool `json:"agent,omitempty"`
	// AgentDescription is a human-readable agent description (Authplane
	// extension, max 255 chars).
	AgentDescription string `json:"agent_description,omitempty"`
}

// registerResponse is the JSON body returned by POST /oauth/register
// (RFC 7591 §3.2.1).
type registerResponse struct {
	ClientID              string `json:"client_id"`
	ClientSecret          string `json:"client_secret,omitempty"`
	ClientIDIssuedAt      int64  `json:"client_id_issued_at"`
	ClientSecretExpiresAt *int64 `json:"client_secret_expires_at,omitempty"`

	RedirectURIs            []string `json:"redirect_uris"`
	ClientName              string   `json:"client_name"`
	GrantTypes              []string `json:"grant_types"`
	ResponseTypes           []string `json:"response_types"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method"`
	// ApplicationType is always concrete, resolved through the OIDC default, so
	// a client that omitted it learns what it was defaulted to.
	ApplicationType  string `json:"application_type"`
	Agent            bool   `json:"agent,omitempty"`
	AgentDescription string `json:"agent_description,omitempty"`
}
