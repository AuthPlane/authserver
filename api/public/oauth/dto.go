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
