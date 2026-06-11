package output

import "context"

// OIDCTokenResult holds the verified claims from an upstream ID token.
type OIDCTokenResult struct {
	Subject string   // "sub" claim from upstream IdP
	Email   string   // "email" claim (may be empty)
	Name    string   // "name" claim (may be empty)
	Issuer  string   // "iss" claim
	Groups  []string // "groups" claim (may be nil)
}

// OIDCUserInfo holds claims returned from the UserInfo endpoint.
type OIDCUserInfo struct {
	Subject string
	Email   string
	Name    string
	Groups  []string
}

// OIDCProvider abstracts upstream OIDC federation.
type OIDCProvider interface {
	// AuthorizationURL returns the URL to redirect the user to the upstream IdP.
	// codeChallenge is the S256 PKCE challenge to send to the upstream IdP.
	AuthorizationURL(state, nonce, codeChallenge, redirectURI string) string

	// ExchangeCode exchanges an authorization code for tokens and verifies the ID token.
	// The nonce must match the one sent in the authorization request.
	// codeVerifier is the PKCE verifier corresponding to the challenge sent at authorization time.
	ExchangeCode(ctx context.Context, code, nonce, codeVerifier, redirectURI string) (*OIDCTokenResult, error)

	// GetUserInfo calls the upstream UserInfo endpoint with the given access token.
	// Returns nil, nil if the upstream does not expose a userinfo_endpoint.
	GetUserInfo(ctx context.Context, accessToken string) (*OIDCUserInfo, error)
}
