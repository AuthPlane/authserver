package input

import "context"

// TokenPort handles token issuance and refresh.
type TokenPort interface {
	// ExchangeCode exchanges an authorization code + PKCE verifier for tokens.
	ExchangeCode(ctx context.Context, req ExchangeCodeRequest) (*TokenResponse, error)

	// RefreshToken rotates a refresh token and issues a new access token.
	// Reuse of a consumed refresh token triggers family revocation.
	RefreshToken(ctx context.Context, req RefreshTokenRequest) (*TokenResponse, error)
}

// ExchangeCodeRequest contains the parameters from POST /oauth/token
// with grant_type=authorization_code.
type ExchangeCodeRequest struct {
	Code         string
	RedirectURI  string
	ClientID     string
	ClientSecret string // empty for public clients
	CodeVerifier string // PKCE
	// Resource is the RFC 8707 resource indicator, optional at the token
	// endpoint. When present it must name the resource the authorization grant
	// already covers; anything else is refused with invalid_target rather than
	// quietly ignored, because a client that asked for one audience and was
	// handed another only finds out at the resource server.
	Resource string

	// DPoP fields (RFC 9449) — optional.
	DPoPProof  string // raw DPoP proof JWT from DPoP header
	HTTPMethod string // HTTP method of the token request (e.g. "POST")
	HTTPURL    string // HTTP URL of the token endpoint
}

// RefreshTokenRequest contains the parameters from POST /oauth/token
// with grant_type=refresh_token.
type RefreshTokenRequest struct {
	RefreshToken string
	ClientID     string
	ClientSecret string // empty for public clients
	Scope        string // optional: request narrower scope
	// Resource is the RFC 8707 resource indicator, optional. Same rule as
	// ExchangeCodeRequest.Resource: it may only name what the refresh family
	// was issued against.
	Resource string

	// DPoP fields (RFC 9449) — optional.
	DPoPProof  string // raw DPoP proof JWT from DPoP header
	HTTPMethod string // HTTP method of the token request (e.g. "POST")
	HTTPURL    string // HTTP URL of the token endpoint
}

// TokenResponse is the response to a successful token request.
type TokenResponse struct {
	AccessToken  string
	TokenType    string // "Bearer" or "DPoP"
	ExpiresIn    int    // seconds
	RefreshToken string
	Scope        string
}
