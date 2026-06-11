package input

import "context"

// TokenExchangePort handles RFC 8693 token exchange.
type TokenExchangePort interface {
	Exchange(ctx context.Context, req TokenExchangeRequest) (*TokenExchangeResponse, error)
}

// TokenExchangeRequest contains the parameters from POST /oauth/token
// with grant_type=urn:ietf:params:oauth:grant-type:token-exchange.
type TokenExchangeRequest struct {
	SubjectToken     string
	SubjectTokenType string
	ActorToken       string
	ActorTokenType   string
	Scope            string
	Resource         string
	ClientID         string
	ClientSecret     string

	// DPoP fields (RFC 9449) — optional.
	DPoPProof  string // raw DPoP proof JWT from DPoP header
	HTTPMethod string // HTTP method of the token request (e.g. "POST")
	HTTPURL    string // HTTP URL of the token endpoint
}

// TokenExchangeResponse is the response to a successful token exchange (RFC 8693 §2.2).
type TokenExchangeResponse struct {
	AccessToken     string
	IssuedTokenType string // "urn:ietf:params:oauth:token-type:access_token"
	TokenType       string // "Bearer" or "DPoP"
	ExpiresIn       int    // seconds
	Scope           string
}
