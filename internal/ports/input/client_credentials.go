package input

import (
	"context"
)

// ClientCredentialsPort handles machine-to-machine token issuance
// via the client_credentials grant (RFC 6749 §4.4).
type ClientCredentialsPort interface {
	// Exchange authenticates a client and issues a machine access token.
	// No user is involved; no refresh token is issued.
	Exchange(ctx context.Context, req ClientCredentialsRequest) (*ClientCredentialsResponse, error)
}

// ClientCredentialsRequest contains the parameters from POST /oauth/token
// with grant_type=client_credentials.
type ClientCredentialsRequest struct {
	ClientID     string
	ClientSecret string
	Scope        string // optional: space-separated requested scopes
	Resource     string // optional: RFC 8707 resource indicator → JWT aud

	// DPoP fields (RFC 9449) — optional.
	DPoPProof  string // raw DPoP proof JWT from DPoP header
	HTTPMethod string // HTTP method of the token request (e.g. "POST")
	HTTPURL    string // HTTP URL of the token endpoint
}

// ClientCredentialsResponse is the response to a successful client_credentials exchange.
type ClientCredentialsResponse struct {
	AccessToken string
	TokenType   string // "Bearer" or "DPoP"
	ExpiresIn   int    // seconds
	Scope       string // granted scopes (may differ from requested)
}
