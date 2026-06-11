package input

import (
	"context"
)

// JWTBearerPort handles token issuance via the jwt-bearer grant type
// (RFC 7523 / MCP Enterprise-Managed Authorization).
type JWTBearerPort interface {
	// GrantJWTBearer validates an ID-JAG assertion and issues an access token.
	// No refresh token is issued (per spec: "SHOULD NOT issue refresh tokens").
	GrantJWTBearer(ctx context.Context, req JWTBearerRequest) (*JWTBearerResponse, error)
}

// JWTBearerRequest contains the parameters from POST /oauth/token
// with grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer.
type JWTBearerRequest struct {
	Assertion    string // raw ID-JAG JWT from "assertion" form parameter
	ClientID     string
	ClientSecret string
	Scope        string // optional: space-separated requested scopes
	Resource     string // optional: RFC 8707 resource indicator

	// DPoP fields (RFC 9449) — optional.
	DPoPProof  string
	HTTPMethod string
	HTTPURL    string
}

// JWTBearerResponse is the response to a successful jwt-bearer grant.
type JWTBearerResponse struct {
	AccessToken string
	TokenType   string // "Bearer" or "DPoP"
	ExpiresIn   int    // seconds
	Scope       string // granted scopes
}
