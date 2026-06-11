package input

import "context"

// IntrospectionPort handles token introspection (RFC 7662).
type IntrospectionPort interface {
	IntrospectToken(ctx context.Context, req IntrospectRequest) (*IntrospectResponse, error)
}

// IntrospectRequest contains the parameters from POST /oauth/introspect.
type IntrospectRequest struct {
	Token         string
	TokenTypeHint string // "access_token" or "refresh_token" (optional)
	ClientID      string
	ClientSecret  string // empty for public clients
}

// IntrospectResponse is the RFC 7662 §2.2 response body.
type IntrospectResponse struct {
	Active    bool                   `json:"active"`
	Scope     string                 `json:"scope,omitempty"`
	ClientID  string                 `json:"client_id,omitempty"`
	Username  string                 `json:"username,omitempty"`
	Sub       string                 `json:"sub,omitempty"`
	Aud       string                 `json:"aud,omitempty"`
	Iss       string                 `json:"iss,omitempty"`
	Exp       int64                  `json:"exp,omitempty"`
	Iat       int64                  `json:"iat,omitempty"`
	Jti       string                 `json:"jti,omitempty"`
	TokenType string                 `json:"token_type,omitempty"`
	Cnf       map[string]interface{} `json:"cnf,omitempty"` // DPoP confirmation (RFC 9449): {"jkt": "<thumbprint>"}
}
