package output

import "context"

// OAuthConfig is the per-request OAuth authorization-server behavior config.
type OAuthConfig struct {
	RequireScope bool // reject authorize requests missing scope (RFC 6749 §3.3)
	// IntrospectionEnabled advertises the introspection endpoint in the
	// discovery document and gates POST /oauth/introspect at runtime. When
	// false the endpoint responds 404 (matching an unregistered route) and
	// introspection_endpoint is omitted from the discovery document. It is a
	// single-value oauth.* behavior flag, same category as RequireScope.
	IntrospectionEnabled bool
}

// OAuthConfigProvider supplies OAuth behavior config for a request.
type OAuthConfigProvider interface {
	Config(ctx context.Context) (OAuthConfig, error)
}
