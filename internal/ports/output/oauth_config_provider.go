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
	// DefaultClientScope is the scope ceiling assigned to clients created
	// through dynamic registration and CIMD, neither of which can set their
	// own. RFC 7591 §2 permits the server to register a client with a default
	// scope set. It is only read at registration time; the authorize path
	// reads the ceiling off the stored client.
	DefaultClientScope string
}

// OAuthConfigProvider supplies OAuth behavior config for a request.
type OAuthConfigProvider interface {
	Config(ctx context.Context) (OAuthConfig, error)
}
