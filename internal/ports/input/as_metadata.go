package input

import "context"

// ASMetadata is the application-level, fully-resolved authorization-server
// metadata for the discovery document. Every capability flag and value is
// already resolved for the request being served. It is NOT the RFC 8414 JSON
// DTO — the wire representation (field tags, omitempty rules) stays in the HTTP
// adapter as a transport concern.
type ASMetadata struct {
	Issuer                            string
	AuthorizationEndpoint             string
	TokenEndpoint                     string
	RegistrationEndpoint              string
	RevocationEndpoint                string
	IntrospectionEndpoint             string // empty when introspection is disabled
	JWKSURI                           string
	ResponseTypesSupported            []string
	GrantTypesSupported               []string
	TokenEndpointAuthMethodsSupported []string
	IntrospectionEndpointAuthMethods  []string // empty when introspection is disabled
	RevocationEndpointAuthMethods     []string
	CodeChallengeMethodsSupported     []string
	ScopesSupported                   []string // nil when no resources / lookup failed
	ResourceIndicatorsSupported       bool
	ClientIDMetadataDocumentSupported bool
	DPoPSigningAlgValuesSupported     []string // empty when DPoP is disabled
	AgentIdentitySupported            bool
	IdentityAssertionSupported        bool
}

// ASMetadataPort assembles the resolved authorization-server metadata served by
// the discovery endpoints (GET /.well-known/oauth-authorization-server and its
// alias /.well-known/openid-configuration).
type ASMetadataPort interface {
	Metadata(ctx context.Context) (*ASMetadata, error)
}
