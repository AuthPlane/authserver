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

	// AuthorizationResponseIssParameterSupported reports that authorization
	// responses carry the iss parameter (RFC 9207 Section 2). RFC 9207
	// Section 2.3 makes advertising this MANDATORY for a server that emits iss,
	// because clients key their rejection behavior on it: a client that reads
	// true here MUST reject any authorization response arriving without iss.
	// It is therefore always true — the authorize and consent handlers fail the
	// request rather than emit a response without iss, so the flag can never
	// overstate what the server does.
	AuthorizationResponseIssParameterSupported bool

	DPoPSigningAlgValuesSupported []string // empty when DPoP is disabled
	AgentIdentitySupported        bool

	// AuthorizationGrantProfilesSupported lists the OAuth grant profiles this AS
	// accepts, per draft-ietf-oauth-identity-assertion-authz-grant Section 7.2.
	// It carries urn:ietf:params:oauth:grant-profile:id-jag when the jwt-bearer
	// grant is enabled: that URN is how the stable MCP Enterprise-Managed
	// Authorization extension tells a client the ID-JAG flow is available here.
	AuthorizationGrantProfilesSupported []string

	// IdentityAssertionSupported is the pre-2026-07-28 Authplane-private flag for
	// the same capability. Deprecated: it appears in no spec or RFC, so no
	// conformant client reads it. Kept for one release so existing integrations
	// that hard-coded it keep working; AuthorizationGrantProfilesSupported is the
	// field clients actually look at.
	IdentityAssertionSupported bool
}

// ASMetadataPort assembles the resolved authorization-server metadata served by
// the discovery endpoints (GET /.well-known/oauth-authorization-server and its
// alias /.well-known/openid-configuration).
type ASMetadataPort interface {
	Metadata(ctx context.Context) (*ASMetadata, error)
}
