package wellknown

// healthResponse is the JSON body for GET /livez, GET /health and GET /ready.
type healthResponse struct {
	Status string `json:"status"`
	Time   string `json:"time"`
	DB     string `json:"db,omitempty"`
}

// asMetadata is the JSON body for GET /.well-known/oauth-authorization-server (RFC 8414).
type asMetadata struct {
	Issuer                            string   `json:"issuer"`
	AuthorizationEndpoint             string   `json:"authorization_endpoint"`
	TokenEndpoint                     string   `json:"token_endpoint"`
	RegistrationEndpoint              string   `json:"registration_endpoint"`
	RevocationEndpoint                string   `json:"revocation_endpoint"`
	IntrospectionEndpoint             string   `json:"introspection_endpoint,omitempty"`
	JWKSURI                           string   `json:"jwks_uri"`
	ResponseTypesSupported            []string `json:"response_types_supported"`
	GrantTypesSupported               []string `json:"grant_types_supported"`
	TokenEndpointAuthMethodsSupported []string `json:"token_endpoint_auth_methods_supported"`
	IntrospectionEndpointAuthMethods  []string `json:"introspection_endpoint_auth_methods_supported,omitempty"`
	RevocationEndpointAuthMethods     []string `json:"revocation_endpoint_auth_methods_supported"`
	CodeChallengeMethodsSupported     []string `json:"code_challenge_methods_supported"`
	ScopesSupported                   []string `json:"scopes_supported,omitempty"`
	ResourceIndicatorsSupported       bool     `json:"resource_indicators_supported"`
	ClientIDMetadataDocumentSupported bool     `json:"client_id_metadata_document_supported,omitempty"`

	// AuthorizationResponseIssParameterSupported is RFC 9207 Section 2.3. No
	// omitempty: a client distinguishes "false" from "absent" only by the local
	// policy in Section 2.4, and omitting the field when true would be a lie,
	// while emitting it explicitly lets a client enforce the strict branch —
	// reject an authorization response that arrives with no iss.
	AuthorizationResponseIssParameterSupported bool `json:"authorization_response_iss_parameter_supported"`

	DPoPSigningAlgValuesSupported []string `json:"dpop_signing_alg_values_supported,omitempty"`
	AgentIdentitySupported        bool     `json:"authplane_agent_identity_supported,omitempty"` // Authplane extension (non-standard)

	// AuthorizationGrantProfilesSupported is the discovery field the stable MCP
	// Enterprise-Managed Authorization extension reads (its Discovery section:
	// a client determines profile support by checking for
	// urn:ietf:params:oauth:grant-profile:id-jag here). Defined in
	// draft-ietf-oauth-identity-assertion-authz-grant Section 7.2.
	AuthorizationGrantProfilesSupported []string `json:"authorization_grant_profiles_supported,omitempty"`

	// IdentityAssertionSupported is a non-standard Authplane flag for the same
	// capability, emitted before the extension stabilized. Deprecated: no
	// conformant client reads it; scheduled for removal in v0.3.0. Clients must
	// use authorization_grant_profiles_supported.
	IdentityAssertionSupported bool `json:"identity_assertion_supported,omitempty"`
}

// protectedResourceMetadata is the JSON body for
// GET /.well-known/oauth-protected-resource and its path-suffixed form
// (RFC 9728 §2).
//
// Field order follows the RFC's own presentation order. resource is the only
// REQUIRED member and so carries no omitempty; the rest are OPTIONAL and are
// omitted rather than emitted empty, since a client reads an empty
// scopes_supported as "this resource advertises no scopes" rather than "this
// server did not say".
type protectedResourceMetadata struct {
	Resource               string   `json:"resource"`
	AuthorizationServers   []string `json:"authorization_servers,omitempty"`
	ScopesSupported        []string `json:"scopes_supported,omitempty"`
	BearerMethodsSupported []string `json:"bearer_methods_supported,omitempty"`
	ResourceName           string   `json:"resource_name,omitempty"`
}
