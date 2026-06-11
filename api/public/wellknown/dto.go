package wellknown

// healthResponse is the JSON body for GET /health and GET /ready.
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
	ScopesSupported                   []string `json:"scopes_supported"`
	ResourceIndicatorsSupported       bool     `json:"resource_indicators_supported"`
	ClientIDMetadataDocumentSupported bool     `json:"client_id_metadata_document_supported,omitempty"`
	DPoPSigningAlgValuesSupported     []string `json:"dpop_signing_alg_values_supported,omitempty"`
	AgentIdentitySupported            bool     `json:"authplane_agent_identity_supported,omitempty"` // Authplane extension (non-standard)
	IdentityAssertionSupported        bool     `json:"identity_assertion_supported,omitempty"`       // MCP XAA extension
}
