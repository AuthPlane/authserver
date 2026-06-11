package token

// IdentityAssertion represents the claims in an ID-JAG (Identity Assertion
// Authorization Grant) JWT, as defined by the MCP Enterprise-Managed
// Authorization extension and RFC 7523.
type IdentityAssertion struct {
	Issuer   string `json:"iss"`       // IdP issuer URL
	Subject  string `json:"sub"`       // User ID at IdP
	Audience string `json:"aud"`       // Our AS issuer URL
	Resource string `json:"resource"`  // MCP server URI (RFC 9728)
	ClientID string `json:"client_id"` // MCP Client ID at our AS
	JTI      string `json:"jti"`       // Unique ID (single-use)
	Expiry   int64  `json:"exp"`       // Expiration time
	IssuedAt int64  `json:"iat"`       // Issued at time
	Scope    string `json:"scope"`     // Optional requested scopes
}
