// Package idp contains the TrustedIDP domain entity for XAA enterprise-managed authorization.
package idp

import "time"

// TrustedIDP represents an enterprise identity provider trusted to issue ID-JAG assertions.
type TrustedIDP struct {
	ID        string
	Name      string // Human-readable name ("Acme Corp Okta")
	Issuer    string // IdP issuer URL (https://acme.okta.com)
	JWKSUri   string // JWKS endpoint (discovered or configured)
	Audience  string // Expected audience in ID-JAGs (our issuer URL)
	Enabled   bool
	CreatedAt time.Time
	UpdatedAt time.Time
}
