// Package xaa provides domain types for Enterprise-Managed Authorization
// (Cross App Access) policies and subject mappings.
package xaa

import "time"

// Policy defines which IdP/client/scope/resource combinations are permitted
// for the jwt-bearer grant type.
type Policy struct {
	ID        string
	Name      string
	IDPID     string   // Trusted IdP this policy applies to
	ClientIDs []string // Allowed MCP client IDs (nil/empty = all clients)
	Scopes    []string // Maximum allowed scopes (nil/empty = client default)
	Resources []string // Allowed target resources (nil/empty = all resources)
	Enabled   bool
	CreatedAt time.Time
	UpdatedAt time.Time
}
