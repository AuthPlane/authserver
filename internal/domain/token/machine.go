// Package token contains the Family, RefreshToken, and MachineToken domain entities.
package token

import (
	"time"

	"github.com/authplane/authserver/internal/domain/scope"
)

// MachineToken represents a machine-to-machine access token issued via the
// client_credentials grant (RFC 6749 §4.4). Unlike user tokens, machine
// tokens have no associated user or refresh token — the JTI is stored for
// introspection and revocation.
type MachineToken struct {
	JTI       string
	ClientID  string
	Scopes    scope.Set
	Resource  string
	IssuedAt  time.Time
	ExpiresAt time.Time
	Revoked   bool
}

// IsExpired reports whether the machine token has expired.
func (t MachineToken) IsExpired() bool {
	return time.Now().UTC().After(t.ExpiresAt)
}
