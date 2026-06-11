// Package client contains the Client domain entity for OAuth 2.1 clients.
package client

import (
	"net/url"
	"time"

	"github.com/authplane/authserver/internal/domain"
)

// Status represents the lifecycle state of a client.
type Status string

// Client statuses.
const (
	StatusActive    Status = "active"
	StatusSuspended Status = "suspended"
	StatusRevoked   Status = "revoked"
)

// RegistrationSource indicates how the client was registered.
type RegistrationSource string

// Registration sources.
const (
	SourceDCR   RegistrationSource = "dcr"
	SourceCIMD  RegistrationSource = "cimd"
	SourceAdmin RegistrationSource = "admin"
)

// Client is an OAuth 2.1 client registered with the authorization server.
type Client struct {
	ID                      string
	SecretHash              string // bcrypt hash; empty for public clients
	Name                    string
	RedirectURIs            []string
	GrantTypes              []string // e.g. ["authorization_code"]
	ResponseTypes           []string // e.g. ["code"]
	TokenEndpointAuthMethod string   // "none", "client_secret_basic", "client_secret_post"
	Status                  Status
	RegistrationSource      RegistrationSource
	CIMDURL                 string // non-empty for CIMD-registered clients
	Scope                   string // space-separated list of allowed scopes (RFC 7591); empty = no restriction
	IsAgent                 bool   // true for agent clients (Authplane extension)
	AgentDescription        string // human-readable agent description (max 255 chars)
	Version                 int64  // optimistic locking — starts at 1, increments on each Update
	IssuedAt                time.Time
	UpdatedAt               time.Time
}

// IsPublic returns true if the client has no secret (public client).
func (c *Client) IsPublic() bool {
	return c.SecretHash == ""
}

// IsActive returns true if the client can participate in OAuth flows.
func (c *Client) IsActive() bool {
	return c.Status == StatusActive
}

// Suspend transitions an active client to suspended.
func (c *Client) Suspend() error {
	if c.Status != StatusActive {
		return &StateError{From: c.Status, To: StatusSuspended}
	}
	c.Status = StatusSuspended
	c.UpdatedAt = time.Now().UTC()
	return nil
}

// Revoke permanently revokes a client. Allowed from any state.
func (c *Client) Revoke() {
	c.Status = StatusRevoked
	c.UpdatedAt = time.Now().UTC()
}

// Reactivate transitions a suspended client back to active.
func (c *Client) Reactivate() error {
	if c.Status != StatusSuspended {
		return &StateError{From: c.Status, To: StatusActive}
	}
	c.Status = StatusActive
	c.UpdatedAt = time.Now().UTC()
	return nil
}

// HasRedirectURI checks if uri is in the client's registered redirect URIs.
// For loopback redirects (localhost, 127.0.0.1, [::1]) the port is ignored
// per RFC 8252 §7.3. All other URIs use exact string match per RFC 9700.
func (c *Client) HasRedirectURI(uri string) bool {
	for _, registered := range c.RedirectURIs {
		if registered == uri {
			return true
		}
		if matchesLoopbackRedirect(registered, uri) {
			return true
		}
	}
	return false
}

// matchesLoopbackRedirect returns true when registered is a loopback URI and
// uri matches on scheme + host + path (port ignored) per RFC 8252 §7.3.
func matchesLoopbackRedirect(registered, uri string) bool {
	r, err := url.Parse(registered)
	if err != nil {
		return false
	}
	if !isLoopback(r.Hostname()) {
		return false
	}
	u, err := url.Parse(uri)
	if err != nil {
		return false
	}
	return r.Scheme == u.Scheme &&
		r.Hostname() == u.Hostname() &&
		r.Path == u.Path &&
		r.RawQuery == u.RawQuery
}

// isLoopback reports whether host is a loopback address.
func isLoopback(host string) bool {
	return host == "localhost" || host == "127.0.0.1" || host == "::1"
}

// StateError is returned when a state transition is invalid.
type StateError struct {
	From Status
	To   Status
}

func (e *StateError) Error() string {
	return "invalid client state transition from " + string(e.From) + " to " + string(e.To)
}

// Code reports the canonical error code so writeDomainOrInternalError maps
// the no-op transition to HTTP 409 instead of falling through to 500.
func (e *StateError) Code() string { return domain.CodeConflict }

// CreateParams are the inputs for creating a new client via DCR or admin.
type CreateParams struct {
	Name                    string
	RedirectURIs            []string
	GrantTypes              []string
	ResponseTypes           []string
	TokenEndpointAuthMethod string
	RegistrationSource      RegistrationSource
	CIMDURL                 string
	IsAgent                 bool
	AgentDescription        string
}

// Defaults fills in RFC 7591 defaults for optional fields.
func (p *CreateParams) Defaults() {
	if len(p.GrantTypes) == 0 {
		p.GrantTypes = []string{"authorization_code"}
	}
	if len(p.ResponseTypes) == 0 {
		p.ResponseTypes = []string{"code"}
	}
	if p.TokenEndpointAuthMethod == "" {
		p.TokenEndpointAuthMethod = "none"
	}
}
