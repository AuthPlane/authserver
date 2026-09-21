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
	// ApplicationType is the OIDC application_type declared at registration:
	// ApplicationTypeWeb or ApplicationTypeNative. Empty means the client
	// registered before we asked for it — read it through EffectiveApplicationType,
	// which applies the OIDC default rather than leaking the empty value.
	ApplicationType string
	// Scope is the space-separated per-client scope ceiling (RFC 7591 §2).
	// A request exceeding it is refused with invalid_scope (RFC 6749 §5.2).
	//
	// Enforced on authorization_code (services/authorize.go),
	// client_credentials (services/client_credentials.go), jwt-bearer
	// (services/jwt_bearer.go) and refresh_token (services/token.go). On
	// refresh the ceiling is read as it stands at refresh time, not as it
	// stood at consent, so narrowing a live client shrinks what its existing
	// refresh families can still mint.
	//
	// An empty value is a ceiling of zero on the two machine grants. On
	// authorization_code and refresh_token it is not, until v0.3.0: those
	// paths never consulted the ceiling before, so denying an absent one would
	// break every client that has none — which is every client dynamic
	// registration and CIMD ever created, since neither door lets a client
	// state one. Until then an empty ceiling is left unenforced there, and
	// logged on the authorize path.
	//
	// token_exchange has its own per-resource gate instead and does not read
	// this field.
	//
	// The admin surface sets it directly. Dynamic registration and CIMD
	// cannot: nothing in either door states a ceiling, so both stamp
	// oauth.default_client_scope on the clients they create — and only on
	// those whose grants all keep a user in the loop, since a ceiling reachable
	// from a machine grant would be spendable with no consent behind it.
	// oauth.default_client_scope is a startup warning rather than a boot
	// requirement, so an empty ceiling is reachable in production. On the
	// authorization_code path the ceiling bounds what consent may propose —
	// the user narrows within it and can never widen past it.
	Scope            string
	IsAgent          bool   // true for agent clients (Authplane extension)
	AgentDescription string // human-readable agent description (max 255 chars)
	Version          int64  // optimistic locking — starts at 1, increments on each Update
	IssuedAt         time.Time
	UpdatedAt        time.Time
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

// Application types defined by OpenID Connect Dynamic Client Registration 1.0.
//
// The distinction is not cosmetic: an OIDC-conformant AS refuses a "web" client
// the http://localhost and http://127.0.0.1 redirect URIs that desktop apps,
// mobile apps, CLI tools and locally-hosted web apps rely on. The MCP
// 2026-07-28 client-registration spec therefore requires MCP clients to declare
// one, since omitting it defaults to "web".
const (
	ApplicationTypeWeb    = "web"
	ApplicationTypeNative = "native"
)

// EffectiveApplicationType returns the client's application type, substituting
// the OIDC default for a client that registered before the field existed.
//
// Callers must use this rather than reading ApplicationType directly: an empty
// stored value and an explicit "web" mean the same thing to every consumer, and
// only the audit trail cares which one is in the row.
func (c *Client) EffectiveApplicationType() string {
	if c.ApplicationType == "" {
		return ApplicationTypeWeb
	}
	return c.ApplicationType
}

// ValidateApplicationType accepts the two OIDC-defined values, plus empty for
// a request that omits the field.
func ValidateApplicationType(t string) error {
	switch t {
	case "", ApplicationTypeWeb, ApplicationTypeNative:
		return nil
	default:
		return &ValidationError{
			Errors: []string{`application_type must be "web" or "native", got "` + t + `"`},
		}
	}
}
