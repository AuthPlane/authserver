package input

import (
	"context"
	"time"

	"github.com/authplane/authserver/internal/domain/audit"
	"github.com/authplane/authserver/internal/domain/client"
	"github.com/authplane/authserver/internal/domain/user"
)

// AdminPort provides administrative operations.
type AdminPort interface {
	// --- Clients ---
	CreateClient(ctx context.Context, req CreateClientRequest) (*CreateClientResponse, error)
	RotateClientSecret(ctx context.Context, clientID string) (*RotateSecretResponse, error)
	UpdateClient(ctx context.Context, id string, req UpdateClientRequest) (*client.Client, error)
	ListClients(ctx context.Context, filter ClientFilter) ([]client.Client, error)
	GetClient(ctx context.Context, id string) (*client.Client, error)
	SuspendClient(ctx context.Context, id string) error
	RevokeClient(ctx context.Context, id string) error
	ReactivateClient(ctx context.Context, id string) error
	DeleteClient(ctx context.Context, id string, force bool) error

	// --- Users ---
	CreateUser(ctx context.Context, req CreateUserRequest) (*user.User, error)
	ListUsers(ctx context.Context) ([]user.User, error)
	GetUser(ctx context.Context, id string) (*user.User, error)
	DisableUser(ctx context.Context, id string) error
	EnableUser(ctx context.Context, id string) error
	ForceLogoutUser(ctx context.Context, id string) (int, error)
	UpdateUser(ctx context.Context, id string, req UpdateUserRequest) (*user.User, error)
	DeleteUser(ctx context.Context, id string, force bool) error

	// --- Tokens ---
	ListTokens(ctx context.Context, filter TokenFilter) (*TokenListResponse, error)
	ListUserTokens(ctx context.Context, userID string, limit, offset int) (*TokenListResponse, error)
	RevokeToken(ctx context.Context, jti string) error

	// --- Audit ---
	QueryAudit(ctx context.Context, filter AuditFilter) ([]audit.Event, error)

	// --- Stats ---
	GetStats(ctx context.Context) (*DashboardStats, error)
}

// ClientFilter constrains client listing.
type ClientFilter struct {
	Status string // empty = all
	Source string // empty = all
	Limit  int
	Offset int
}

// CreateUserRequest defines a new local user.
type CreateUserRequest struct {
	Email    string
	Name     string
	Password string
	Role     user.Role
}

// AuditFilter constrains audit event queries.
type AuditFilter struct {
	Action   string // empty = all
	ActorID  string
	ClientID string
	Since    *time.Time
	Until    *time.Time
	Limit    int
	Offset   int
}

// CreateClientRequest defines the inputs for admin-provisioned client creation.
type CreateClientRequest struct {
	Name                    string
	RedirectURIs            []string
	GrantTypes              []string
	ResponseTypes           []string
	TokenEndpointAuthMethod string
	Scope                   string
	IsAgent                 bool
	AgentDescription        string
}

// CreateClientResponse returns the created client and the plaintext secret (shown once).
type CreateClientResponse struct {
	Client       *client.Client
	ClientSecret string // plaintext, shown once; empty for public clients
}

// UpdateClientRequest defines the inputs for updating a client.
// Pointer fields allow partial updates — only non-nil fields are applied.
type UpdateClientRequest struct {
	Name         *string
	RedirectURIs *[]string
	GrantTypes   *[]string
	Scope        *string
}

// UpdateUserRequest defines the inputs for updating a user.
// Pointer fields allow partial updates — only non-nil fields are applied.
type UpdateUserRequest struct {
	Email *string
	Name  *string
}

// RotateSecretResponse returns the new plaintext secret (shown once) after rotation.
type RotateSecretResponse struct {
	ClientID     string
	ClientSecret string // plaintext, shown once
}

// TokenFilter constrains token listing across families and machine tokens.
type TokenFilter struct {
	ClientID string
	UserID   string
	Limit    int
	Offset   int
}

// TokenView is a unified representation of a token (family or machine) for listing.
type TokenView struct {
	JTI       string     `json:"jti"`  // family ID or machine token JTI
	Type      string     `json:"type"` // "authorization_code" or "client_credentials"
	ClientID  string     `json:"client_id"`
	UserID    string     `json:"user_id,omitempty"`
	Scope     string     `json:"scope"`
	Resource  string     `json:"resource"`
	Status    string     `json:"status"`
	CreatedAt time.Time  `json:"created_at"`
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
}

// TokenListResponse is the paginated response for token listing.
type TokenListResponse struct {
	Tokens []TokenView `json:"tokens"`
	Total  int         `json:"total"`
}

// DashboardStats provides summary metrics for the admin dashboard.
type DashboardStats struct {
	TotalClients       int
	ActiveClients      int
	TotalUsers         int
	TokensIssuedToday  int
	TokensRevokedToday int
}
