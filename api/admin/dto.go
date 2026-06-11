package admin

import (
	"encoding/json"
	"time"

	"github.com/authplane/authserver/internal/admin/dto"
	"github.com/authplane/authserver/internal/domain/audit"
	"github.com/authplane/authserver/internal/domain/client"
	"github.com/authplane/authserver/internal/domain/user"
	"github.com/authplane/authserver/internal/ports/input"
)

// createClientRequest is the JSON body for POST /admin/clients.
type createClientRequest struct {
	ClientName              string   `json:"client_name"`
	RedirectURIs            []string `json:"redirect_uris"`
	GrantTypes              []string `json:"grant_types"`
	ResponseTypes           []string `json:"response_types"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method"`
	Scope                   string   `json:"scope"`
	Agent                   bool     `json:"agent"`
	AgentDescription        string   `json:"agent_description"`
}

// createClientResponse is the JSON body for POST /admin/clients (201).
// The client_secret is shown once and never stored in plaintext.
type createClientResponse struct {
	ClientID                string   `json:"client_id"`
	ClientSecret            string   `json:"client_secret,omitempty"`
	ClientName              string   `json:"client_name"`
	RedirectURIs            []string `json:"redirect_uris"`
	GrantTypes              []string `json:"grant_types"`
	ResponseTypes           []string `json:"response_types"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method"`
	Scope                   string   `json:"scope"`
	Status                  string   `json:"status"`
	RegistrationSource      string   `json:"registration_source"`
	IsAgent                 bool     `json:"agent,omitempty"`
	AgentDescription        string   `json:"agent_description,omitempty"`
	IssuedAt                string   `json:"issued_at"`
}

// updateClientRequest is the JSON body for PATCH /admin/clients/{id}.
// Pointer fields enable partial updates — only non-null fields are applied.
type updateClientRequest struct {
	Name         *string   `json:"client_name,omitempty"`
	RedirectURIs *[]string `json:"redirect_uris,omitempty"`
	GrantTypes   *[]string `json:"grant_types,omitempty"`
	Scope        *string   `json:"scope,omitempty"`
}

// rotateSecretResponse is the JSON body for POST /admin/clients/{id}/rotate-secret (200).
// The client_secret is shown once and never stored in plaintext.
type rotateSecretResponse struct {
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
}

// createUserRequest is the JSON body for POST /admin/users.
type createUserRequest struct {
	Email    string `json:"email"`
	Name     string `json:"name"`
	Password string `json:"password"`
	Role     string `json:"role"`
}

type updateUserRequest struct {
	Email *string `json:"email,omitempty"`
	Name  *string `json:"name,omitempty"`
}

// statusResponse is the JSON body for simple status-only responses.
type statusResponse struct {
	Status string `json:"status"`
}

// clientView is the sanitized JSON representation of a client (no secrets).
type clientView struct {
	ID                      string                    `json:"id"`
	Name                    string                    `json:"name"`
	RedirectURIs            []string                  `json:"redirect_uris"`
	GrantTypes              []string                  `json:"grant_types"`
	ResponseTypes           []string                  `json:"response_types"`
	TokenEndpointAuthMethod string                    `json:"token_endpoint_auth_method"`
	Status                  client.Status             `json:"status"`
	RegistrationSource      client.RegistrationSource `json:"registration_source"`
	CIMDURL                 string                    `json:"cimd_url"`
	IssuedAt                time.Time                 `json:"issued_at"`
	UpdatedAt               time.Time                 `json:"updated_at"`
}

// newClientView creates a clientView from a domain client, stripping sensitive fields.
func newClientView(c *client.Client) clientView {
	return clientView{
		ID:                      c.ID,
		Name:                    c.Name,
		RedirectURIs:            c.RedirectURIs,
		GrantTypes:              c.GrantTypes,
		ResponseTypes:           c.ResponseTypes,
		TokenEndpointAuthMethod: c.TokenEndpointAuthMethod,
		Status:                  c.Status,
		RegistrationSource:      c.RegistrationSource,
		CIMDURL:                 c.CIMDURL,
		IssuedAt:                c.IssuedAt,
		UpdatedAt:               c.UpdatedAt,
	}
}

// newClientViews creates a slice of clientView from domain clients.
func newClientViews(cs []client.Client) []clientView {
	out := make([]clientView, len(cs))
	for i := range cs {
		out[i] = newClientView(&cs[i])
	}
	return out
}

// userView is the sanitized JSON representation of a user (no password hash).
type userView struct {
	ID        string        `json:"id"`
	Email     string        `json:"email"`
	Name      string        `json:"name"`
	Role      user.Role     `json:"role"`
	Status    user.Status   `json:"status"`
	Provider  user.Provider `json:"provider"`
	CreatedAt time.Time     `json:"created_at"`
}

// newUserView creates a userView from a domain user, stripping sensitive fields.
func newUserView(u *user.User) userView {
	return userView{
		ID:        u.ID,
		Email:     u.Email,
		Name:      u.Name,
		Role:      u.Role,
		Status:    u.Status,
		Provider:  u.Provider,
		CreatedAt: u.CreatedAt,
	}
}

// newUserViews creates a slice of userView from domain users.
func newUserViews(us []user.User) []userView {
	out := make([]userView, len(us))
	for i := range us {
		out[i] = newUserView(&us[i])
	}
	return out
}

// statsView is the JSON body for GET /admin/stats.
type statsView struct {
	Clients         int `json:"clients"`
	Users           int `json:"users"`
	ActiveTokens24h int `json:"active_tokens_24h"`
	RevokedTokens   int `json:"revoked_tokens"`
	Connections     int `json:"connections"`
}

func newStatsView(s input.DashboardStats) statsView {
	return statsView{
		Clients:         s.TotalClients,
		Users:           s.TotalUsers,
		ActiveTokens24h: s.TokensIssuedToday,
		RevokedTokens:   s.TokensRevokedToday,
		Connections:     0, // TODO: add upstream-connection count to DashboardStats
	}
}

// keyView is the JSON representation of a signing key (public info only).
type keyView struct {
	KeyID     string `json:"kid"`
	Algorithm string `json:"alg"`
	Use       string `json:"use"`
	Status    string `json:"status"`
}

// listKeysResponse is the JSON body for GET /admin/keys.
type listKeysResponse struct {
	Keys []keyView `json:"keys"`
}

// rotateKeyResponse is the JSON body for POST /admin/keys/rotate.
type rotateKeyResponse struct {
	KeyID     string `json:"kid"`
	Algorithm string `json:"alg"`
}

// dcrSettingsView is the JSON body for GET/PATCH /admin/settings/dcr.
type dcrSettingsView struct {
	Mode string `json:"mode"`
}

// updateDCRSettingsRequest is the JSON body for PATCH /admin/settings/dcr.
type updateDCRSettingsRequest struct {
	Mode string `json:"mode"`
}

// auditEventView is the JSON representation of an audit event.
type auditEventView struct {
	ID        string `json:"id"`
	Action    string `json:"action"`
	ActorID   string `json:"actor_id"`
	ClientID  string `json:"client_id"`
	IP        string `json:"ip"`
	Detail    string `json:"detail"`
	TraceID   string `json:"trace_id"`
	CreatedAt string `json:"created_at"`
}

func newAuditEventView(e audit.Event) auditEventView {
	return auditEventView{
		ID:        e.ID,
		Action:    string(e.Action),
		ActorID:   e.ActorID,
		ClientID:  e.ClientID,
		IP:        e.IP,
		Detail:    e.Detail,
		TraceID:   e.TraceID,
		CreatedAt: e.CreatedAt.Format(time.RFC3339),
	}
}

func newAuditEventViews(events []audit.Event) []auditEventView {
	out := make([]auditEventView, len(events))
	for i := range events {
		out[i] = newAuditEventView(events[i])
	}
	return out
}

// authVerifyResponse is the JSON body for POST /admin/auth/verify.
type authVerifyResponse struct {
	Valid   bool   `json:"valid"`
	Version string `json:"version"`
}

// systemStatusResponse is the JSON body for GET /admin/system/status.
type systemStatusResponse struct {
	Version    string            `json:"version"`
	Uptime     string            `json:"uptime"`
	UptimeSecs int64             `json:"uptime_secs"`
	Subsystems []subsystemStatus `json:"subsystems"`
}

// subsystemStatus represents the health status of a server subsystem.
type subsystemStatus struct {
	Name   string `json:"name"`
	Status string `json:"status"`
	Driver string `json:"driver,omitempty"`
}

// systemConfigResponse is the JSON body for GET /admin/system/config.
type systemConfigResponse struct {
	Issuer            string                      `json:"issuer"`
	Storage           storageConfigView           `json:"storage"`
	Signing           signingConfigView           `json:"signing"`
	Encryption        encryptionConfigView        `json:"encryption"`
	DCR               dcrConfigView               `json:"dcr"`
	RateLimit         rateLimitConfigView         `json:"rate_limit"`
	ClientCredentials clientCredentialsConfigView `json:"client_credentials"`
	DPoP              dpopConfigView              `json:"dpop"`
	TokenExchange     tokenExchangeConfigView     `json:"token_exchange"`
	Agents            agentsConfigView            `json:"agents"`
	OIDC              oidcConfigView              `json:"oidc"`
}

type storageConfigView struct {
	Driver string `json:"driver"`
}

type signingConfigView struct {
	Algorithm string `json:"algorithm"`
	KeyStore  string `json:"key_store"`
}

type encryptionConfigView struct {
	Driver string `json:"driver"`
}

type dcrConfigView struct {
	Mode string `json:"mode"`
}

type rateLimitConfigView struct {
	Enabled bool `json:"enabled"`
}

type clientCredentialsConfigView struct {
	Enabled bool `json:"enabled"`
}

type dpopConfigView struct {
	Enabled      bool   `json:"enabled"`
	NonceTTL     string `json:"nonce_ttl,omitempty"`
	RequireNonce bool   `json:"require_nonce"`
}

type tokenExchangeConfigView struct {
	Enabled       bool `json:"enabled"`
	MaxChainDepth int  `json:"max_chain_depth,omitempty"`
}

type agentsConfigView struct {
	Enabled     bool `json:"enabled"`
	JWKSListing bool `json:"jwks_listing"`
}

type oidcConfigView struct {
	Enabled bool `json:"enabled"`
}

// --- Unified Resource + Broker Provider DTOs ---
//
// The view shapes + conversion helpers were extracted to
// internal/admin/dto so they're shareable with the cmd/authserver CLI
// ( follow-up). The aliases below preserve the local lowercase
// identifiers that this package's handler code references; HTTP-only
// REQUEST shapes (createResourceRequest, patchResourceRequest, etc.)
// continue to live here because the CLI doesn't read JSON bodies.

type (
	scopeWithUpstreamView = dto.ScopeView
	policyView            = dto.PolicyView
	resourceView          = dto.ResourceView
	brokerProviderView    = dto.BrokerProviderView
	issuanceView          = dto.IssuanceView
	issuanceListResponse  = dto.IssuanceListResponse
)

var (
	scopesUpstreamFromViews = dto.ScopesFromViews
	policyFromView          = dto.PolicyFromView
	resourceToView          = dto.ResourceToView
	brokerProviderToView    = dto.BrokerProviderToView
	userGrantsToView        = dto.UserGrantsToView
	issuanceToView          = dto.IssuanceToView
	issuancesToViews        = dto.IssuancesToViews
)

// createResourceRequest is the JSON body for POST /admin/resources.
//
// BrokerProviderSlug is the slug-friendly alternative to
// BrokerProviderID. Operators may supply either one — the handler
// resolves the slug to a UUID before persistence. Supplying both with
// inconsistent values returns 400; supplying both with consistent values
// is accepted and the slug is honored.
type createResourceRequest struct {
	Slug               string                  `json:"slug"`
	URI                string                  `json:"uri"`
	BackendKind        string                  `json:"backend_kind"`
	BrokerProviderID   string                  `json:"broker_provider_id,omitempty"`
	BrokerProviderSlug string                  `json:"broker_provider_slug,omitempty"`
	DisplayName        string                  `json:"display_name"`
	Scopes             []scopeWithUpstreamView `json:"scopes"`
	Policy             *policyView             `json:"policy,omitempty"`
}

// patchResourceRequest is the JSON body for PATCH /admin/resources/{id}.
// Pointer fields enable partial updates with the security-by-default rule
// described on input.ResourcePatch.
type patchResourceRequest struct {
	Slug             *string                  `json:"slug,omitempty"`
	URI              *string                  `json:"uri,omitempty"`
	BackendKind      *string                  `json:"backend_kind,omitempty"`
	BrokerProviderID *string                  `json:"broker_provider_id,omitempty"`
	DisplayName      *string                  `json:"display_name,omitempty"`
	Scopes           *[]scopeWithUpstreamView `json:"scopes,omitempty"`
	Policy           *policyView              `json:"policy,omitempty"`
}

// createBrokerProviderRequest is the JSON body for POST /admin/broker-providers.
type createBrokerProviderRequest struct {
	Slug        string          `json:"slug"`
	DisplayName string          `json:"display_name"`
	Protocol    string          `json:"protocol"`
	ConfigData  json.RawMessage `json:"config_data"`
}

// patchBrokerProviderRequest is the JSON body for
// PATCH /admin/broker-providers/{id}. Pointer fields enable partial updates.
type patchBrokerProviderRequest struct {
	Slug        *string          `json:"slug,omitempty"`
	DisplayName *string          `json:"display_name,omitempty"`
	Protocol    *string          `json:"protocol,omitempty"`
	ConfigData  *json.RawMessage `json:"config_data,omitempty"`
}

// --- Fronting links ---

type (
	frontingLinkView = dto.FrontingLinkView
)

var (
	frontingLinkToView        = dto.FrontingLinkToView
	frontingLinksToViews      = dto.FrontingLinksToViews
	resourceFrontingFromLinks = dto.ResourceFrontingFromLinks
)

// createFrontingLinkRequest is the JSON body for POST /admin/fronting (and the
// validation preflight POST /admin/fronting?dry_run=true). All three fields
// are required; the service applies validation rule-by-rule and returns the
// most specific failure.
type createFrontingLinkRequest struct {
	Source   string              `json:"source"`
	Target   string              `json:"target"`
	ScopeMap map[string][]string `json:"scope_map"`
}

// patchFrontingLinkRequest is the JSON body for
// PATCH /admin/fronting/{source}/{target}. Only ScopeMap is patchable —
// rewiring source/target requires delete + recreate.
//
// PATCH-dirty semantics: a nil pointer field is LEFT UNCHANGED. Sending the
// explicit `{}` empty object would be a wipe (rejected by domain validation
// since scope_map must contain at least one entry). This mirrors the
// security-by-default rule on input.ResourcePatch.
type patchFrontingLinkRequest struct {
	ScopeMap *map[string][]string `json:"scope_map,omitempty"`
}

// frontingLinkConflictResponse is the body of the 409 returned from
// DELETE /admin/resources/{id} when fronting links reference the resource
// and ?cascade=true was not supplied. Callers (UI, CLI) read `dependents`
// to render the cascade-confirmation modal.
type frontingLinkConflictResponse struct {
	Detail     string             `json:"detail"`
	Dependents []frontingLinkView `json:"dependents"`
}
