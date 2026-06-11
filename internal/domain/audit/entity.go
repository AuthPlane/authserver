// Package audit contains the Event domain entity.
package audit

import "time"

// Action identifies what happened.
type Action string

const (
	// ActionTokenIssued records a token issuance event.
	ActionTokenIssued Action = "token.issued"
	// ActionTokenRefreshed records a token refresh event.
	ActionTokenRefreshed Action = "token.refreshed"
	// ActionTokenRevoked records a token revocation event.
	ActionTokenRevoked Action = "token.revoked"
	// ActionConsentGranted records a consent grant event.
	ActionConsentGranted Action = "consent.granted"
	// ActionConsentDenied records a consent denial event.
	ActionConsentDenied Action = "consent.denied"
	// ActionClientRegistered records a dynamic client registration event.
	ActionClientRegistered Action = "client.registered"
	// ActionClientSuspended records a client suspension event.
	ActionClientSuspended Action = "client.suspended"
	// ActionClientRevoked records a client revocation event.
	ActionClientRevoked Action = "client.revoked"
	// ActionAuthDenied records an authorization denial event.
	ActionAuthDenied Action = "auth.denied"
	// ActionAuthLockedOut records an account lockout event.
	ActionAuthLockedOut Action = "auth.locked_out"
	// ActionUserLogin records a successful user login event.
	ActionUserLogin Action = "user.login"
	// ActionUserLoginFailed records a failed user login event.
	ActionUserLoginFailed Action = "user.login_failed"
	// ActionUserCreated records a user creation event.
	ActionUserCreated Action = "user.created"
	// ActionUserDisabled records a user account disable event.
	ActionUserDisabled Action = "user.disabled"
	// ActionKeyRotated records a signing key rotation event.
	ActionKeyRotated Action = "key.rotated"
	// ActionFamilyRevoked records a refresh token family revocation event.
	ActionFamilyRevoked Action = "family.revoked"
	// ActionUserOIDCLogin records a successful OIDC-federated user login event.
	ActionUserOIDCLogin Action = "user.oidc_login"
	// ActionUserOIDCLoginFailed records a failed OIDC-federated user login event.
	ActionUserOIDCLoginFailed Action = "user.oidc_login_failed"
	// ActionTokenIntrospected records a token introspection event.
	ActionTokenIntrospected Action = "token.introspected"
	// ActionBrokerGrantCreated records a user-self-service upstream-connection
	// creation event (POST /connect/{provider}/callback persists a fresh
	// broker_grants row). Distinguishes user-driven flows from the admin-driven
	// revocation path tracked by ActionBrokerGrantRevokedAdmin.
	ActionBrokerGrantCreated Action = "broker_grant.created"
	// ActionBrokerGrantRevoked records a user-self-service upstream-connection
	// revocation event (DELETE /connections/{provider}). Distinct from the
	// admin-driven ActionBrokerGrantRevokedAdmin so forensic queries can split
	// "user pulled the plug" from "operator forced revoke".
	ActionBrokerGrantRevoked Action = "broker_grant.revoked"
	// ActionUpstreamTokenIssued records an upstream-broker token issuance event
	// (the AS hands an MCP a freshly vended upstream-format access token).
	ActionUpstreamTokenIssued Action = "upstream.token.issued" //nolint:gosec // not a credential, audit action name
	// ActionUpstreamTokenRefreshed records an automatic upstream refresh-token
	// exchange event (background credential rotation, no MCP-visible token).
	ActionUpstreamTokenRefreshed Action = "upstream.token.refreshed" //nolint:gosec // not a credential, audit action name

	// ActionClientCredentialsIssued records a client credentials token issuance event.
	ActionClientCredentialsIssued Action = "client_credentials.issued"
	// ActionClientCredentialsDenied records a client credentials token denial event.
	ActionClientCredentialsDenied Action = "client_credentials.denied"

	// ActionTokenExchanged records a token exchange grant issuance event (RFC 8693).
	ActionTokenExchanged Action = "token.exchanged"
	// ActionTokenExchangeDenied records a token exchange grant denial event (RFC 8693).
	ActionTokenExchangeDenied Action = "token.exchange_denied"

	// ActionJWTBearerIssued records a JWT Bearer grant issuance event (XAA).
	ActionJWTBearerIssued Action = "jwt_bearer.issued" //nolint:gosec // not a credential, audit action name
	// ActionJWTBearerDenied records a JWT Bearer grant denial event (XAA).
	ActionJWTBearerDenied Action = "jwt_bearer.denied" //nolint:gosec // not a credential, audit action name

	// ActionClientCreatedAdmin records a client creation via admin API.
	ActionClientCreatedAdmin Action = "client.created_admin"
	// ActionClientSecretRotated records a client secret rotation event.
	ActionClientSecretRotated Action = "client.secret_rotated"
	// ActionClientUpdated records a client update event.
	ActionClientUpdated Action = "client.updated"
	// ActionClientDeleted records a client deletion event.
	ActionClientDeleted Action = "client.deleted"
	// ActionUserUpdated records a user update event.
	ActionUserUpdated Action = "user.updated"
	// ActionUserDeleted records a user deletion event.
	ActionUserDeleted Action = "user.deleted"
	// ActionForceLogout records a forced user logout event.
	ActionForceLogout Action = "user.force_logout"
	// ActionDCRModeUpdated records a DCR mode update event.
	ActionDCRModeUpdated Action = "dcr.mode_updated"

	// ActionResourceCreated records a unified Resource creation via admin API
	//.
	ActionResourceCreated Action = "resource.created"
	// ActionResourcePatched records a unified Resource partial update via admin
	// API. Verb is patched (not updated) to match the PATCH HTTP verb and
	// signal partial vs. full replacement to operators reading the audit log.
	ActionResourcePatched Action = "resource.patched"
	// ActionResourceDeleted records a unified Resource deletion via admin API.
	ActionResourceDeleted Action = "resource.deleted"
	// ActionResourcePolicyExchangeAllowedClientAdded records adding a client
	// to a Resource's policy.exchange.allowed_client_ids via the per-field
	// admin endpoint. Distinct from ActionResourcePatched so the
	// audit log shows the operator's atomic intent rather than a generic
	// "policy field touched".
	ActionResourcePolicyExchangeAllowedClientAdded Action = "resource.policy.exchange.allowed_client.added"
	// ActionResourcePolicyExchangeAllowedClientRemoved records removing a
	// client from a Resource's policy.exchange.allowed_client_ids.
	ActionResourcePolicyExchangeAllowedClientRemoved Action = "resource.policy.exchange.allowed_client.removed"
	// ActionResourcePolicyConnectAllowedReturnURLAdded records adding a return
	// URL to a Resource's policy.connect.allowed_return_urls.
	ActionResourcePolicyConnectAllowedReturnURLAdded Action = "resource.policy.connect.allowed_return_url.added"
	// ActionResourcePolicyConnectAllowedReturnURLRemoved records removing a
	// return URL from a Resource's policy.connect.allowed_return_urls.
	ActionResourcePolicyConnectAllowedReturnURLRemoved Action = "resource.policy.connect.allowed_return_url.removed"
	// ActionResourcePolicyRuntimeClientAdded records adding a client to a
	// Resource's policy.runtime.client_ids via the per-field admin endpoint
	//. Pair with ActionResourcePolicyExchangeAllowedClientAdded for
	// the audit log: exchange = "may exchange INTO this resource", runtime
	// = "may act AS this resource".
	ActionResourcePolicyRuntimeClientAdded Action = "resource.policy.runtime.client.added"
	// ActionResourcePolicyRuntimeClientRemoved records removing a client from
	// a Resource's policy.runtime.client_ids.
	ActionResourcePolicyRuntimeClientRemoved Action = "resource.policy.runtime.client.removed"
	// ActionBrokerProviderCreated records a BrokerProvider creation via admin
	// API.
	ActionBrokerProviderCreated Action = "broker_provider.created"
	// ActionBrokerProviderPatched records a BrokerProvider partial update via
	// admin API.
	ActionBrokerProviderPatched Action = "broker_provider.patched"
	// ActionBrokerProviderDeleted records a BrokerProvider deletion via admin
	// API.
	ActionBrokerProviderDeleted Action = "broker_provider.deleted"

	// ActionConsentGrantRevokedAdmin records a consent_grants revocation issued
	// from the admin API. The _admin suffix distinguishes this
	// action from end-user revocations issued from the consent UI ( will
	// add the unsuffixed variant), keeping forensic queries clean.
	ActionConsentGrantRevokedAdmin Action = "consent_grant.revoked_admin"
	// ActionBrokerGrantRevokedAdmin records a broker_grants revocation issued
	// from the admin API.
	ActionBrokerGrantRevokedAdmin Action = "broker_grant.revoked_admin"
	// ActionIssuanceRevokedAdmin records a per-issuance revocation issued from
	// the admin API.
	ActionIssuanceRevokedAdmin Action = "issuance.revoked_admin"

	// ActionFrontingLinkCreated records a fronting_links row creation via
	// admin API. Verb shape mirrors ActionResourceCreated for
	// forensic-query consistency.
	ActionFrontingLinkCreated Action = "fronting_link.created"
	// ActionFrontingLinkPatched records a fronting_links scope_map update.
	ActionFrontingLinkPatched Action = "fronting_link.patched"
	// ActionFrontingLinkDeleted records a fronting_links row deletion.
	ActionFrontingLinkDeleted Action = "fronting_link.deleted"
)

// Event records a security-relevant action.
type Event struct {
	ID        string
	Action    Action
	ActorID   string // user ID, client ID, or "system"
	ClientID  string // OAuth client involved (may be empty)
	IP        string // source IP address
	Detail    string // human-readable or JSON detail
	TraceID   string // OTel trace ID for correlation (may be empty)
	CreatedAt time.Time
}

// NewEvent creates an Event with the current timestamp.
func NewEvent(action Action, actorID, clientID, ip, detail string) Event {
	return Event{
		Action:    action,
		ActorID:   actorID,
		ClientID:  clientID,
		IP:        ip,
		Detail:    detail,
		CreatedAt: time.Now().UTC(),
	}
}
