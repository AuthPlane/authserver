// Package domain contains shared domain types and errors.
// This is the ONLY file for domain errors — NOT a separate package.
package domain

import (
	"errors"
	"fmt"
)

// Error is the interface all domain errors implement.
// Code returns the OAuth 2.1 error code for wire-level mapping.
type Error interface {
	error
	Code() string
}

// domainError is the concrete type backing every sentinel.
type domainError struct {
	code    string
	message string
}

func (e *domainError) Error() string { return e.message }

// Code returns the error code.
func (e *domainError) Code() string { return e.code }

// newError creates a domain error sentinel.
func newError(code, message string) *domainError {
	return &domainError{code: code, message: message}
}

// NewInvalidRequestError returns a domain error with code "invalid_request"
// and the given message. Handlers map invalid_request to HTTP 400.
func NewInvalidRequestError(message string) error {
	return &domainError{code: "invalid_request", message: message}
}

// NewConflictError returns a domain error with code CodeConflict and the
// given message. Handlers map it to HTTP 409. Use for "this would clash
// with an existing row" cases (e.g., duplicate slug on create) where
// none of the existing CodeConflict sentinels carry the right semantics.
func NewConflictError(message string) error {
	return &domainError{code: CodeConflict, message: message}
}

// --- Error Code Constants (used in domain errors and HTTP status mapping) ---

const (
	CodeNotFound     = "not_found"
	CodeConflict     = "conflict"
	CodeAccessDenied = "access_denied"
)

// --- Sentinel Errors ---

var (
	// ErrInvalidGrant — expired code, wrong verifier, wrong redirect_uri.
	ErrInvalidGrant = newError("invalid_grant", "the authorization grant is invalid, expired, or revoked")

	// ErrInvalidClient — unknown client_id, wrong secret.
	ErrInvalidClient = newError("invalid_client", "client authentication failed")

	// ErrClientNotFound — admin lookup miss for a client_id. Distinct from
	// ErrInvalidClient (OAuth-style "unknown or unauthenticated") because
	// admin handlers map this to HTTP 404 → apctl exit 4, while the OAuth
	// flow keeps "invalid_client" → HTTP 400/401 semantics. Storage adapters
	// still return ErrInvalidClient on not-found; AdminService translates at
	// the boundary so OAuth callers are unaffected.
	ErrClientNotFound = newError(CodeNotFound, "client not found")

	// ErrInvalidScope — scope not in client's allowed set or registry.
	ErrInvalidScope = newError("invalid_scope", "the requested scope is invalid or not allowed")

	// ErrCodeConsumed — auth code already used (replay).
	ErrCodeConsumed = newError("invalid_grant", "authorization code has already been used")

	// ErrFamilyRevoked — refresh token family revoked (theft detected).
	ErrFamilyRevoked = newError("invalid_grant", "token family revoked due to reuse detection")

	// ErrConsentRequired — user hasn't consented.
	ErrConsentRequired = newError("consent_required", "user consent is required")

	// ErrSessionExpired — auth session timed out.
	ErrSessionExpired = newError("invalid_grant", "authorization session has expired")

	// ErrInvalidRedirectURI — redirect_uri doesn't match registration.
	ErrInvalidRedirectURI = newError("invalid_request", "redirect_uri does not match client registration")

	// ErrInvalidPKCE — wrong verifier or missing challenge.
	ErrInvalidPKCE = newError("invalid_grant", "PKCE verification failed")

	// ErrClientSuspended — client suspended or revoked.
	ErrClientSuspended = newError("invalid_client", "client is suspended or revoked")

	// ErrRateLimited — too many requests.
	ErrRateLimited = newError("slow_down", "too many requests")

	// ErrUserNotFound — unknown user.
	ErrUserNotFound = newError(CodeNotFound, "user not found")

	// ErrInvalidCredentials — wrong password.
	ErrInvalidCredentials = newError("invalid_grant", "invalid credentials")

	// ErrUnsupportedGrantType — unsupported grant_type value.
	ErrUnsupportedGrantType = newError("unsupported_grant_type", "the grant type is not supported")

	// ErrCIMDFetchFailed — failed to fetch CIMD document.
	ErrCIMDFetchFailed = newError("invalid_client", "failed to fetch client metadata document")

	// ErrCIMDInvalid — CIMD document validation failed.
	ErrCIMDInvalid = newError("invalid_client", "client metadata document is invalid")

	// ErrOIDCAuthFailed — upstream OIDC authentication failed.
	ErrOIDCAuthFailed = newError(CodeAccessDenied, "OIDC authentication failed")

	// ErrRefreshTokenReused — refresh token was already consumed (concurrent or replay).
	ErrRefreshTokenReused = newError("invalid_grant", "refresh token has already been used")

	// ErrRegistrationDisabled — DCR is disabled (admin_only mode).
	ErrRegistrationDisabled = newError(CodeAccessDenied, "client registration is disabled")

	// ErrEncryptionFailed — encryption or decryption operation failed (bad input).
	ErrEncryptionFailed = newError("server_error", "encryption operation failed")

	// ErrDecryptionFailed — decryption failed (wrong key, wrong context, or tampered ciphertext).
	ErrDecryptionFailed = newError("server_error", "decryption failed")

	// ErrEncryptorUnavailable — encryption backend is temporarily unavailable.
	ErrEncryptorUnavailable = newError("server_error", "encryption backend unavailable")

	// ErrRotationConflict — concurrent key rotation detected (unique index violation).
	ErrRotationConflict = newError("server_error", "key rotation conflict — concurrent rotation in progress")

	// ErrKeyNotFound — signing key not found in store.
	ErrKeyNotFound = newError("server_error", "signing key not found")

	// ErrConnectionNotFound — Connect flow not found.
	ErrConnectionNotFound = newError(CodeNotFound, "Connect flow not found")

	// ErrConnectionConflict — concurrent update detected (optimistic lock violation).
	ErrConnectionConflict = newError(CodeConflict, "Connect flow version conflict — concurrent update")

	// ErrConnectionExists — Connect flow already exists for this owner+service.
	ErrConnectionExists = newError(CodeConflict, "Connect flow already exists for this owner and service")

	// ErrStateNotFound — vault state not found, expired, or already consumed.
	ErrStateNotFound = newError("invalid_request", "vault state not found, expired, or already consumed")

	// ErrServiceNotFound — connector service not found in registry.
	ErrServiceNotFound = newError("invalid_request", "connector service not found")

	// ErrInvalidState — invalid or tampered state token.
	ErrInvalidState = newError("invalid_request", "invalid or tampered state token")

	// ErrStateForeignUser — state token belongs to a different user.
	ErrStateForeignUser = newError(CodeAccessDenied, "state token belongs to a different user")

	// ErrInvalidReturnURL — return URL not in allowed list.
	ErrInvalidReturnURL = newError("invalid_request", "return URL not in allowed list")

	// ErrScopeNotGranted — requested scope not in granted scopes for Connect flow.
	ErrScopeNotGranted = newError("scope_not_granted", "requested scope not in granted scopes")

	// ErrVaultTokenExpired — vault access token is expired and cannot be refreshed.
	ErrVaultTokenExpired = newError("token_expired", "access token is expired and no refresh token is available")

	// --- Phase 3 errors ---

	// ErrUnauthorizedClient — client not permitted for the requested grant_type.
	ErrUnauthorizedClient = newError("unauthorized_client", "client is not authorized for this grant type")

	// ErrDPoPReplay — DPoP proof jti has already been used.
	ErrDPoPReplay = newError("invalid_dpop_proof", "DPoP proof jti has already been used")

	// ErrDPoPInvalidProof — DPoP proof JWT is invalid (bad alg, htm, htu, iat, or ath).
	ErrDPoPInvalidProof = newError("invalid_dpop_proof", "DPoP proof is invalid")

	// ErrDPoPNonceRequired — server-issued nonce is required but missing from proof.
	ErrDPoPNonceRequired = newError("use_dpop_nonce", "server nonce is required in DPoP proof")

	// ErrDPoPNonceMismatch — nonce in proof does not match server-issued nonce.
	ErrDPoPNonceMismatch = newError("use_dpop_nonce", "DPoP proof nonce does not match server-issued nonce")

	// ErrTokenExchangeNotAuthorized — requesting client not permitted to exchange this token.
	ErrTokenExchangeNotAuthorized = newError(CodeAccessDenied, "client is not authorized to exchange this token")

	// ErrTokenExchangeChainTooDeep — delegation chain exceeds configured max_chain_depth.
	ErrTokenExchangeChainTooDeep = newError(CodeAccessDenied, "delegation chain depth exceeds maximum allowed")

	// ErrInvalidTarget — requested resource target is not available (e.g., no Connect flow for this user/service).
	ErrInvalidTarget = newError("invalid_target", "the requested resource target is unavailable")

	// ErrAmbiguousBrokerResource — the provider has multiple Broker-backed
	// resources and the caller did not pin one with ?resource=. The picked
	// resource governs the return-URL allowlist and the upstream scope
	// catalog, so guessing silently risks issuing the wrong scopes
	// or allowing the wrong return URL. Caller must specify ?resource=<slug>.
	ErrAmbiguousBrokerResource = newError("invalid_request", "provider has multiple broker-backed resources — specify ?resource=<slug>")

	// ErrVaultVendActorNotAllowed — vault vending does not support delegation (actor_token).
	ErrVaultVendActorNotAllowed = newError("invalid_request", "vault vending does not support delegation — omit actor_token")

	// --- Admin UI / Connector Config errors ---

	// ErrConnectorConfigNotFound — connector configuration not found for this service.
	ErrConnectorConfigNotFound = newError(CodeNotFound, "connector configuration not found")

	// ErrConnectorConfigExists — connector configuration already exists for this service.
	ErrConnectorConfigExists = newError(CodeConflict, "connector configuration already exists for this service")

	// ErrConnectorHasConnections — cannot delete connector with active Connect flows.
	ErrConnectorHasConnections = newError(CodeConflict, "cannot delete connector with active connections")

	// ErrClientHasActiveTokens — cannot delete client with active tokens (use force=true).
	ErrClientHasActiveTokens = newError(CodeConflict, "client has active tokens — use force=true to revoke and delete")

	// ErrUserHasActiveTokens — cannot delete user with active tokens (use force=true).
	ErrUserHasActiveTokens = newError(CodeConflict, "user has active tokens — use force=true to revoke and delete")

	// --- XAA (Enterprise-Managed Authorization) errors ---

	// ErrIDPNotFound — trusted IdP not registered.
	ErrIDPNotFound = newError(CodeNotFound, "trusted identity provider not found")

	// ErrIDPDisabled — trusted IdP exists but is disabled.
	ErrIDPDisabled = newError("invalid_grant", "trusted identity provider is disabled")

	// ErrAssertionInvalid — ID-JAG validation failed (generic).
	ErrAssertionInvalid = newError("invalid_grant", "identity assertion is invalid")

	// ErrAssertionExpired — ID-JAG exp in past.
	ErrAssertionExpired = newError("invalid_grant", "identity assertion has expired")

	// ErrAssertionAudienceMismatch — ID-JAG aud doesn't match our issuer.
	ErrAssertionAudienceMismatch = newError("invalid_grant", "identity assertion audience does not match")

	// ErrAssertionIssuerUntrusted — ID-JAG iss not in trusted IdP registry.
	ErrAssertionIssuerUntrusted = newError("invalid_grant", "identity assertion issuer is not trusted")

	// ErrAssertionTypeMismatch — JWT typ != oauth-id-jag+jwt.
	ErrAssertionTypeMismatch = newError("invalid_grant", "identity assertion type header is invalid")

	// ErrAssertionClientMismatch — ID-JAG client_id doesn't match authenticated client.
	ErrAssertionClientMismatch = newError("invalid_client", "identity assertion client_id does not match authenticated client")

	// ErrAssertionPolicyDenied — policy check failed for assertion.
	ErrAssertionPolicyDenied = newError(CodeAccessDenied, "identity assertion denied by policy")

	// ErrAssertionReplay — ID-JAG jti already consumed.
	ErrAssertionReplay = newError("invalid_grant", "identity assertion has already been used")

	// ErrSubjectMappingNotFound — no subject mapping found in strict mode.
	ErrSubjectMappingNotFound = newError(CodeAccessDenied, "no subject mapping found for identity")

	// ErrXAAPolicyNotFound — XAA policy not found.
	ErrXAAPolicyNotFound = newError(CodeNotFound, "XAA policy not found")

	// ErrSubjectMappingDuplicate — subject mapping already exists for this IdP/subject pair.
	ErrSubjectMappingDuplicate = newError("invalid_request", "subject mapping already exists for this IdP and subject")

	// --- Concurrency / Optimistic Locking errors ---

	// ErrClientConflict — concurrent update detected on client (optimistic lock violation).
	ErrClientConflict = newError(CodeConflict, "client version conflict — concurrent update detected")

	// ErrUserConflict — concurrent update detected on user (optimistic lock violation).
	ErrUserConflict = newError(CodeConflict, "user version conflict — concurrent update detected")

	// ErrUserAlreadyExists — a user with the given email already exists.
	ErrUserAlreadyExists = newError(CodeConflict, "user with this email already exists")

	// --- Resource Server errors ---

	// ErrResourceServerNotFound — resource server not found.
	ErrResourceServerNotFound = newError(CodeNotFound, "resource server not found")

	// ErrResourceServerExists — resource server already exists for this URI.
	ErrResourceServerExists = newError(CodeConflict, "resource server already exists for this URI")

	// --- Cross-Client Allowlist errors ---

	// ErrAllowlistEntryNotFound — cross-client allowlist entry not found.
	ErrAllowlistEntryNotFound = newError(CodeNotFound, "cross-client allowlist entry not found")

	// ErrAllowlistEntryExists — cross-client allowlist entry already exists for this pair.
	ErrAllowlistEntryExists = newError(CodeConflict, "cross-client allowlist entry already exists for this pair")

	// --- Resource Unification errors (the architecture doc) ---
	// ErrConsentRequired (defined above) is reused as the §2.5
	// "consent required" sentinel; semantics already match.

	// ErrResourceNotFound — unified Resource not found by id, slug, or URI.
	ErrResourceNotFound = newError(CodeNotFound, "resource not found")

	// ErrAmbiguousResource — resource lookup matched more than one row.
	ErrAmbiguousResource = newError("invalid_request", "resource identifier is ambiguous")

	// ErrInvalidSlug — slug failed normalization or regex validation.
	ErrInvalidSlug = newError("invalid_request", "invalid slug")

	// ErrBrokerActorNotAllowed — broker resources reject delegation (actor_token).
	ErrBrokerActorNotAllowed = newError("invalid_request", "actor not allowed for broker resource")

	// ErrBrokerCredentialMissing — no broker_grants row for (user, broker_provider).
	ErrBrokerCredentialMissing = newError("invalid_grant", "broker credential missing")

	// ErrScopeNotInCatalog — requested scope is not declared on the resource.
	ErrScopeNotInCatalog = newError("invalid_scope", "scope not in resource catalog")

	// ErrScopeNotConsented — requested scope is not in the user's consent grant.
	ErrScopeNotConsented = newError("invalid_scope", "scope not consented")

	// ErrConsentResourceNotMint — the resource= parameter resolved to a Broker
	// resource. Per DESIGN_v4 §7 / the data model, consent_grants only
	// target Mint resources; upstream Broker resources are gated by operator
	// policy + broker_grants. Defense in depth — the resolver in /authorize
	// rejects this case before the user reaches /consent, but the consent
	// service re-checks.
	ErrConsentResourceNotMint = newError("invalid_request", "consent only valid for mint resources")

	// ErrAdapterNotRegistered — broker protocol has no registered BrokerProtocol adapter.
	ErrAdapterNotRegistered = newError("server_error", "broker protocol adapter not registered")

	// ErrResourceHasReferences — resource cannot be deleted because consent_grants
	// or issuances rows reference it (FK block per the data model).
	ErrResourceHasReferences = newError(CodeConflict, "resource has references and cannot be deleted")

	// ErrBrokerProviderHasReferences — broker provider cannot be deleted because
	// resources or broker_grants rows reference it (FK block per the data model).
	ErrBrokerProviderHasReferences = newError(CodeConflict, "broker provider has references and cannot be deleted")

	// ErrBrokerGrantConflict — concurrent update detected on a broker_grants
	// row (optimistic-lock violation on the (id, version) WHERE clause of
	// BrokerGrantStore.UpdateWithVersion). Caller refetches and retries per
	// the data model Q4.
	ErrBrokerGrantConflict = newError(CodeConflict, "broker grant version conflict — concurrent update detected")

	// ErrPendingStateNotFound — connect_pending_states row not found, expired,
	// or already consumed. Returned by ConnectPendingStateStore.Consume when the
	// atomic DELETE … RETURNING affects zero rows. Single-use semantics: the
	// second consumer of the same id always sees this sentinel.
	ErrPendingStateNotFound = newError("invalid_request", "connect pending state not found, expired, or already consumed")

	// ErrIssuanceNotFound — issuance row not found by id. Returned by
	// IssuanceStore.GetByID when no row matches the supplied id.
	ErrIssuanceNotFound = newError(CodeNotFound, "issuance not found")

	// --- Fronting links ---

	// ErrFrontingLinkNotFound — fronting_links row not found by
	// (source_slug, target_slug). Returned by FrontingLinkStore.Get and
	// downstream service methods when the lookup misses.
	ErrFrontingLinkNotFound = newError(CodeNotFound, "fronting link not found")

	// ErrFrontingLinkExists — a fronting_links row with this (source, target)
	// pair already exists. The pair is the primary key; one link per
	// direction is allowed.
	ErrFrontingLinkExists = newError(CodeConflict, "fronting link already exists for this source and target")

	// ErrFrontingLinkCycle — accepting the proposed link would close a cycle
	// in the fronting graph. Cycles are rejected at write time so the runtime
	// dispatch path (Inc N+1) never has to break a tie at vend time.
	ErrFrontingLinkCycle = newError("invalid_request", "fronting link would form a cycle")

	// ErrResourceHasFrontingLinks — the Resource cannot be deleted because
	// fronting_links rows reference it (as source or target). The admin must
	// pass ?cascade=true after reviewing the dependent list.
	ErrResourceHasFrontingLinks = newError(CodeConflict, "resource has fronting links and cannot be deleted without cascade")
)

// FeatureDisabledError is returned by runtime endpoints whose backing
// service was intentionally not constructed (operator opted out by leaving
// the feature flag false or required config blank). The wire response sets
// error=service_unavailable and names the config key the operator must
// flip to re-enable the feature, so an integrator never has to chase an
// empty payload back through the code.
//
// Usage: handlers detect svc == nil at request time and return this typed
// error instead of an empty-200 or generic 503. Boot-time *misconfig*
// (partial config, unknown values) fails the AS at startup and never
// reaches runtime; what's left at runtime is genuine operator opt-out.
type FeatureDisabledError struct {
	// Feature names the disabled subsystem (e.g. "connect",
	// "token_exchange"). Matches the FeatureCheck.Name reported in the
	// startup self-check block.
	Feature string
	// ConfigKey is the dotted YAML key (or env-var equivalent) the
	// operator must set to re-enable the feature. Required.
	ConfigKey string
}

// Error implements the error interface. The message is the same string
// emitted on the wire so logs and clients see identical phrasing.
func (e *FeatureDisabledError) Error() string {
	return "feature " + e.Feature + " is disabled (set " + e.ConfigKey + " to enable)"
}

// Code returns the OAuth error code for wire-level mapping. RFC 6749 has
// no first-class "feature disabled" code; service_unavailable is the
// closest semantic match (the endpoint exists but the backing capability
// is currently off).
func (e *FeatureDisabledError) Code() string { return "service_unavailable" }

// NewFeatureDisabledError constructs a FeatureDisabledError. Both fields
// are required; an empty Feature or ConfigKey turns the wire response
// into an unhelpful blob, so callers should always pass both.
func NewFeatureDisabledError(feature, configKey string) *FeatureDisabledError {
	return &FeatureDisabledError{Feature: feature, ConfigKey: configKey}
}

// FrontingLinkMissingError is returned by dispatchBroker when the subject
// token's audience resolves to a Mint Resource different from the target
// Broker but no fronting_links row connects them. The non-fronted
// Mint→Broker dispatch path is not a documented topology — it only
// happens when the operator's fronting setup is broken (forgot the
// fronting_links row, typo'd a slug, or followed a stale pre-
// example).
//
// this fail-fast error replaces the previous fall-through into
// the legacy bound-B agent-attestation gate, whose
// "consent_required: agent_attestation_required" response pointed
// operators at the wrong fix (populate consent_grants on the actor MCP)
// instead of the right fix (declare a fronting link). The bound-B path
// remains as defense-in-depth for the case where the subject token's
// `aud` doesn't resolve to a Mint Resource at all (legacy tokens, direct
// broker exchanges that didn't go through a gateway).
type FrontingLinkMissingError struct {
	// SourceSlug is the Mint Resource the subject token's `aud` resolved
	// to (the gateway). Required.
	SourceSlug string
	// TargetSlug is the Broker Resource the agent is trying to vend
	// against. Required.
	TargetSlug string
}

// Error implements the error interface. The message names both slugs
// and the canonical topology doc so an operator reading the wire
// response can resolve it without grepping the codebase.
func (e *FrontingLinkMissingError) Error() string {
	return fmt.Sprintf(
		"no fronting link declared from %q to %q — declare fronting_links(%s, %s) — see docs/how-to/topologies/mcp-gateway-broker.md",
		e.SourceSlug, e.TargetSlug, e.SourceSlug, e.TargetSlug,
	)
}

// Code returns the OAuth error code for wire-level mapping. The
// code is `invalid_request` rather than `consent_required` — the
// failure is operator misconfiguration, not user-facing consent.
func (e *FrontingLinkMissingError) Code() string { return "invalid_request" }

// CauseConsentMissing is the ConsentRequiredError.Cause value used when no
// consent grant exists for the (user, agent, resource) tuple. The empty
// string is treated as CauseConsentMissing for backwards compatibility with
// handlers previously; new call sites set this explicitly.
const CauseConsentMissing = "consent_missing"

// CauseScopeInsufficient is the ConsentRequiredError.Cause value used when a
// consent grant exists but does not cover one or more of the requested
// scopes. The wire response sets error_description to a fixed user-safe
// string; ConsentRequiredError.MissingScopes carries the diagnostic detail
// server-side only (not on the wire — probe-oracle reduction).
const CauseScopeInsufficient = "scope_insufficient"

// ConsentRequiredError is a structured error returned by the token exchange
// service when a Broker-backed resource cannot be vended because the user has
// not consented (or is missing an agent-attestation grant) for the upstream.
// The absolute consent URL is built by the HTTP layer
// (api/public/connection.ConsentURL) at response-serialization time so the
// service layer stays free of transport concerns. Clients (e.g. the Go SDK)
// read the resulting consent_url from the wire response (MCP SEP-1036).
//
// Unlike the sentinel ErrConsentRequired (used by the /authorize flow), this
// is a value type so the slug can vary per call.
//
// ProviderSlug and ResourceSlug are populated by the unified dispatch path
// (: Mint + Broker). The handler reads them to render a connect_url
// that names the upstream provider and the originating resource separately.
//
// Service is retained as a deprecated fallback for downstream consumers
// using errors.As; it should hold the same value as one of the typed slugs
// so older callers do not break. New callers populate the typed fields.
//
// Cause + MissingScopes are sub-discriminators for the wire
// response. Cause is one of CauseConsentMissing / CauseScopeInsufficient;
// empty is treated as CauseConsentMissing for legacy callers. MissingScopes
// is server-side-only (logged for forensics, NOT on the wire) — clients
// re-discover via PRM and the user's consent surface.
type ConsentRequiredError struct {
	// Deprecated: use ResourceSlug or ProviderSlug. Populated for backward
	// compatibility with previously callers; will be removed in a follow-up.
	Service      string
	ProviderSlug string
	ResourceSlug string
	// Cause is a sub-discriminator: CauseConsentMissing (no grant row) or
	// CauseScopeInsufficient (grant exists, requested scopes not all
	// covered). Empty for legacy call sites; the handler treats empty as
	// CauseConsentMissing on the wire.
	Cause string
	// MissingScopes lists the requested scopes not covered by the relevant
	// grant when Cause == CauseScopeInsufficient. NOT serialized on the
	// wire; logged server-side only.
	MissingScopes []string

	// DeniedReason is a fine-grained sub-discriminator that explains *why*
	// a denial was emitted, beyond the broader Cause. Surfaced in audit
	// detail and as a `denied_reason` metric label. NOT serialized on
	// the wire — clients see only `consent_required` + `consent_url`.
	// Used for triage: distinguishes "user never connected" from "refresh
	// token revoked" from "upstream IdP 5xx" — all of which collapse to
	// `Cause = CauseConsentMissing` on the wire.
	// Optional. Empty string means "no fine-grained reason captured".
	DeniedReason string
}

// Error implements the error interface. It prefers ResourceSlug, then
// ProviderSlug, then the deprecated Service field.
func (e *ConsentRequiredError) Error() string {
	target := e.ResourceSlug
	if target == "" {
		target = e.ProviderSlug
	}
	if target == "" {
		target = e.Service
	}
	return "Authorize access to " + target
}

// Code returns the OAuth error code for wire-level mapping.
func (e *ConsentRequiredError) Code() string { return "consent_required" }

// IsError reports whether err (or any error in its chain) is an Error.
func IsError(err error) bool {
	var de Error
	return errors.As(err, &de)
}

// ErrorCode extracts the OAuth error code from err if it is an Error.
// Returns "server_error" for non-domain errors.
func ErrorCode(err error) string {
	var de Error
	if errors.As(err, &de) {
		return de.Code()
	}
	return "server_error"
}
