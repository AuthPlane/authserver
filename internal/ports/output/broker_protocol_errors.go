package output

import "errors"

// Sentinels returned by BrokerProtocol.Vend implementations to flag
// upstream-side failure conditions that require caller-specific handling.
//
// BrokerIssuer.Issue (internal/services/broker_issuer.go) maps each
// sentinel to a ConsentRequiredError with the appropriate Cause and
// DeniedReason — the wire response is uniform `consent_required` but the
// audit log and metrics carry the fine-grained reason for triage.
//
// Adapters that do not refresh tokens (apikey, serviceaccount today) are
// not required to emit these. The OAuth adapter (refresh-token aware)
// is the primary emitter as of.
var (
	// ErrUpstreamInvalidGrant indicates the upstream IdP rejected the
	// stored refresh_token (RFC 6749 §5.2 "invalid_grant"), typically
	// because the user revoked the app, rotated their password, or the
	// refresh_token expired. Recovery: user must reconnect via
	// /connect/<provider>.
	ErrUpstreamInvalidGrant = errors.New("upstream IdP rejected grant (invalid_grant)")

	// ErrUpstreamUnavailable indicates the upstream IdP is transiently
	// unreachable: network failure, DNS error, 5xx response, etc.
	// Recovery: retry. The user has nothing to do.
	ErrUpstreamUnavailable = errors.New("upstream IdP unavailable (network/5xx)")

	// ErrUpstreamScopeDowngrade indicates the upstream IdP returned a
	// `scope` field on the refresh response that is a strict subset of
	// what was previously granted, AND the requested fine scopes can no
	// longer be covered. Recovery: user must reconnect to re-grant the
	// missing scopes.
	ErrUpstreamScopeDowngrade = errors.New("upstream IdP downgraded granted scopes")
)
