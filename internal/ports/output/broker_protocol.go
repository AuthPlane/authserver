package output

import (
	"context"
	"errors"

	"github.com/authplane/authserver/internal/domain/resource"
)

// BrokerProtocol is implemented by adapters that know how to speak a specific
// upstream protocol (OAuth, API key, service-account impersonation, …).
//
// One adapter per protocol. Adapters are registered into brokerproto.Registry
// at server startup; BrokerIssuer dispatches to adapters by looking up
// broker_providers.protocol against the registry.
//
// All credential bytes carried across the interface are plaintext at the port
// boundary. Encryption-at-rest is the storage layer's concern.
//
// See the architecture doc, the resource-unification design, and
// ADR-001 for why the registry lives in internal/brokerproto/ rather than
// alongside this interface.
type BrokerProtocol interface {
	// Name is the protocol identifier and matches broker_providers.protocol.
	Name() string

	// BuildConnectURL initiates the upstream connect flow. Returns the URL
	// the user's browser should be redirected to and the pending state to
	// persist. Returns ErrNoConnectStep for protocols that have no per-user
	// connect step (e.g. api_key, service_account) — the orchestration
	// layer treats that as a signal to skip the connect dance.
	//
	// callbackURL is the AS-side absolute URL the upstream provider redirects
	// the user back to (e.g. "https://auth.example.com/connect/github/callback").
	// The orchestration layer (ConnectService) is the single source of truth
	// for it; adapters know nothing about the AS's URL structure. OAuth
	// providers that require redirect_uri at the authorize endpoint and demand
	// it match at the token endpoint (Google, Microsoft, etc.) need this
	// passed through. Empty callbackURL omits redirect_uri end-to-end —
	// acceptable for upstreams that fall back to a single registered URI.
	BuildConnectURL(
		ctx context.Context,
		p *resource.BrokerProvider,
		r *resource.Resource,
		userID, returnURL, callbackURL string,
		requestedScopes []string,
	) (url string, pending *resource.ConnectPendingState, err error)

	// HandleCallback processes the upstream's redirect after user consent.
	// Returns the credential bytes to persist (the storage layer encrypts
	// them) and the upstream-format scopes the user actually granted.
	// Returns ErrNoConnectStep for protocols without a connect step.
	//
	// callbackURL must match the value passed to BuildConnectURL for the
	// same flow — RFC 6749 §4.1.3 requires the redirect_uri sent to the
	// token endpoint to equal the one sent to the authorize endpoint.
	HandleCallback(
		ctx context.Context,
		p *resource.BrokerProvider,
		r *resource.Resource,
		code, callbackURL string,
		pending *resource.ConnectPendingState,
	) (credential []byte, scopesGranted []string, err error)

	// Vend produces a fresh, upstream-narrowed access token from the
	// persisted credential bytes. Returns the access token, its lifetime
	// in seconds, and updatedCredential.
	//
	// updatedCredential semantics:
	//   - nil   → the upstream did not rotate the credential; do not write.
	//   - non-nil (including an empty []byte{}) → persist these exact
	//     bytes, replacing the previous credential, via the optimistic-lock
	//     UPDATE on broker_grants.
	Vend(
		ctx context.Context,
		p *resource.BrokerProvider,
		r *resource.Resource,
		credential []byte,
		requestedScopes []string,
	) (accessToken string, expiresIn int, updatedCredential []byte, err error)

	// Revoke informs the upstream that the credential is no longer valid
	// (RFC 7009 for OAuth, or the protocol equivalent). Best-effort; the
	// caller treats the local revocation as authoritative regardless of
	// the return value.
	Revoke(ctx context.Context, p *resource.BrokerProvider, credential []byte) error
}

// ErrNoConnectStep is returned by BuildConnectURL/HandleCallback for
// protocols that have no per-user upstream consent flow. Callers compare
// with errors.Is and skip the connect handoff when matched.
var ErrNoConnectStep = errors.New("protocol does not have a connect step")
