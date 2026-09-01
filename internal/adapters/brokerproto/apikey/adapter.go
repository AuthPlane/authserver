// Package apikey implements the BrokerProtocol port for upstream services
// where the user supplies a long-lived API key (e.g. OpenAI, Anthropic
// admin keys, vendor PATs). Per the resource-unification design /
// §5.3 and the architecture doc, there is no per-user authorization dance:
// the user pastes the key into the connect screen, the AS encrypts and
// stores it on broker_grants, and Vend returns it verbatim as the access
// token.
//
// BuildConnectURL and HandleCallback return output.ErrNoConnectStep so the
// orchestration layer ('s ConnectService rewrite) skips the OAuth
// redirect and routes the user to a paste-the-key form instead. Revoke is
// a no-op: there is no upstream API for invalidating a user-issued PAT
// from the AS side — the user must rotate at the upstream.
//
// HeaderName / HeaderPrefix in configData are descriptive metadata for
// downstream consumers (the resource server / MCP that ultimately calls
// the upstream); this adapter never sends HTTP itself.
package apikey

import (
	"context"

	"github.com/authplane/authserver/internal/domain/resource"
	"github.com/authplane/authserver/internal/ports/output"
)

// Adapter implements output.BrokerProtocol for the api_key protocol. One
// adapter instance handles every BrokerProvider whose Protocol is
// "api_key"; per-provider state lives in BrokerProvider.ConfigData and
// per-user state lives in broker_grants.credential_data.
type Adapter struct {
	secretResolver output.SecretResolver
}

// New builds an Adapter. The SecretResolver is accepted for interface
// symmetry (see package comment) but is unused by the current
// implementation.
func New(sr output.SecretResolver) *Adapter {
	return &Adapter{secretResolver: sr}
}

// Static interface assertion — fails to compile if the port surface drifts.
var _ output.BrokerProtocol = (*Adapter)(nil)

// Name returns the protocol identifier matching broker_providers.protocol
// values whose dispatch lands on this adapter.
func (a *Adapter) Name() string { return "api_key" }

// BuildConnectURL returns ErrNoConnectStep — the api_key protocol has no
// per-user upstream consent flow. The orchestration layer treats this as
// a signal to render a paste-the-key form instead of an OAuth redirect.
func (a *Adapter) BuildConnectURL(
	_ context.Context,
	_ *resource.BrokerProvider,
	_ *resource.Resource,
	_, _, _ string,
	_ []string,
) (string, *resource.ConnectPendingState, error) {
	return "", nil, output.ErrNoConnectStep
}

// HandleCallback returns ErrNoConnectStep — see BuildConnectURL.
func (a *Adapter) HandleCallback(
	_ context.Context,
	_ *resource.BrokerProvider,
	_ *resource.Resource,
	_, _ string,
	_ *resource.ConnectPendingState,
) ([]byte, []string, error) {
	return nil, nil, output.ErrNoConnectStep
}

// Vend returns the stored API key as the access token.
//
// expiresIn is 0 — API keys are long-lived from the AS's perspective; a
// zero lifetime tells BrokerIssuer there is no AS-known expiry and the
// resource server should rely on the upstream's own validity signal.
//
// updatedCredential is always nil — API keys do not rotate from the AS's
// side (the user rotates them at the upstream and re-pastes if needed).
//
// requestedScopes is intentionally ignored. API keys carry whatever
// permissions the user granted them at issuance time at the upstream;
// per-vend narrowing is not possible for this protocol because the
// upstream doesn't accept a `scope` parameter on its API calls. The
// requested ⊆ broker_grants.scopes_granted gate is enforced upstream of
// this adapter by BrokerIssuer.
func (a *Adapter) Vend(
	_ context.Context,
	_ *resource.BrokerProvider,
	_ *resource.Resource,
	credential []byte,
	_ []string,
) (string, int, []byte, error) {
	cred, err := parseCredential(credential)
	if err != nil {
		return "", 0, nil, err
	}
	return cred.APIKey, 0, nil, nil
}

// Revoke is a no-op — there is no upstream API for invalidating a
// user-issued PAT from the AS side. The local revocation (clearing
// broker_grants.revoked_at) is authoritative; the user must rotate at
// the upstream to actually invalidate the key.
func (a *Adapter) Revoke(_ context.Context, _ *resource.BrokerProvider, _ []byte) error {
	return nil
}
