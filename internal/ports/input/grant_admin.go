package input

import (
	"context"

	"github.com/authplane/authserver/internal/domain/resource"
)

// GrantAdminPort exposes administrative reads + revocations over both
// consent_grants (per-MCP user→Agent authorization) and broker_grants
// (per-provider upstream credential). the design §6 / the data model / §2.4.
//
// One ListForUser returns BOTH shapes in a single response so the operator
// surface ("what has user X authorized") doesn't issue two round trips.
// Revocation is split into RevokeConsent / RevokeBroker because the cascade
// semantics differ: consent revocation triggers IssuanceStore.RevokeFamily
// ; broker revocation does not (already-vended
// upstream tokens are not AS-revocable).
type GrantAdminPort interface {
	// ListForUser returns every grant — consent + broker, active and
	// revoked — for the given user. The two halves are returned in a
	// single UserGrants struct so the wire response can disambiguate
	// the shapes. History semantics match the underlying stores
	// (ConsentGrantStore.ListForUser / BrokerGrantStore.ListForUser).
	ListForUser(ctx context.Context, userID string) (UserGrants, error)

	// RevokeConsent soft-deletes the consent_grants row by id and
	// cascades onto matching live Mint issuances via
	// IssuanceStore.RevokeFamily(user, client, resource). If the cascade
	// itself fails after the grant revocation succeeds, the call still
	// returns nil — grant revocation is the load-bearing security
	// action; the audit detail records revoked_issuances=0 so alerting
	// can fire on the partial-success case.
	RevokeConsent(ctx context.Context, id string) error

	// RevokeBroker soft-deletes the broker_grants row by id. There is no
	// issuance cascade — already-vended upstream tokens are not
	// AS-revocable.
	RevokeBroker(ctx context.Context, id string) error
}

// UserGrants packages both grant shapes for a user. Both slices are
// ordered by created_at DESC and may include revoked rows (revoked_at
// non-nil); the admin surface displays the full audit history.
type UserGrants struct {
	Consent []*resource.ConsentGrant
	Broker  []*resource.BrokerGrant
}
