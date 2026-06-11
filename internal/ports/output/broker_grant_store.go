package output

import (
	"context"

	"github.com/authplane/authserver/internal/domain/resource"
)

// BrokerGrantStore persists per-provider upstream credentials keyed on
// (user_id, broker_provider_id) — the v3→v4 fix that lets a single
// Google connection cover every Resource backed by the google-workspace
// provider. See the architecture doc / §5.4 and the data model /
// §3.2 / §6 Q3 / §6 Q4.
//
// CredentialData is opaque encrypted bytes. The store does not encrypt:
// the service layer ( BrokerIssuer) holds the DataEncryptor and
// passes already-encrypted bytes in. The adapter round-trips them
// byte-for-byte. This matches the existing connection.Connection pattern
// (internal/adapters/{sqlite,postgres}/connection.go::Update).
//
// Re-connect contract (, ): the connect-callback path uses
// Upsert, NOT Create — the UNIQUE (user_id, broker_provider_id)
// constraint covers active AND soft-deleted rows, so a Create after a
// Revoke would still 500 on conflict. Upsert atomically resurrects /
// rewrites the existing row. Create remains for callers that want
// strict-insert semantics (e.g. test seeds, admin replay paths).
type BrokerGrantStore interface {
	// Get returns the active grant for (user, brokerProvider), or
	// (nil, nil) when no row matches. Filter clause:
	// WHERE revoked_at IS NULL. Implements the data model Q3.
	Get(ctx context.Context, userID, brokerProviderID string) (*resource.BrokerGrant, error)

	// GetByID returns the grant with the given id (active or revoked),
	// or (nil, nil) when no row matches. Used by the admin revoke
	// path (the design audit-followup B17) to recover the
	// (user, broker_provider) pair pre-revoke so the audit detail can
	// carry it. Does NOT filter on revoked_at.
	GetByID(ctx context.Context, id string) (*resource.BrokerGrant, error)

	// Create inserts a new grant with version = 1. Caller is
	// responsible for revoking any previous active row for the same
	// (user, provider) before calling Create — see the re-connect
	// contract above. The connect-callback path uses Upsert
	// instead; Create is retained for strict-insert callers.
	Create(ctx context.Context, g *resource.BrokerGrant) error

	// Upsert atomically inserts a new grant OR updates the existing
	// (user_id, broker_provider_id) row. Resurrects soft-deleted rows
	// (clears revoked_at). Replaces credential_data, scopes_granted,
	// enc_backend; bumps version + updated_at. Used by the connect
	// callback to make re-connect a one-call-no-conflict path.
	//
	// On insert: the supplied g.ID is persisted, version starts at 1.
	// On update: the existing row's id is preserved (g.ID is ignored
	// for the matched-row case); version is bumped by 1; revoked_at is
	// cleared. The returned BrokerGrant carries the canonical
	// post-mutation state (id, version, created_at, updated_at,
	// revoked_at) so the caller can stamp audit / log lines on the
	// row as it actually exists in the table.
	Upsert(ctx context.Context, g *resource.BrokerGrant) (*resource.BrokerGrant, error)

	// UpdateWithVersion atomically updates credential_data,
	// scopes_granted, enc_backend and updated_at, increments version,
	// and matches on (id, version) — the optimistic-lock pattern from
	// the data model Q4. Returns domain.ErrBrokerGrantConflict when
	// 0 rows are affected (caller refetches and retries). Mirrors
	// connection.go::Update byte-for-byte.
	UpdateWithVersion(ctx context.Context, g *resource.BrokerGrant) error

	// Revoke sets revoked_at on the row with the given id. Idempotent:
	// returns nil if no row matches.
	Revoke(ctx context.Context, id string) error

	// ListForUser returns every grant for the user — both active and
	// revoked — ordered by created_at descending. Powers the
	// admin/user-self-service connections view.
	ListForUser(ctx context.Context, userID string) ([]*resource.BrokerGrant, error)
}
