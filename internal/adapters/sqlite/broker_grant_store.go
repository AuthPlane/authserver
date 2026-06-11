package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"

	"github.com/authplane/authserver/internal/domain"
	"github.com/authplane/authserver/internal/domain/resource"
	"github.com/authplane/authserver/internal/observability"
	"github.com/authplane/authserver/internal/ports/output"
)

// BrokerGrantStore implements output.BrokerGrantStore using SQLite
// against the broker_grants table. Schema lives in
// migrations/sqlite/001_initial.up.sql lines 470-488.
//
// CredentialData is opaque BLOB bytes — see the port comment.
type BrokerGrantStore struct {
	db      *sql.DB
	logger  *slog.Logger
	tracer  trace.Tracer
	metrics *observability.Metrics
}

var _ output.BrokerGrantStore = (*BrokerGrantStore)(nil)

const brokerGrantColumns = `id, user_id, broker_provider_id, credential_data, scopes_granted, enc_backend, version, created_at, updated_at, revoked_at`

// Get returns the active grant for (user, broker_provider) or
// (nil, nil) when no row matches.
func (s *BrokerGrantStore) Get(ctx context.Context, userID, brokerProviderID string) (*resource.BrokerGrant, error) {
	ctx, span := s.tracer.Start(ctx, "SQLite.BrokerGrantGet")
	defer span.End()
	start := time.Now()

	row := s.db.QueryRowContext(ctx,
		`SELECT `+brokerGrantColumns+`
		   FROM broker_grants
		  WHERE user_id = ? AND broker_provider_id = ?
		    AND revoked_at IS NULL`,
		userID, brokerProviderID,
	)
	g, err := scanBrokerGrant(row)
	s.recordDB(ctx, "broker_grant_get", start)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return nil, fmt.Errorf("get broker grant: %w", err)
	}
	return g, nil
}

// GetByID returns the grant with the given id (active or revoked) or
// (nil, nil) when no row matches. Used by the admin revoke path
// (the design audit-followup B17) to recover the
// (user, broker_provider) pair pre-revoke for audit-detail enrichment.
func (s *BrokerGrantStore) GetByID(ctx context.Context, id string) (*resource.BrokerGrant, error) {
	ctx, span := s.tracer.Start(ctx, "SQLite.BrokerGrantGetByID")
	defer span.End()
	start := time.Now()

	row := s.db.QueryRowContext(ctx,
		`SELECT `+brokerGrantColumns+`
		   FROM broker_grants
		  WHERE id = ?`,
		id,
	)
	g, err := scanBrokerGrant(row)
	s.recordDB(ctx, "broker_grant_get_by_id", start)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return nil, fmt.Errorf("get broker grant by id: %w", err)
	}
	return g, nil
}

// Create inserts a new grant with version = 1. Caller must Revoke any
// previous active row for the same (user, provider) before calling
// Create — see port comment for the re-connect contract.
func (s *BrokerGrantStore) Create(ctx context.Context, g *resource.BrokerGrant) error {
	ctx, span := s.tracer.Start(ctx, "SQLite.BrokerGrantCreate")
	defer span.End()
	start := time.Now()

	scopes := marshalBrokerGrantScopes(g.ScopesGranted)
	g.Version = 1
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO broker_grants (`+brokerGrantColumns+`)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		g.ID, g.UserID, g.BrokerProviderID,
		g.CredentialData, scopes, g.EncBackend, g.Version,
		formatTime(g.CreatedAt), formatTime(g.UpdatedAt),
		formatNullableTime(g.RevokedAt),
	)
	s.recordDB(ctx, "broker_grant_create", start)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return fmt.Errorf("create broker grant: %w", err)
	}
	return nil
}

// Upsert atomically inserts a new grant OR updates the existing
// (user_id, broker_provider_id) row. On conflict it resurrects soft-
// deleted rows (clears revoked_at), replaces credential_data,
// scopes_granted, enc_backend, bumps version by 1, and refreshes
// updated_at. Preserves the existing row's id (the supplied g.ID is
// only persisted on insert). Returns the canonical post-mutation row
// so the caller can audit/log the actual id+version..
func (s *BrokerGrantStore) Upsert(ctx context.Context, g *resource.BrokerGrant) (*resource.BrokerGrant, error) {
	ctx, span := s.tracer.Start(ctx, "SQLite.BrokerGrantUpsert")
	defer span.End()
	start := time.Now()

	scopes := marshalBrokerGrantScopes(g.ScopesGranted)
	now := time.Now().UTC()
	createdAt := g.CreatedAt
	if createdAt.IsZero() {
		createdAt = now
	}

	// ON CONFLICT keys on the UNIQUE (user_id, broker_provider_id)
	// index. version=1 on insert; on update version is read-modified
	// from the existing row (broker_grants.version + 1) so the
	// optimistic-lock counter keeps moving — readers downstream can
	// still detect a concurrent rotation. revoked_at is cleared so a
	// previously-soft-deleted row resurrects with the new credential.
	row := s.db.QueryRowContext(ctx,
		`INSERT INTO broker_grants (`+brokerGrantColumns+`)
		 VALUES (?, ?, ?, ?, ?, ?, 1, ?, ?, NULL)
		 ON CONFLICT(user_id, broker_provider_id) DO UPDATE SET
		    credential_data = excluded.credential_data,
		    scopes_granted  = excluded.scopes_granted,
		    enc_backend     = excluded.enc_backend,
		    version         = broker_grants.version + 1,
		    updated_at      = excluded.updated_at,
		    revoked_at      = NULL
		 RETURNING `+brokerGrantColumns,
		g.ID, g.UserID, g.BrokerProviderID,
		g.CredentialData, scopes, g.EncBackend,
		formatTime(createdAt), formatTime(now),
	)

	out, err := scanBrokerGrant(row)
	s.recordDB(ctx, "broker_grant_upsert", start)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return nil, fmt.Errorf("upsert broker grant: %w", err)
	}
	return out, nil
}

// UpdateWithVersion atomically updates credential_data, scopes_granted,
// enc_backend, and updated_at; increments version; matches on
// (id, version). Returns domain.ErrBrokerGrantConflict on stale
// version (0 rows affected). the data model Q4.
func (s *BrokerGrantStore) UpdateWithVersion(ctx context.Context, g *resource.BrokerGrant) error {
	ctx, span := s.tracer.Start(ctx, "SQLite.BrokerGrantUpdateWithVersion")
	defer span.End()
	start := time.Now()

	scopes := marshalBrokerGrantScopes(g.ScopesGranted)
	res, err := s.db.ExecContext(ctx,
		`UPDATE broker_grants
		    SET credential_data = ?, scopes_granted = ?, enc_backend = ?,
		        version = version + 1, updated_at = ?
		  WHERE id = ? AND version = ?`,
		g.CredentialData, scopes, g.EncBackend,
		formatTime(time.Now().UTC()),
		g.ID, g.Version,
	)
	s.recordDB(ctx, "broker_grant_update_with_version", start)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return fmt.Errorf("update broker grant: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("rows affected: %w", err)
	}
	if n == 0 {
		return domain.ErrBrokerGrantConflict
	}
	return nil
}

// Revoke sets revoked_at on the row with the given id. Idempotent.
func (s *BrokerGrantStore) Revoke(ctx context.Context, id string) error {
	ctx, span := s.tracer.Start(ctx, "SQLite.BrokerGrantRevoke")
	defer span.End()
	start := time.Now()

	now := formatTime(time.Now().UTC())
	_, err := s.db.ExecContext(ctx,
		`UPDATE broker_grants
		    SET revoked_at = ?, updated_at = ?
		  WHERE id = ?`,
		now, now, id,
	)
	s.recordDB(ctx, "broker_grant_revoke", start)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return fmt.Errorf("revoke broker grant: %w", err)
	}
	return nil
}

// ListForUser returns all grants for the user (active + revoked),
// newest first.
func (s *BrokerGrantStore) ListForUser(ctx context.Context, userID string) ([]*resource.BrokerGrant, error) {
	ctx, span := s.tracer.Start(ctx, "SQLite.BrokerGrantListForUser")
	defer span.End()
	start := time.Now()

	rows, err := s.db.QueryContext(ctx,
		`SELECT `+brokerGrantColumns+`
		   FROM broker_grants
		  WHERE user_id = ?
		  ORDER BY created_at DESC`,
		userID,
	)
	s.recordDB(ctx, "broker_grant_list_for_user", start)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return nil, fmt.Errorf("list broker grants: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var out []*resource.BrokerGrant
	for rows.Next() {
		g, err := scanBrokerGrant(rows)
		if err != nil {
			span.RecordError(err)
			span.SetStatus(codes.Error, err.Error())
			return nil, fmt.Errorf("scan broker grant: %w", err)
		}
		out = append(out, g)
	}
	if err := rows.Err(); err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return nil, fmt.Errorf("iterate broker grants: %w", err)
	}
	return out, nil
}

func (s *BrokerGrantStore) recordDB(ctx context.Context, op string, start time.Time) {
	if s.metrics != nil && s.metrics.DBOperationDuration != nil {
		s.metrics.DBOperationDuration.Record(ctx, time.Since(start).Seconds(), dbAttrs(op))
	}
}

// scanBrokerGrant scans one broker_grants row into a domain
// BrokerGrant. credential_data round-trips byte-for-byte as opaque
// BLOB.
func scanBrokerGrant(row interface{ Scan(...any) error }) (*resource.BrokerGrant, error) {
	var (
		g          resource.BrokerGrant
		scopesStr  string
		createdAt  string
		updatedAt  string
		revokedRaw sql.NullString
	)
	if err := row.Scan(
		&g.ID, &g.UserID, &g.BrokerProviderID,
		&g.CredentialData, &scopesStr, &g.EncBackend, &g.Version,
		&createdAt, &updatedAt, &revokedRaw,
	); err != nil {
		return nil, err
	}

	scopes, err := unmarshalBrokerGrantScopes(scopesStr)
	if err != nil {
		return nil, fmt.Errorf("parse scopes_granted: %w", err)
	}
	g.ScopesGranted = scopes

	g.CreatedAt, err = scanTime(createdAt)
	if err != nil {
		return nil, fmt.Errorf("parse created_at: %w", err)
	}
	g.UpdatedAt, err = scanTime(updatedAt)
	if err != nil {
		return nil, fmt.Errorf("parse updated_at: %w", err)
	}
	g.RevokedAt, err = scanNullableTime(revokedRaw)
	if err != nil {
		return nil, fmt.Errorf("parse revoked_at: %w", err)
	}
	return &g, nil
}

// --- Private JSON helpers ---
//
// broker_grants.scopes_granted is a JSON-array string per
// the data model Helpers stay private to this file.

func marshalBrokerGrantScopes(ss []string) string {
	// Reuse the shared encoder for symmetry with the consent-grant
	// store; both columns are JSON-array strings on sqlite.
	return marshalConsentGrantScopes(ss)
}

func unmarshalBrokerGrantScopes(s string) ([]string, error) {
	return unmarshalConsentGrantScopes(s)
}
