package postgres

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"

	"github.com/authplane/authserver/internal/domain"
	"github.com/authplane/authserver/internal/domain/resource"
	"github.com/authplane/authserver/internal/observability"
	"github.com/authplane/authserver/internal/ports/output"
)

// BrokerGrantStore implements output.BrokerGrantStore using PostgreSQL
// against the broker_grants table. Schema lives in
// migrations/postgres/001_initial.up.sql lines 537-555.
//
// CredentialData is opaque BYTEA bytes — see the port comment.
type BrokerGrantStore struct {
	pool    *pgxpool.Pool
	logger  *slog.Logger
	tracer  trace.Tracer
	metrics *observability.Metrics
}

var _ output.BrokerGrantStore = (*BrokerGrantStore)(nil)

const brokerGrantColumns = `id, user_id, broker_provider_id, credential_data, scopes_granted, enc_backend, version, created_at, updated_at, revoked_at`

// Get returns the active grant for (user, broker_provider) or
// (nil, nil) when no row matches.
func (s *BrokerGrantStore) Get(ctx context.Context, userID, brokerProviderID string) (*resource.BrokerGrant, error) {
	ctx, span := s.tracer.Start(ctx, "Postgres.BrokerGrantGet")
	defer span.End()
	start := time.Now()

	row := s.pool.QueryRow(ctx,
		`SELECT `+brokerGrantColumns+`
		   FROM broker_grants
		  WHERE user_id = $1 AND broker_provider_id = $2
		    AND revoked_at IS NULL`,
		userID, brokerProviderID,
	)
	g, err := scanBrokerGrant(row)
	s.recordDB(ctx, "broker_grant_get", start)
	if isNoRows(err) {
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
// (the design audit-followup B17) for audit-detail enrichment.
func (s *BrokerGrantStore) GetByID(ctx context.Context, id string) (*resource.BrokerGrant, error) {
	ctx, span := s.tracer.Start(ctx, "Postgres.BrokerGrantGetByID")
	defer span.End()
	start := time.Now()

	row := s.pool.QueryRow(ctx,
		`SELECT `+brokerGrantColumns+`
		   FROM broker_grants
		  WHERE id = $1`,
		id,
	)
	g, err := scanBrokerGrant(row)
	s.recordDB(ctx, "broker_grant_get_by_id", start)
	if isNoRows(err) {
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
	ctx, span := s.tracer.Start(ctx, "Postgres.BrokerGrantCreate")
	defer span.End()
	start := time.Now()

	g.Version = 1
	_, err := s.pool.Exec(ctx,
		`INSERT INTO broker_grants (`+brokerGrantColumns+`)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`,
		g.ID, g.UserID, g.BrokerProviderID,
		g.CredentialData, consentGrantScopesArg(g.ScopesGranted),
		g.EncBackend, g.Version,
		toUTC(g.CreatedAt), toUTC(g.UpdatedAt), g.RevokedAt,
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
	ctx, span := s.tracer.Start(ctx, "Postgres.BrokerGrantUpsert")
	defer span.End()
	start := time.Now()

	createdAt := g.CreatedAt
	if createdAt.IsZero() {
		createdAt = time.Now().UTC()
	}

	// ON CONFLICT keys on the UNIQUE (user_id, broker_provider_id)
	// index. version=1 on insert; on update version is read-modified
	// from the existing row (broker_grants.version + 1) so the
	// optimistic-lock counter keeps moving — readers downstream can
	// still detect a concurrent rotation. revoked_at is cleared so a
	// previously-soft-deleted row resurrects with the new credential.
	row := s.pool.QueryRow(ctx,
		`INSERT INTO broker_grants (`+brokerGrantColumns+`)
		 VALUES ($1, $2, $3, $4, $5, $6, 1, $7, NOW(), NULL)
		 ON CONFLICT (user_id, broker_provider_id) DO UPDATE SET
		    credential_data = EXCLUDED.credential_data,
		    scopes_granted  = EXCLUDED.scopes_granted,
		    enc_backend     = EXCLUDED.enc_backend,
		    version         = broker_grants.version + 1,
		    updated_at      = NOW(),
		    revoked_at      = NULL
		 RETURNING `+brokerGrantColumns,
		g.ID, g.UserID, g.BrokerProviderID,
		g.CredentialData, consentGrantScopesArg(g.ScopesGranted),
		g.EncBackend, toUTC(createdAt),
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

// UpdateWithVersion atomically updates credential_data,
// scopes_granted, enc_backend, and updated_at; increments version;
// matches on (id, version). Returns domain.ErrBrokerGrantConflict on
// stale version (0 rows affected). the data model Q4.
func (s *BrokerGrantStore) UpdateWithVersion(ctx context.Context, g *resource.BrokerGrant) error {
	ctx, span := s.tracer.Start(ctx, "Postgres.BrokerGrantUpdateWithVersion")
	defer span.End()
	start := time.Now()

	tag, err := s.pool.Exec(ctx,
		`UPDATE broker_grants
		    SET credential_data = $1, scopes_granted = $2, enc_backend = $3,
		        version = version + 1, updated_at = NOW()
		  WHERE id = $4 AND version = $5`,
		g.CredentialData, consentGrantScopesArg(g.ScopesGranted),
		g.EncBackend, g.ID, g.Version,
	)
	s.recordDB(ctx, "broker_grant_update_with_version", start)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return fmt.Errorf("update broker grant: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return domain.ErrBrokerGrantConflict
	}
	return nil
}

// Revoke sets revoked_at on the row with the given id. Idempotent.
func (s *BrokerGrantStore) Revoke(ctx context.Context, id string) error {
	ctx, span := s.tracer.Start(ctx, "Postgres.BrokerGrantRevoke")
	defer span.End()
	start := time.Now()

	_, err := s.pool.Exec(ctx,
		`UPDATE broker_grants
		    SET revoked_at = NOW(), updated_at = NOW()
		  WHERE id = $1`,
		id,
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
	ctx, span := s.tracer.Start(ctx, "Postgres.BrokerGrantListForUser")
	defer span.End()
	start := time.Now()

	rows, err := s.pool.Query(ctx,
		`SELECT `+brokerGrantColumns+`
		   FROM broker_grants
		  WHERE user_id = $1
		  ORDER BY created_at DESC`,
		userID,
	)
	s.recordDB(ctx, "broker_grant_list_for_user", start)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return nil, fmt.Errorf("list broker grants: %w", err)
	}
	defer rows.Close()

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
// BYTEA.
func scanBrokerGrant(row interface{ Scan(...any) error }) (*resource.BrokerGrant, error) {
	var (
		g         resource.BrokerGrant
		scopes    []string
		createdAt time.Time
		updatedAt time.Time
		revokedAt *time.Time
	)
	if err := row.Scan(
		&g.ID, &g.UserID, &g.BrokerProviderID,
		&g.CredentialData, &scopes, &g.EncBackend, &g.Version,
		&createdAt, &updatedAt, &revokedAt,
	); err != nil {
		return nil, err
	}
	if len(scopes) == 0 {
		g.ScopesGranted = nil
	} else {
		g.ScopesGranted = scopes
	}
	g.CreatedAt = toUTC(createdAt)
	g.UpdatedAt = toUTC(updatedAt)
	if revokedAt != nil {
		t := toUTC(*revokedAt)
		g.RevokedAt = &t
	}
	return &g, nil
}
