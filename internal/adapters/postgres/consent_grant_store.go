package postgres

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"

	"github.com/authplane/authserver/internal/domain/resource"
	"github.com/authplane/authserver/internal/observability"
	"github.com/authplane/authserver/internal/ports/output"
)

// ConsentGrantStore implements output.ConsentGrantStore using
// PostgreSQL against the consent_grants table.
// Schema lives in migrations/postgres/001_initial.up.sql lines 518-535.
type ConsentGrantStore struct {
	pool    *pgxpool.Pool
	logger  *slog.Logger
	tracer  trace.Tracer
	metrics *observability.Metrics
}

var _ output.ConsentGrantStore = (*ConsentGrantStore)(nil)

const consentGrantColumns = `id, user_id, client_id, resource_id, scopes, created_at, updated_at, revoked_at`

// Get returns the active grant for (user, client, resource) or
// (nil, nil) when no row matches.
func (s *ConsentGrantStore) Get(ctx context.Context, userID, clientID, resourceID string) (*resource.ConsentGrant, error) {
	ctx, span := s.tracer.Start(ctx, "Postgres.ConsentGrantGet")
	defer span.End()
	start := time.Now()

	row := dbOrTx(ctx, s.pool).QueryRow(ctx,
		`SELECT `+consentGrantColumns+`
		   FROM consent_grants
		  WHERE user_id = $1 AND client_id = $2 AND resource_id = $3
		    AND revoked_at IS NULL`,
		userID, clientID, resourceID,
	)
	g, err := scanConsentGrant(row)
	s.recordDB(ctx, "consent_grant_get", start)
	if isNoRows(err) {
		return nil, nil
	}
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return nil, fmt.Errorf("get consent grant: %w", err)
	}
	return g, nil
}

// GetByID returns the grant with the given id (active or revoked) or
// (nil, nil) when no row matches. Used by the admin revocation cascade.
func (s *ConsentGrantStore) GetByID(ctx context.Context, id string) (*resource.ConsentGrant, error) {
	ctx, span := s.tracer.Start(ctx, "Postgres.ConsentGrantGetByID")
	defer span.End()
	start := time.Now()

	row := dbOrTx(ctx, s.pool).QueryRow(ctx,
		`SELECT `+consentGrantColumns+`
		   FROM consent_grants
		  WHERE id = $1`,
		id,
	)
	g, err := scanConsentGrant(row)
	s.recordDB(ctx, "consent_grant_get_by_id", start)
	if isNoRows(err) {
		return nil, nil
	}
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return nil, fmt.Errorf("get consent grant by id: %w", err)
	}
	return g, nil
}

// Upsert inserts a new grant or updates the existing row keyed on
// (user_id, client_id, resource_id). A re-grant after revocation
// re-activates the same row by clearing revoked_at.
func (s *ConsentGrantStore) Upsert(ctx context.Context, g *resource.ConsentGrant) error {
	ctx, span := s.tracer.Start(ctx, "Postgres.ConsentGrantUpsert")
	defer span.End()
	start := time.Now()

	_, err := dbOrTx(ctx, s.pool).Exec(ctx,
		`INSERT INTO consent_grants (`+consentGrantColumns+`)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
		 ON CONFLICT (user_id, client_id, resource_id) DO UPDATE SET
		   scopes     = EXCLUDED.scopes,
		   updated_at = EXCLUDED.updated_at,
		   revoked_at = NULL`,
		g.ID, g.UserID, g.ClientID, g.ResourceID,
		consentGrantScopesArg(g.Scopes),
		toUTC(g.CreatedAt), toUTC(g.UpdatedAt),
		g.RevokedAt,
	)
	s.recordDB(ctx, "consent_grant_upsert", start)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return fmt.Errorf("upsert consent grant: %w", err)
	}
	return nil
}

// Revoke sets revoked_at on the row with the given id. Idempotent.
func (s *ConsentGrantStore) Revoke(ctx context.Context, id string) error {
	ctx, span := s.tracer.Start(ctx, "Postgres.ConsentGrantRevoke")
	defer span.End()
	start := time.Now()

	_, err := dbOrTx(ctx, s.pool).Exec(ctx,
		`UPDATE consent_grants
		    SET revoked_at = NOW(), updated_at = NOW()
		  WHERE id = $1`,
		id,
	)
	s.recordDB(ctx, "consent_grant_revoke", start)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return fmt.Errorf("revoke consent grant: %w", err)
	}
	return nil
}

// ListForUser returns all grants for the user (active + revoked),
// newest first.
func (s *ConsentGrantStore) ListForUser(ctx context.Context, userID string) ([]*resource.ConsentGrant, error) {
	ctx, span := s.tracer.Start(ctx, "Postgres.ConsentGrantListForUser")
	defer span.End()
	start := time.Now()

	rows, err := dbOrTx(ctx, s.pool).Query(ctx,
		`SELECT `+consentGrantColumns+`
		   FROM consent_grants
		  WHERE user_id = $1
		  ORDER BY created_at DESC`,
		userID,
	)
	s.recordDB(ctx, "consent_grant_list_for_user", start)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return nil, fmt.Errorf("list consent grants: %w", err)
	}
	defer rows.Close()

	var out []*resource.ConsentGrant
	for rows.Next() {
		g, err := scanConsentGrant(rows)
		if err != nil {
			span.RecordError(err)
			span.SetStatus(codes.Error, err.Error())
			return nil, fmt.Errorf("scan consent grant: %w", err)
		}
		out = append(out, g)
	}
	if err := rows.Err(); err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return nil, fmt.Errorf("iterate consent grants: %w", err)
	}
	return out, nil
}

func (s *ConsentGrantStore) recordDB(ctx context.Context, op string, start time.Time) {
	if s.metrics != nil && s.metrics.DBOperationDuration != nil {
		s.metrics.DBOperationDuration.Record(ctx, time.Since(start).Seconds(), dbAttrs(op))
	}
}

// scanConsentGrant scans one row from consent_grants into a
// domain ConsentGrant.
func scanConsentGrant(row interface{ Scan(...any) error }) (*resource.ConsentGrant, error) {
	var (
		g         resource.ConsentGrant
		scopes    []string
		createdAt time.Time
		updatedAt time.Time
		revokedAt *time.Time
	)
	if err := row.Scan(
		&g.ID, &g.UserID, &g.ClientID, &g.ResourceID,
		&scopes, &createdAt, &updatedAt, &revokedAt,
	); err != nil {
		return nil, err
	}
	if len(scopes) == 0 {
		g.Scopes = nil
	} else {
		g.Scopes = scopes
	}
	g.CreatedAt = toUTC(createdAt)
	g.UpdatedAt = toUTC(updatedAt)
	if revokedAt != nil {
		t := toUTC(*revokedAt)
		g.RevokedAt = &t
	}
	return &g, nil
}

// consentGrantScopesArg normalizes nil to an empty slice so pgx
// encodes it as the empty TEXT[] '{}' rather than NULL — the column
// is NOT NULL DEFAULT '{}'.
func consentGrantScopesArg(ss []string) []string {
	if ss == nil {
		return []string{}
	}
	return ss
}
