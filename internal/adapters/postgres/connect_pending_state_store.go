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

// ConnectPendingStateStore implements output.ConnectPendingStateStore
// using PostgreSQL against the connect_pending_states table.
// Schema lives in migrations/postgres/001_initial.up.sql lines 588-602.
type ConnectPendingStateStore struct {
	pool    *pgxpool.Pool
	logger  *slog.Logger
	tracer  trace.Tracer
	metrics *observability.Metrics
}

var _ output.ConnectPendingStateStore = (*ConnectPendingStateStore)(nil)

const connectPendingStateColumns = `id, user_id, provider_id, resource_id, code_verifier, return_url, scopes, expires_at`

// Insert persists a new pending-state row.
func (s *ConnectPendingStateStore) Insert(ctx context.Context, state *resource.ConnectPendingState) error {
	ctx, span := s.tracer.Start(ctx, "Postgres.ConnectPendingStateInsert")
	defer span.End()
	start := time.Now()

	_, err := dbOrTx(ctx, s.pool).Exec(ctx,
		`INSERT INTO connect_pending_states (`+connectPendingStateColumns+`)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
		state.ID, state.UserID, state.ProviderID, state.ResourceID,
		state.CodeVerifier, state.ReturnURL,
		issuanceScopesArg(state.Scopes),
		toUTC(state.ExpiresAt),
	)
	s.recordDB(ctx, "connect_pending_state_insert", start)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return fmt.Errorf("insert connect pending state: %w", err)
	}
	return nil
}

// Consume atomically reads + deletes the row using DELETE ... RETURNING.
// Single-use: a second Consume on the same id returns
// domain.ErrPendingStateNotFound.
func (s *ConnectPendingStateStore) Consume(ctx context.Context, id string) (*resource.ConnectPendingState, error) {
	ctx, span := s.tracer.Start(ctx, "Postgres.ConnectPendingStateConsume")
	defer span.End()
	start := time.Now()

	row := dbOrTx(ctx, s.pool).QueryRow(ctx,
		`DELETE FROM connect_pending_states
		  WHERE id = $1 AND expires_at > NOW()
		  RETURNING `+connectPendingStateColumns,
		id,
	)
	state, err := scanConnectPendingState(row)
	s.recordDB(ctx, "connect_pending_state_consume", start)
	if isNoRows(err) {
		return nil, domain.ErrPendingStateNotFound
	}
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return nil, fmt.Errorf("consume connect pending state: %w", err)
	}
	return state, nil
}

// PurgeExpired deletes rows whose expires_at is before the given
// instant.
func (s *ConnectPendingStateStore) PurgeExpired(ctx context.Context, before time.Time) (int, error) {
	ctx, span := s.tracer.Start(ctx, "Postgres.ConnectPendingStatePurgeExpired")
	defer span.End()
	start := time.Now()

	tag, err := dbOrTx(ctx, s.pool).Exec(ctx,
		`DELETE FROM connect_pending_states WHERE expires_at < $1`,
		toUTC(before),
	)
	s.recordDB(ctx, "connect_pending_state_purge_expired", start)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return 0, fmt.Errorf("purge connect pending states: %w", err)
	}
	return int(tag.RowsAffected()), nil
}

func (s *ConnectPendingStateStore) recordDB(ctx context.Context, op string, start time.Time) {
	if s.metrics != nil && s.metrics.DBOperationDuration != nil {
		s.metrics.DBOperationDuration.Record(ctx, time.Since(start).Seconds(), dbAttrs(op))
	}
}

// scanConnectPendingState scans one row into a domain
// ConnectPendingState.
func scanConnectPendingState(row interface{ Scan(...any) error }) (*resource.ConnectPendingState, error) {
	var (
		s         resource.ConnectPendingState
		scopes    []string
		expiresAt time.Time
	)
	if err := row.Scan(
		&s.ID, &s.UserID, &s.ProviderID, &s.ResourceID,
		&s.CodeVerifier, &s.ReturnURL, &scopes, &expiresAt,
	); err != nil {
		return nil, err
	}
	if len(scopes) == 0 {
		s.Scopes = nil
	} else {
		s.Scopes = scopes
	}
	s.ExpiresAt = toUTC(expiresAt)
	return &s, nil
}
