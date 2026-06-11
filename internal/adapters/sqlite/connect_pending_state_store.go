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

// ConnectPendingStateStore implements output.ConnectPendingStateStore
// using SQLite against the connect_pending_states table.
// Schema lives in migrations/sqlite/001_initial.up.sql lines 521-535.
type ConnectPendingStateStore struct {
	db      *sql.DB
	logger  *slog.Logger
	tracer  trace.Tracer
	metrics *observability.Metrics
}

var _ output.ConnectPendingStateStore = (*ConnectPendingStateStore)(nil)

const connectPendingStateColumns = `id, user_id, provider_id, resource_id, code_verifier, return_url, scopes, expires_at`

// Insert persists a new pending-state row.
func (s *ConnectPendingStateStore) Insert(ctx context.Context, state *resource.ConnectPendingState) error {
	ctx, span := s.tracer.Start(ctx, "SQLite.ConnectPendingStateInsert")
	defer span.End()
	start := time.Now()

	_, err := dbOrTx(ctx, s.db).ExecContext(ctx,
		`INSERT INTO connect_pending_states (`+connectPendingStateColumns+`)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		state.ID, state.UserID, state.ProviderID, state.ResourceID,
		state.CodeVerifier, state.ReturnURL,
		marshalIssuanceScopes(state.Scopes),
		formatTime(state.ExpiresAt),
	)
	s.recordDB(ctx, "connect_pending_state_insert", start)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return fmt.Errorf("insert connect pending state: %w", err)
	}
	return nil
}

// Consume atomically reads + deletes the row in a single transaction.
// Single-use: a second Consume on the same id returns
// domain.ErrPendingStateNotFound.
func (s *ConnectPendingStateStore) Consume(ctx context.Context, id string) (*resource.ConnectPendingState, error) {
	ctx, span := s.tracer.Start(ctx, "SQLite.ConnectPendingStateConsume")
	defer span.End()
	start := time.Now()

	tx, joined, err := beginOrJoinTx(ctx, s.db)
	if err != nil {
		s.recordDB(ctx, "connect_pending_state_consume", start)
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return nil, fmt.Errorf("begin tx: %w", err)
	}
	if !joined {
		defer func() { _ = tx.Rollback() }()
	}

	now := formatTime(time.Now().UTC())
	row := tx.QueryRowContext(ctx,
		`SELECT `+connectPendingStateColumns+`
		   FROM connect_pending_states
		  WHERE id = ? AND expires_at > ?`,
		id, now,
	)
	state, err := scanConnectPendingState(row)
	if errors.Is(err, sql.ErrNoRows) {
		s.recordDB(ctx, "connect_pending_state_consume", start)
		return nil, domain.ErrPendingStateNotFound
	}
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return nil, fmt.Errorf("select connect pending state: %w", err)
	}

	res, err := tx.ExecContext(ctx,
		`DELETE FROM connect_pending_states WHERE id = ?`, id,
	)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return nil, fmt.Errorf("delete connect pending state: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return nil, fmt.Errorf("rows affected: %w", err)
	}
	if n == 0 {
		// A concurrent caller deleted the row between SELECT and
		// DELETE — enforce single-use semantics.
		s.recordDB(ctx, "connect_pending_state_consume", start)
		return nil, domain.ErrPendingStateNotFound
	}

	if !joined {
		if err := tx.Commit(); err != nil {
			return nil, fmt.Errorf("commit: %w", err)
		}
	}
	s.recordDB(ctx, "connect_pending_state_consume", start)
	return state, nil
}

// PurgeExpired deletes rows whose expires_at is before the given
// instant.
func (s *ConnectPendingStateStore) PurgeExpired(ctx context.Context, before time.Time) (int, error) {
	ctx, span := s.tracer.Start(ctx, "SQLite.ConnectPendingStatePurgeExpired")
	defer span.End()
	start := time.Now()

	res, err := dbOrTx(ctx, s.db).ExecContext(ctx,
		`DELETE FROM connect_pending_states WHERE expires_at < ?`,
		formatTime(before.UTC()),
	)
	s.recordDB(ctx, "connect_pending_state_purge_expired", start)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return 0, fmt.Errorf("purge connect pending states: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("rows affected: %w", err)
	}
	return int(n), nil
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
		scopesStr string
		expiresAt string
	)
	if err := row.Scan(
		&s.ID, &s.UserID, &s.ProviderID, &s.ResourceID,
		&s.CodeVerifier, &s.ReturnURL, &scopesStr, &expiresAt,
	); err != nil {
		return nil, err
	}
	scopes, err := unmarshalIssuanceScopes(scopesStr)
	if err != nil {
		return nil, fmt.Errorf("parse scopes: %w", err)
	}
	s.Scopes = scopes
	s.ExpiresAt, err = scanTime(expiresAt)
	if err != nil {
		return nil, fmt.Errorf("parse expires_at: %w", err)
	}
	return &s, nil
}
