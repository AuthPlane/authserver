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
	"github.com/authplane/authserver/internal/domain/session"
	"github.com/authplane/authserver/internal/observability"
	"github.com/authplane/authserver/internal/ports/output"
)

// SessionStore implements output.SessionStore using SQLite.
type SessionStore struct {
	db      *sql.DB
	logger  *slog.Logger
	tracer  trace.Tracer
	metrics *observability.Metrics
}

var _ output.SessionStore = (*SessionStore)(nil)

const sessionColumns = `id, client_id, user_id, redirect_uri, scope, resource, state, code_hash, code_challenge, code_challenge_method, expires_at, consumed_at, created_at`

func scanSession(row interface{ Scan(...any) error }) (*session.AuthSession, error) {
	var s session.AuthSession
	var expiresAt, createdAt string
	var consumedAt, codeHash sql.NullString

	if err := row.Scan(
		&s.ID, &s.ClientID, &s.UserID, &s.RedirectURI, &s.Scope, &s.Resource,
		&s.State, &codeHash, &s.CodeChallenge, &s.CodeChallengeMethod,
		&expiresAt, &consumedAt, &createdAt,
	); err != nil {
		return nil, err
	}
	if codeHash.Valid {
		s.CodeHash = codeHash.String
	}

	var err error
	s.ExpiresAt, err = scanTime(expiresAt)
	if err != nil {
		return nil, fmt.Errorf("parse expires_at: %w", err)
	}
	s.ConsumedAt, err = scanNullableTime(consumedAt)
	if err != nil {
		return nil, fmt.Errorf("parse consumed_at: %w", err)
	}
	s.CreatedAt, err = scanTime(createdAt)
	if err != nil {
		return nil, fmt.Errorf("parse created_at: %w", err)
	}
	return &s, nil
}

// Create implements output.SessionStore.
func (st *SessionStore) Create(ctx context.Context, s *session.AuthSession) error {
	ctx, span := st.tracer.Start(ctx, "SQLite.SessionCreate")
	defer span.End()

	// Store code_hash as NULL when empty so the partial unique index allows
	// multiple sessions without a code (code is set later via UpdateCodeHashAndScope).
	var codeHash any
	if s.CodeHash != "" {
		codeHash = s.CodeHash
	}

	start := time.Now()
	_, err := dbOrTx(ctx, st.db).ExecContext(ctx,
		`INSERT INTO auth_sessions (`+sessionColumns+`) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		s.ID, s.ClientID, s.UserID, s.RedirectURI, s.Scope, s.Resource,
		s.State, codeHash, s.CodeChallenge, s.CodeChallengeMethod,
		formatTime(s.ExpiresAt), formatNullableTime(s.ConsumedAt), formatTime(s.CreatedAt),
	)
	st.metrics.DBOperationDuration.Record(ctx, time.Since(start).Seconds(), dbAttrs("session_create"))

	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return fmt.Errorf("insert session: %w", err)
	}
	return nil
}

// GetByID implements output.SessionStore.
func (st *SessionStore) GetByID(ctx context.Context, id string) (*session.AuthSession, error) {
	ctx, span := st.tracer.Start(ctx, "SQLite.SessionGetByID")
	defer span.End()

	start := time.Now()
	row := dbOrTx(ctx, st.db).QueryRowContext(ctx,
		`SELECT `+sessionColumns+` FROM auth_sessions WHERE id = ?`, id,
	)
	s, err := scanSession(row)
	st.metrics.DBOperationDuration.Record(ctx, time.Since(start).Seconds(), dbAttrs("session_get_by_id"))

	if errors.Is(err, sql.ErrNoRows) {
		return nil, domain.ErrInvalidGrant
	}
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return nil, fmt.Errorf("get session by id: %w", err)
	}
	return s, nil
}

// ConsumeByCodeHash atomically marks the session as consumed.
// If already consumed, returns ErrCodeConsumed.
// If not found, returns ErrInvalidGrant.
func (st *SessionStore) ConsumeByCodeHash(ctx context.Context, codeHash string) (*session.AuthSession, error) {
	ctx, span := st.tracer.Start(ctx, "SQLite.SessionConsumeByCodeHash")
	defer span.End()

	start := time.Now()
	tx, joined, err := beginOrJoinTx(ctx, st.db)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return nil, fmt.Errorf("begin tx: %w", err)
	}
	if !joined {
		defer func() { _ = tx.Rollback() }()
	}

	now := formatTime(time.Now().UTC())

	// Attempt atomic consume: only succeeds if consumed_at IS NULL.
	result, err := tx.ExecContext(ctx,
		`UPDATE auth_sessions SET consumed_at = ? WHERE code_hash = ? AND consumed_at IS NULL`,
		now, codeHash,
	)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return nil, fmt.Errorf("consume session: %w", err)
	}

	affected, err := result.RowsAffected()
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return nil, fmt.Errorf("rows affected: %w", err)
	}

	if affected == 1 {
		// Success: read back the consumed session.
		row := tx.QueryRowContext(ctx,
			`SELECT `+sessionColumns+` FROM auth_sessions WHERE code_hash = ?`, codeHash,
		)
		s, err := scanSession(row)
		if err != nil {
			span.RecordError(err)
			span.SetStatus(codes.Error, err.Error())
			return nil, fmt.Errorf("read consumed session: %w", err)
		}
		if !joined {
			if err := tx.Commit(); err != nil {
				span.RecordError(err)
				span.SetStatus(codes.Error, err.Error())
				return nil, fmt.Errorf("commit: %w", err)
			}
		}
		st.metrics.DBOperationDuration.Record(ctx, time.Since(start).Seconds(), dbAttrs("session_consume_by_code_hash"))
		return s, nil
	}

	// RowsAffected == 0: either not found or already consumed.
	row := tx.QueryRowContext(ctx,
		`SELECT `+sessionColumns+` FROM auth_sessions WHERE code_hash = ?`, codeHash,
	)
	s, scanErr := scanSession(row)
	st.metrics.DBOperationDuration.Record(ctx, time.Since(start).Seconds(), dbAttrs("session_consume_by_code_hash"))

	if errors.Is(scanErr, sql.ErrNoRows) {
		return nil, domain.ErrInvalidGrant
	}
	if scanErr != nil {
		span.RecordError(scanErr)
		span.SetStatus(codes.Error, scanErr.Error())
		return nil, fmt.Errorf("check session: %w", scanErr)
	}
	// Session exists but was already consumed.
	_ = s // we only need to know it exists
	return nil, domain.ErrCodeConsumed
}

// UpdateCodeHashAndScope implements output.SessionStore.
func (st *SessionStore) UpdateCodeHashAndScope(ctx context.Context, sessionID, codeHash, scope string) error {
	ctx, span := st.tracer.Start(ctx, "SQLite.SessionUpdateCodeHashAndScope")
	defer span.End()

	start := time.Now()
	result, err := dbOrTx(ctx, st.db).ExecContext(ctx,
		`UPDATE auth_sessions SET code_hash = ?, scope = ? WHERE id = ? AND expires_at > ?`,
		codeHash, scope, sessionID, formatTime(time.Now().UTC()),
	)
	st.metrics.DBOperationDuration.Record(ctx, time.Since(start).Seconds(), dbAttrs("session_update_code_hash"))

	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return fmt.Errorf("update code hash: %w", err)
	}
	affected, err := result.RowsAffected()
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return fmt.Errorf("rows affected: %w", err)
	}
	if affected == 0 {
		return domain.ErrInvalidGrant
	}
	return nil
}

// Delete implements output.SessionStore.
func (st *SessionStore) Delete(ctx context.Context, id string) error {
	ctx, span := st.tracer.Start(ctx, "SQLite.SessionDelete")
	defer span.End()

	start := time.Now()
	_, err := dbOrTx(ctx, st.db).ExecContext(ctx,
		`DELETE FROM auth_sessions WHERE id = ?`, id,
	)
	st.metrics.DBOperationDuration.Record(ctx, time.Since(start).Seconds(), dbAttrs("session_delete"))

	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return fmt.Errorf("delete session: %w", err)
	}
	return nil
}

// DeleteExpired implements output.SessionStore.
func (st *SessionStore) DeleteExpired(ctx context.Context) (int64, error) {
	ctx, span := st.tracer.Start(ctx, "SQLite.SessionDeleteExpired")
	defer span.End()

	now := formatTime(time.Now().UTC())

	start := time.Now()
	result, err := dbOrTx(ctx, st.db).ExecContext(ctx,
		`DELETE FROM auth_sessions WHERE expires_at < ?`, now,
	)
	st.metrics.DBOperationDuration.Record(ctx, time.Since(start).Seconds(), dbAttrs("session_delete_expired"))

	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return 0, fmt.Errorf("delete expired sessions: %w", err)
	}
	return result.RowsAffected()
}
