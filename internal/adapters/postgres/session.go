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
	"github.com/authplane/authserver/internal/domain/session"
	"github.com/authplane/authserver/internal/observability"
	"github.com/authplane/authserver/internal/ports/output"
)

// SessionStore implements output.SessionStore using PostgreSQL.
type SessionStore struct {
	pool    *pgxpool.Pool
	logger  *slog.Logger
	tracer  trace.Tracer
	metrics *observability.Metrics
}

var _ output.SessionStore = (*SessionStore)(nil)

const sessionColumns = `id, client_id, user_id, redirect_uri, scope, resource, state, code_hash, code_challenge, code_challenge_method, expires_at, consumed_at, created_at`

func scanSession(row interface{ Scan(...any) error }) (*session.AuthSession, error) {
	var s session.AuthSession
	var codeHash *string

	if err := row.Scan(
		&s.ID, &s.ClientID, &s.UserID, &s.RedirectURI, &s.Scope, &s.Resource,
		&s.State, &codeHash, &s.CodeChallenge, &s.CodeChallengeMethod,
		&s.ExpiresAt, &s.ConsumedAt, &s.CreatedAt,
	); err != nil {
		return nil, err
	}
	if codeHash != nil {
		s.CodeHash = *codeHash
	}
	s.ExpiresAt = toUTC(s.ExpiresAt)
	s.CreatedAt = toUTC(s.CreatedAt)
	if s.ConsumedAt != nil {
		t := toUTC(*s.ConsumedAt)
		s.ConsumedAt = &t
	}
	return &s, nil
}

// Create implements output.SessionStore.
func (st *SessionStore) Create(ctx context.Context, s *session.AuthSession) error {
	ctx, span := st.tracer.Start(ctx, "Postgres.SessionCreate")
	defer span.End()

	// Store code_hash as NULL when empty so the partial unique index allows
	// multiple sessions without a code (code is set later via UpdateCodeHashAndScope).
	var codeHash *string
	if s.CodeHash != "" {
		codeHash = &s.CodeHash
	}

	start := time.Now()
	_, err := dbOrTx(ctx, st.pool).Exec(ctx,
		`INSERT INTO auth_sessions (`+sessionColumns+`) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)`,
		s.ID, s.ClientID, s.UserID, s.RedirectURI, s.Scope, s.Resource,
		s.State, codeHash, s.CodeChallenge, s.CodeChallengeMethod,
		toUTC(s.ExpiresAt), s.ConsumedAt, toUTC(s.CreatedAt),
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
	ctx, span := st.tracer.Start(ctx, "Postgres.SessionGetByID")
	defer span.End()

	start := time.Now()
	row := dbOrTx(ctx, st.pool).QueryRow(ctx,
		`SELECT `+sessionColumns+` FROM auth_sessions WHERE id = $1`, id,
	)
	s, err := scanSession(row)
	st.metrics.DBOperationDuration.Record(ctx, time.Since(start).Seconds(), dbAttrs("session_get_by_id"))

	if isNoRows(err) {
		return nil, domain.ErrInvalidGrant
	}
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return nil, fmt.Errorf("get session by id: %w", err)
	}
	return s, nil
}

// ConsumeByCodeHash atomically marks the session as consumed using UPDATE...RETURNING.
// If already consumed, returns ErrCodeConsumed.
// If not found, returns ErrInvalidGrant.
func (st *SessionStore) ConsumeByCodeHash(ctx context.Context, codeHash string) (*session.AuthSession, error) {
	ctx, span := st.tracer.Start(ctx, "Postgres.SessionConsumeByCodeHash")
	defer span.End()

	start := time.Now()

	// Atomic consume: UPDATE succeeds only if consumed_at IS NULL.
	row := dbOrTx(ctx, st.pool).QueryRow(ctx,
		`UPDATE auth_sessions SET consumed_at = NOW()
		 WHERE code_hash = $1 AND consumed_at IS NULL
		 RETURNING `+sessionColumns,
		codeHash,
	)
	s, err := scanSession(row)
	if err == nil {
		st.metrics.DBOperationDuration.Record(ctx, time.Since(start).Seconds(), dbAttrs("session_consume_by_code_hash"))
		return s, nil
	}
	if !isNoRows(err) {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		st.metrics.DBOperationDuration.Record(ctx, time.Since(start).Seconds(), dbAttrs("session_consume_by_code_hash"))
		return nil, fmt.Errorf("consume session: %w", err)
	}

	// No row returned by UPDATE: either not found or already consumed.
	// Read to distinguish the two cases.
	var existsID string
	checkErr := dbOrTx(ctx, st.pool).QueryRow(ctx,
		`SELECT id FROM auth_sessions WHERE code_hash = $1`, codeHash,
	).Scan(&existsID)
	st.metrics.DBOperationDuration.Record(ctx, time.Since(start).Seconds(), dbAttrs("session_consume_by_code_hash"))

	if isNoRows(checkErr) {
		return nil, domain.ErrInvalidGrant
	}
	if checkErr != nil {
		span.RecordError(checkErr)
		span.SetStatus(codes.Error, checkErr.Error())
		return nil, fmt.Errorf("check session: %w", checkErr)
	}
	// Session exists but was already consumed.
	return nil, domain.ErrCodeConsumed
}

// UpdateCodeHashAndScope implements output.SessionStore.
func (st *SessionStore) UpdateCodeHashAndScope(ctx context.Context, sessionID, codeHash, scope string) error {
	ctx, span := st.tracer.Start(ctx, "Postgres.SessionUpdateCodeHashAndScope")
	defer span.End()

	start := time.Now()
	tag, err := dbOrTx(ctx, st.pool).Exec(ctx,
		`UPDATE auth_sessions SET code_hash = $1, scope = $2 WHERE id = $3 AND expires_at > NOW()`,
		codeHash, scope, sessionID,
	)
	st.metrics.DBOperationDuration.Record(ctx, time.Since(start).Seconds(), dbAttrs("session_update_code_hash"))

	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return fmt.Errorf("update code hash and scope: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return domain.ErrInvalidGrant
	}
	return nil
}

// Delete implements output.SessionStore.
func (st *SessionStore) Delete(ctx context.Context, id string) error {
	ctx, span := st.tracer.Start(ctx, "Postgres.SessionDelete")
	defer span.End()

	start := time.Now()
	_, err := dbOrTx(ctx, st.pool).Exec(ctx,
		`DELETE FROM auth_sessions WHERE id = $1`, id,
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
	ctx, span := st.tracer.Start(ctx, "Postgres.SessionDeleteExpired")
	defer span.End()

	start := time.Now()
	tag, err := dbOrTx(ctx, st.pool).Exec(ctx,
		`DELETE FROM auth_sessions WHERE expires_at < NOW()`,
	)
	st.metrics.DBOperationDuration.Record(ctx, time.Since(start).Seconds(), dbAttrs("session_delete_expired"))

	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return 0, fmt.Errorf("delete expired sessions: %w", err)
	}
	return tag.RowsAffected(), nil
}
