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
	"github.com/authplane/authserver/internal/domain/token"
	"github.com/authplane/authserver/internal/observability"
	"github.com/authplane/authserver/internal/ports/output"
)

// TokenStore implements output.TokenStore using SQLite.
type TokenStore struct {
	db      *sql.DB
	logger  *slog.Logger
	tracer  trace.Tracer
	metrics *observability.Metrics
}

var _ output.TokenStore = (*TokenStore)(nil)

// --- Token Families ---

const familyColumns = `id, client_id, user_id, scope, resource, status, created_at, revoked_at, auth_session_id`

func scanFamily(row interface{ Scan(...any) error }) (*token.Family, error) {
	var f token.Family
	var createdAt string
	var revokedAt sql.NullString
	var authSessionID sql.NullString

	if err := row.Scan(
		&f.ID, &f.ClientID, &f.UserID, &f.Scope, &f.Resource,
		&f.Status, &createdAt, &revokedAt, &authSessionID,
	); err != nil {
		return nil, err
	}
	if authSessionID.Valid {
		f.AuthSessionID = authSessionID.String
	}

	var err error
	f.CreatedAt, err = scanTime(createdAt)
	if err != nil {
		return nil, fmt.Errorf("parse created_at: %w", err)
	}
	f.RevokedAt, err = scanNullableTime(revokedAt)
	if err != nil {
		return nil, fmt.Errorf("parse revoked_at: %w", err)
	}
	return &f, nil
}

// CreateFamily implements output.TokenStore.
func (s *TokenStore) CreateFamily(ctx context.Context, f *token.Family) error {
	ctx, span := s.tracer.Start(ctx, "SQLite.TokenCreateFamily")
	defer span.End()

	// NULL rather than "" when unknown, so the index holds no empty-string rows.
	var authSessionID any
	if f.AuthSessionID != "" {
		authSessionID = f.AuthSessionID
	}

	start := time.Now()
	_, err := dbOrTx(ctx, s.db).ExecContext(ctx,
		`INSERT INTO token_families (`+familyColumns+`) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		f.ID, f.ClientID, f.UserID, f.Scope, f.Resource,
		f.Status, formatTime(f.CreatedAt), formatNullableTime(f.RevokedAt), authSessionID,
	)
	s.metrics.DBOperationDuration.Record(ctx, time.Since(start).Seconds(), dbAttrs("token_create_family"))

	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return fmt.Errorf("insert token family: %w", err)
	}
	return nil
}

// GetFamily implements output.TokenStore.
func (s *TokenStore) GetFamily(ctx context.Context, id string) (*token.Family, error) {
	ctx, span := s.tracer.Start(ctx, "SQLite.TokenGetFamily")
	defer span.End()

	start := time.Now()
	row := dbOrTx(ctx, s.db).QueryRowContext(ctx,
		`SELECT `+familyColumns+` FROM token_families WHERE id = ?`, id,
	)
	f, err := scanFamily(row)
	s.metrics.DBOperationDuration.Record(ctx, time.Since(start).Seconds(), dbAttrs("token_get_family"))

	if errors.Is(err, sql.ErrNoRows) {
		return nil, domain.ErrInvalidGrant
	}
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return nil, fmt.Errorf("get token family: %w", err)
	}
	return f, nil
}

// GetFamilyByAuthSessionID implements output.TokenStore.
func (s *TokenStore) GetFamilyByAuthSessionID(ctx context.Context, authSessionID string) (*token.Family, error) {
	ctx, span := s.tracer.Start(ctx, "SQLite.TokenGetFamilyByAuthSessionID")
	defer span.End()

	start := time.Now()
	row := dbOrTx(ctx, s.db).QueryRowContext(ctx,
		`SELECT `+familyColumns+` FROM token_families WHERE auth_session_id = ?`, authSessionID,
	)
	f, err := scanFamily(row)
	s.metrics.DBOperationDuration.Record(ctx, time.Since(start).Seconds(), dbAttrs("token_get_family_by_auth_session"))

	if errors.Is(err, sql.ErrNoRows) {
		return nil, domain.ErrInvalidGrant
	}
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return nil, fmt.Errorf("get token family by auth session: %w", err)
	}
	return f, nil
}

// RevokeFamily atomically revokes a family and all its refresh tokens.
// Idempotent — an already-revoked family is a no-op, reported as revoked=false.
func (s *TokenStore) RevokeFamily(ctx context.Context, familyID string) (bool, error) {
	ctx, span := s.tracer.Start(ctx, "SQLite.TokenRevokeFamily")
	defer span.End()

	start := time.Now()
	tx, joined, err := beginOrJoinTx(ctx, s.db)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return false, fmt.Errorf("begin tx: %w", err)
	}
	if !joined {
		defer func() { _ = tx.Rollback() }()
	}

	now := formatTime(time.Now().UTC())

	// Mark family as revoked (only if active). The row count is the answer
	// to "did this call revoke it": 0 means it already was.
	res, err := tx.ExecContext(ctx,
		`UPDATE token_families SET status = 'revoked', revoked_at = ? WHERE id = ? AND status = 'active'`,
		now, familyID,
	)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return false, fmt.Errorf("revoke family: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return false, fmt.Errorf("revoke family rows affected: %w", err)
	}

	// Consume all unconsumed refresh tokens in the family.
	if _, err := tx.ExecContext(ctx,
		`UPDATE refresh_tokens SET consumed_at = ? WHERE family_id = ? AND consumed_at IS NULL`,
		now, familyID,
	); err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return false, fmt.Errorf("consume family tokens: %w", err)
	}

	if !joined {
		if err := tx.Commit(); err != nil {
			span.RecordError(err)
			span.SetStatus(codes.Error, err.Error())
			return false, fmt.Errorf("commit: %w", err)
		}
	}
	s.metrics.DBOperationDuration.Record(ctx, time.Since(start).Seconds(), dbAttrs("token_revoke_family"))
	return n > 0, nil
}

// --- Refresh Tokens ---

const refreshColumns = `id, family_id, token_hash, expires_at, consumed_at, created_at`

func scanRefreshToken(row interface{ Scan(...any) error }) (*token.RefreshToken, error) {
	var rt token.RefreshToken
	var expiresAt, createdAt string
	var consumedAt sql.NullString

	if err := row.Scan(
		&rt.ID, &rt.FamilyID, &rt.TokenHash,
		&expiresAt, &consumedAt, &createdAt,
	); err != nil {
		return nil, err
	}

	var err error
	rt.ExpiresAt, err = scanTime(expiresAt)
	if err != nil {
		return nil, fmt.Errorf("parse expires_at: %w", err)
	}
	rt.ConsumedAt, err = scanNullableTime(consumedAt)
	if err != nil {
		return nil, fmt.Errorf("parse consumed_at: %w", err)
	}
	rt.CreatedAt, err = scanTime(createdAt)
	if err != nil {
		return nil, fmt.Errorf("parse created_at: %w", err)
	}
	return &rt, nil
}

// CreateRefreshToken implements output.TokenStore.
func (s *TokenStore) CreateRefreshToken(ctx context.Context, rt *token.RefreshToken) error {
	ctx, span := s.tracer.Start(ctx, "SQLite.TokenCreateRefreshToken")
	defer span.End()

	start := time.Now()
	_, err := dbOrTx(ctx, s.db).ExecContext(ctx,
		`INSERT INTO refresh_tokens (`+refreshColumns+`) VALUES (?, ?, ?, ?, ?, ?)`,
		rt.ID, rt.FamilyID, rt.TokenHash,
		formatTime(rt.ExpiresAt), formatNullableTime(rt.ConsumedAt), formatTime(rt.CreatedAt),
	)
	s.metrics.DBOperationDuration.Record(ctx, time.Since(start).Seconds(), dbAttrs("token_create_refresh"))

	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return fmt.Errorf("insert refresh token: %w", err)
	}
	return nil
}

// GetRefreshTokenByHash implements output.TokenStore.
func (s *TokenStore) GetRefreshTokenByHash(ctx context.Context, hash string) (*token.RefreshToken, error) {
	ctx, span := s.tracer.Start(ctx, "SQLite.TokenGetRefreshTokenByHash")
	defer span.End()

	start := time.Now()
	row := dbOrTx(ctx, s.db).QueryRowContext(ctx,
		`SELECT `+refreshColumns+` FROM refresh_tokens WHERE token_hash = ?`, hash,
	)
	rt, err := scanRefreshToken(row)
	s.metrics.DBOperationDuration.Record(ctx, time.Since(start).Seconds(), dbAttrs("token_get_refresh_by_hash"))

	if errors.Is(err, sql.ErrNoRows) {
		return nil, domain.ErrInvalidGrant
	}
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return nil, fmt.Errorf("get refresh token by hash: %w", err)
	}
	return rt, nil
}

// ConsumeRefreshToken atomically marks a refresh token as consumed.
// If already consumed, returns the token with ConsumedAt set (reuse signal).
// If not found, returns ErrInvalidGrant.
func (s *TokenStore) ConsumeRefreshToken(ctx context.Context, id string) (*token.RefreshToken, error) {
	ctx, span := s.tracer.Start(ctx, "SQLite.TokenConsumeRefreshToken")
	defer span.End()

	start := time.Now()
	tx, joined, err := beginOrJoinTx(ctx, s.db)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return nil, fmt.Errorf("begin tx: %w", err)
	}
	if !joined {
		defer func() { _ = tx.Rollback() }()
	}

	now := formatTime(time.Now().UTC())

	// Attempt atomic consume.
	result, err := tx.ExecContext(ctx,
		`UPDATE refresh_tokens SET consumed_at = ? WHERE id = ? AND consumed_at IS NULL`,
		now, id,
	)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return nil, fmt.Errorf("consume refresh token: %w", err)
	}

	affected, err := result.RowsAffected()
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return nil, fmt.Errorf("rows affected: %w", err)
	}

	// In both cases (success or already consumed) we read back the token.
	row := tx.QueryRowContext(ctx,
		`SELECT `+refreshColumns+` FROM refresh_tokens WHERE id = ?`, id,
	)
	rt, scanErr := scanRefreshToken(row)
	if errors.Is(scanErr, sql.ErrNoRows) {
		s.metrics.DBOperationDuration.Record(ctx, time.Since(start).Seconds(), dbAttrs("token_consume_refresh"))
		return nil, domain.ErrInvalidGrant
	}
	if scanErr != nil {
		span.RecordError(scanErr)
		span.SetStatus(codes.Error, scanErr.Error())
		return nil, fmt.Errorf("read refresh token: %w", scanErr)
	}

	if affected == 1 {
		if !joined {
			if err := tx.Commit(); err != nil {
				span.RecordError(err)
				span.SetStatus(codes.Error, err.Error())
				return nil, fmt.Errorf("commit: %w", err)
			}
		}
		s.metrics.DBOperationDuration.Record(ctx, time.Since(start).Seconds(), dbAttrs("token_consume_refresh"))
		return rt, nil
	}

	// affected == 0 and token exists: already consumed by another request (reuse).
	s.metrics.DBOperationDuration.Record(ctx, time.Since(start).Seconds(), dbAttrs("token_consume_refresh"))
	return rt, domain.ErrRefreshTokenReused
}

// PurgeExpired removes refresh tokens whose expires_at is in the past.
// Both consumed and unconsumed expired rows are deleted: an expired refresh
// token is rejected by the refresh flow before any reuse check, so retaining
// it provides no security value.
func (s *TokenStore) PurgeExpired(ctx context.Context) (int64, error) {
	ctx, span := s.tracer.Start(ctx, "SQLite.PurgeExpired.RefreshTokens")
	defer span.End()
	start := time.Now()

	now := formatTime(time.Now().UTC())
	res, err := dbOrTx(ctx, s.db).ExecContext(ctx,
		`DELETE FROM refresh_tokens WHERE expires_at < ?`, now,
	)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return 0, fmt.Errorf("purge expired refresh tokens: %w", err)
	}
	n, _ := res.RowsAffected()

	s.metrics.DBOperationDuration.Record(ctx, time.Since(start).Seconds(), dbAttrs("purge_expired_refresh_tokens"))
	return n, nil
}

// CountIssuedSince implements output.TokenStore.
func (s *TokenStore) CountIssuedSince(ctx context.Context, since int64) (int, error) {
	ctx, span := s.tracer.Start(ctx, "SQLite.TokenCountIssuedSince")
	defer span.End()

	sinceStr := formatTime(time.Unix(since, 0).UTC())

	start := time.Now()
	var count int
	err := dbOrTx(ctx, s.db).QueryRowContext(ctx,
		`SELECT COUNT(*) FROM token_families WHERE created_at >= ?`, sinceStr,
	).Scan(&count)
	s.metrics.DBOperationDuration.Record(ctx, time.Since(start).Seconds(), dbAttrs("token_count_issued_since"))

	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return 0, fmt.Errorf("count issued since: %w", err)
	}
	return count, nil
}

// CountRevokedSince implements output.TokenStore.
func (s *TokenStore) CountRevokedSince(ctx context.Context, since int64) (int, error) {
	ctx, span := s.tracer.Start(ctx, "SQLite.TokenCountRevokedSince")
	defer span.End()

	sinceStr := formatTime(time.Unix(since, 0).UTC())

	start := time.Now()
	var count int
	err := dbOrTx(ctx, s.db).QueryRowContext(ctx,
		`SELECT COUNT(*) FROM token_families WHERE status = 'revoked' AND revoked_at >= ?`, sinceStr,
	).Scan(&count)
	s.metrics.DBOperationDuration.Record(ctx, time.Since(start).Seconds(), dbAttrs("token_count_revoked_since"))

	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return 0, fmt.Errorf("count revoked since: %w", err)
	}
	return count, nil
}

// --- Admin queries ---

// ListFamilies returns token families matching the filter.
func (s *TokenStore) ListFamilies(ctx context.Context, filter output.FamilyFilter) ([]token.Family, int, error) {
	ctx, span := s.tracer.Start(ctx, "SQLite.TokenListFamilies")
	defer span.End()
	start := time.Now()

	where := "WHERE 1=1"
	args := []any{}
	if filter.ClientID != "" {
		where += " AND client_id = ?"
		args = append(args, filter.ClientID)
	}
	if filter.UserID != "" {
		where += " AND user_id = ?"
		args = append(args, filter.UserID)
	}
	if filter.Status != "" {
		where += " AND status = ?"
		args = append(args, filter.Status)
	}

	// Count total.
	var total int
	countQuery := "SELECT COUNT(*) FROM token_families " + where
	if err := dbOrTx(ctx, s.db).QueryRowContext(ctx, countQuery, args...).Scan(&total); err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return nil, 0, fmt.Errorf("count token families: %w", err)
	}

	limit := filter.Limit
	if limit <= 0 {
		limit = 50
	}
	query := fmt.Sprintf( //nolint:gosec // SQL columns and WHERE clause are hardcoded strings, not user input
		"SELECT %s FROM token_families %s ORDER BY created_at DESC LIMIT ? OFFSET ?",
		familyColumns, where,
	)
	args = append(args, limit, filter.Offset)

	rows, err := dbOrTx(ctx, s.db).QueryContext(ctx, query, args...)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return nil, 0, fmt.Errorf("list token families: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var result []token.Family
	for rows.Next() {
		f, err := scanFamily(rows)
		if err != nil {
			return nil, 0, fmt.Errorf("scan token family: %w", err)
		}
		result = append(result, *f)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("iterate token families: %w", err)
	}

	s.metrics.DBOperationDuration.Record(ctx, time.Since(start).Seconds(), dbAttrs("token_list_families"))
	return result, total, nil
}

// CountActiveByClientID returns the number of active families for a client.
func (s *TokenStore) CountActiveByClientID(ctx context.Context, clientID string) (int, error) {
	ctx, span := s.tracer.Start(ctx, "SQLite.TokenCountActiveByClientID")
	defer span.End()
	start := time.Now()

	var count int
	err := dbOrTx(ctx, s.db).QueryRowContext(ctx,
		`SELECT COUNT(*) FROM token_families WHERE client_id = ? AND status = 'active'`, clientID,
	).Scan(&count)
	s.metrics.DBOperationDuration.Record(ctx, time.Since(start).Seconds(), dbAttrs("token_count_active_by_client"))

	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return 0, fmt.Errorf("count active by client: %w", err)
	}
	return count, nil
}

// RevokeByClientID revokes all active families for a client. Returns count revoked.
func (s *TokenStore) RevokeByClientID(ctx context.Context, clientID string) (int, error) {
	ctx, span := s.tracer.Start(ctx, "SQLite.TokenRevokeByClientID")
	defer span.End()
	start := time.Now()

	now := formatTime(time.Now().UTC())
	result, err := dbOrTx(ctx, s.db).ExecContext(ctx,
		`UPDATE token_families SET status = 'revoked', revoked_at = ? WHERE client_id = ? AND status = 'active'`,
		now, clientID,
	)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return 0, fmt.Errorf("revoke families by client: %w", err)
	}

	n, _ := result.RowsAffected()
	s.metrics.DBOperationDuration.Record(ctx, time.Since(start).Seconds(), dbAttrs("token_revoke_by_client"))
	return int(n), nil
}

// RevokeByUserID revokes all active families for a user. Returns count revoked.
func (s *TokenStore) RevokeByUserID(ctx context.Context, userID string) (int, error) {
	ctx, span := s.tracer.Start(ctx, "SQLite.TokenRevokeByUserID")
	defer span.End()
	start := time.Now()

	now := formatTime(time.Now().UTC())
	result, err := dbOrTx(ctx, s.db).ExecContext(ctx,
		`UPDATE token_families SET status = 'revoked', revoked_at = ? WHERE user_id = ? AND status = 'active'`,
		now, userID,
	)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return 0, fmt.Errorf("revoke families by user: %w", err)
	}

	n, _ := result.RowsAffected()
	s.metrics.DBOperationDuration.Record(ctx, time.Since(start).Seconds(), dbAttrs("token_revoke_by_user"))
	return int(n), nil
}
