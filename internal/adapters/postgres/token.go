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
	"github.com/authplane/authserver/internal/domain/token"
	"github.com/authplane/authserver/internal/observability"
	"github.com/authplane/authserver/internal/ports/output"
)

// TokenStore implements output.TokenStore using PostgreSQL.
type TokenStore struct {
	pool    *pgxpool.Pool
	logger  *slog.Logger
	tracer  trace.Tracer
	metrics *observability.Metrics
}

var _ output.TokenStore = (*TokenStore)(nil)

// --- Token Families ---

const familyColumns = `id, client_id, user_id, scope, resource, status, created_at, revoked_at, auth_session_id`

func scanFamily(row interface{ Scan(...any) error }) (*token.Family, error) {
	var f token.Family
	var authSessionID *string
	if err := row.Scan(
		&f.ID, &f.ClientID, &f.UserID, &f.Scope, &f.Resource,
		&f.Status, &f.CreatedAt, &f.RevokedAt, &authSessionID,
	); err != nil {
		return nil, err
	}
	if authSessionID != nil {
		f.AuthSessionID = *authSessionID
	}
	f.CreatedAt = toUTC(f.CreatedAt)
	if f.RevokedAt != nil {
		t := toUTC(*f.RevokedAt)
		f.RevokedAt = &t
	}
	return &f, nil
}

// CreateFamily implements output.TokenStore.
func (s *TokenStore) CreateFamily(ctx context.Context, f *token.Family) error {
	ctx, span := s.tracer.Start(ctx, "Postgres.TokenCreateFamily")
	defer span.End()

	var authSessionID *string
	if f.AuthSessionID != "" {
		authSessionID = &f.AuthSessionID
	}

	start := time.Now()
	_, err := dbOrTx(ctx, s.pool).Exec(ctx,
		`INSERT INTO token_families (`+familyColumns+`) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)`,
		f.ID, f.ClientID, f.UserID, f.Scope, f.Resource,
		f.Status, toUTC(f.CreatedAt), f.RevokedAt, authSessionID,
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
	ctx, span := s.tracer.Start(ctx, "Postgres.TokenGetFamily")
	defer span.End()

	start := time.Now()
	row := dbOrTx(ctx, s.pool).QueryRow(ctx,
		`SELECT `+familyColumns+` FROM token_families WHERE id = $1`, id,
	)
	f, err := scanFamily(row)
	s.metrics.DBOperationDuration.Record(ctx, time.Since(start).Seconds(), dbAttrs("token_get_family"))

	if isNoRows(err) {
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
	ctx, span := s.tracer.Start(ctx, "Postgres.TokenGetFamilyByAuthSessionID")
	defer span.End()

	start := time.Now()
	row := dbOrTx(ctx, s.pool).QueryRow(ctx,
		`SELECT `+familyColumns+` FROM token_families WHERE auth_session_id = $1`, authSessionID,
	)
	f, err := scanFamily(row)
	s.metrics.DBOperationDuration.Record(ctx, time.Since(start).Seconds(), dbAttrs("token_get_family_by_auth_session"))

	if isNoRows(err) {
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
	ctx, span := s.tracer.Start(ctx, "Postgres.TokenRevokeFamily")
	defer span.End()

	start := time.Now()
	tx, joined, err := beginOrJoinTx(ctx, s.pool)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return false, fmt.Errorf("begin tx: %w", err)
	}
	if !joined {
		defer func() { _ = tx.Rollback(ctx) }()
	}

	// Mark family as revoked (only if active). The row count is the answer
	// to "did this call revoke it": 0 means it already was.
	tag, err := tx.Exec(ctx,
		`UPDATE token_families SET status = 'revoked', revoked_at = NOW() WHERE id = $1 AND status = 'active'`,
		familyID,
	)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return false, fmt.Errorf("revoke family: %w", err)
	}
	revoked := tag.RowsAffected() > 0

	// Consume all unconsumed refresh tokens in the family.
	if _, err := tx.Exec(ctx,
		`UPDATE refresh_tokens SET consumed_at = NOW() WHERE family_id = $1 AND consumed_at IS NULL`,
		familyID,
	); err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return false, fmt.Errorf("consume family tokens: %w", err)
	}

	if !joined {
		if err := tx.Commit(ctx); err != nil {
			span.RecordError(err)
			span.SetStatus(codes.Error, err.Error())
			return false, fmt.Errorf("commit: %w", err)
		}
	}
	s.metrics.DBOperationDuration.Record(ctx, time.Since(start).Seconds(), dbAttrs("token_revoke_family"))
	return revoked, nil
}

// --- Refresh Tokens ---

const refreshColumns = `id, family_id, token_hash, expires_at, consumed_at, created_at`

func scanRefreshToken(row interface{ Scan(...any) error }) (*token.RefreshToken, error) {
	var rt token.RefreshToken
	if err := row.Scan(
		&rt.ID, &rt.FamilyID, &rt.TokenHash,
		&rt.ExpiresAt, &rt.ConsumedAt, &rt.CreatedAt,
	); err != nil {
		return nil, err
	}
	rt.ExpiresAt = toUTC(rt.ExpiresAt)
	rt.CreatedAt = toUTC(rt.CreatedAt)
	if rt.ConsumedAt != nil {
		t := toUTC(*rt.ConsumedAt)
		rt.ConsumedAt = &t
	}
	return &rt, nil
}

// CreateRefreshToken implements output.TokenStore.
func (s *TokenStore) CreateRefreshToken(ctx context.Context, rt *token.RefreshToken) error {
	ctx, span := s.tracer.Start(ctx, "Postgres.TokenCreateRefreshToken")
	defer span.End()

	start := time.Now()
	_, err := dbOrTx(ctx, s.pool).Exec(ctx,
		`INSERT INTO refresh_tokens (`+refreshColumns+`) VALUES ($1,$2,$3,$4,$5,$6)`,
		rt.ID, rt.FamilyID, rt.TokenHash,
		toUTC(rt.ExpiresAt), rt.ConsumedAt, toUTC(rt.CreatedAt),
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
	ctx, span := s.tracer.Start(ctx, "Postgres.TokenGetRefreshTokenByHash")
	defer span.End()

	start := time.Now()
	row := dbOrTx(ctx, s.pool).QueryRow(ctx,
		`SELECT `+refreshColumns+` FROM refresh_tokens WHERE token_hash = $1`, hash,
	)
	rt, err := scanRefreshToken(row)
	s.metrics.DBOperationDuration.Record(ctx, time.Since(start).Seconds(), dbAttrs("token_get_refresh_by_hash"))

	if isNoRows(err) {
		return nil, domain.ErrInvalidGrant
	}
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return nil, fmt.Errorf("get refresh token by hash: %w", err)
	}
	return rt, nil
}

// ConsumeRefreshToken atomically marks a refresh token as consumed using UPDATE...RETURNING.
// If already consumed, returns the token with ConsumedAt set (reuse signal).
// If not found, returns ErrInvalidGrant.
func (s *TokenStore) ConsumeRefreshToken(ctx context.Context, id string) (*token.RefreshToken, error) {
	ctx, span := s.tracer.Start(ctx, "Postgres.TokenConsumeRefreshToken")
	defer span.End()

	start := time.Now()

	// Attempt atomic consume: succeeds only if consumed_at IS NULL.
	row := dbOrTx(ctx, s.pool).QueryRow(ctx,
		`UPDATE refresh_tokens SET consumed_at = NOW()
		 WHERE id = $1 AND consumed_at IS NULL
		 RETURNING `+refreshColumns,
		id,
	)
	rt, err := scanRefreshToken(row)
	if err == nil {
		s.metrics.DBOperationDuration.Record(ctx, time.Since(start).Seconds(), dbAttrs("token_consume_refresh"))
		return rt, nil
	}
	if !isNoRows(err) {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		s.metrics.DBOperationDuration.Record(ctx, time.Since(start).Seconds(), dbAttrs("token_consume_refresh"))
		return nil, fmt.Errorf("consume refresh token: %w", err)
	}

	// No row returned: either not found or already consumed.
	row2 := dbOrTx(ctx, s.pool).QueryRow(ctx,
		`SELECT `+refreshColumns+` FROM refresh_tokens WHERE id = $1`, id,
	)
	rt, err = scanRefreshToken(row2)
	s.metrics.DBOperationDuration.Record(ctx, time.Since(start).Seconds(), dbAttrs("token_consume_refresh"))

	if isNoRows(err) {
		return nil, domain.ErrInvalidGrant
	}
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return nil, fmt.Errorf("read refresh token: %w", err)
	}
	// Token exists with consumed_at set — reuse detected (theft signal).
	return rt, domain.ErrRefreshTokenReused
}

// PurgeExpired removes refresh tokens whose expires_at is in the past.
// Both consumed and unconsumed expired rows are deleted: an expired refresh
// token is rejected by the refresh flow before any reuse check, so retaining
// it provides no security value.
func (s *TokenStore) PurgeExpired(ctx context.Context) (int64, error) {
	ctx, span := s.tracer.Start(ctx, "Postgres.PurgeExpired.RefreshTokens")
	defer span.End()
	start := time.Now()

	res, err := dbOrTx(ctx, s.pool).Exec(ctx,
		`DELETE FROM refresh_tokens WHERE expires_at < NOW()`,
	)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return 0, fmt.Errorf("purge expired refresh tokens: %w", err)
	}
	n := res.RowsAffected()

	s.metrics.DBOperationDuration.Record(ctx, time.Since(start).Seconds(), dbAttrs("purge_expired_refresh_tokens"))
	return n, nil
}

// CountIssuedSince implements output.TokenStore.
func (s *TokenStore) CountIssuedSince(ctx context.Context, since int64) (int, error) {
	ctx, span := s.tracer.Start(ctx, "Postgres.TokenCountIssuedSince")
	defer span.End()

	sinceTime := time.Unix(since, 0).UTC()

	start := time.Now()
	var count int
	err := dbOrTx(ctx, s.pool).QueryRow(ctx,
		`SELECT COUNT(*) FROM token_families WHERE created_at >= $1`, sinceTime,
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
	ctx, span := s.tracer.Start(ctx, "Postgres.TokenCountRevokedSince")
	defer span.End()

	sinceTime := time.Unix(since, 0).UTC()

	start := time.Now()
	var count int
	err := dbOrTx(ctx, s.pool).QueryRow(ctx,
		`SELECT COUNT(*) FROM token_families WHERE status = 'revoked' AND revoked_at >= $1`, sinceTime,
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
	ctx, span := s.tracer.Start(ctx, "Postgres.TokenListFamilies")
	defer span.End()
	start := time.Now()

	where := "WHERE 1=1"
	args := []any{}
	argIdx := 1
	if filter.ClientID != "" {
		where += fmt.Sprintf(" AND client_id = $%d", argIdx)
		args = append(args, filter.ClientID)
		argIdx++
	}
	if filter.UserID != "" {
		where += fmt.Sprintf(" AND user_id = $%d", argIdx)
		args = append(args, filter.UserID)
		argIdx++
	}
	if filter.Status != "" {
		where += fmt.Sprintf(" AND status = $%d", argIdx)
		args = append(args, filter.Status)
		argIdx++
	}

	// Count total.
	var total int
	countQuery := "SELECT COUNT(*) FROM token_families " + where
	if err := dbOrTx(ctx, s.pool).QueryRow(ctx, countQuery, args...).Scan(&total); err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return nil, 0, fmt.Errorf("count token families: %w", err)
	}

	limit := filter.Limit
	if limit <= 0 {
		limit = 50
	}
	query := fmt.Sprintf(
		"SELECT %s FROM token_families %s ORDER BY created_at DESC LIMIT $%d OFFSET $%d",
		familyColumns, where, argIdx, argIdx+1,
	)
	args = append(args, limit, filter.Offset)

	rows, err := dbOrTx(ctx, s.pool).Query(ctx, query, args...)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return nil, 0, fmt.Errorf("list token families: %w", err)
	}
	defer rows.Close()

	var result []token.Family
	for rows.Next() {
		f, err := scanFamily(rows)
		if err != nil {
			return nil, 0, fmt.Errorf("scan token family: %w", err)
		}
		result = append(result, *f)
	}

	s.metrics.DBOperationDuration.Record(ctx, time.Since(start).Seconds(), dbAttrs("token_list_families"))
	return result, total, nil
}

// CountActiveByClientID returns the number of active families for a client.
func (s *TokenStore) CountActiveByClientID(ctx context.Context, clientID string) (int, error) {
	ctx, span := s.tracer.Start(ctx, "Postgres.TokenCountActiveByClientID")
	defer span.End()
	start := time.Now()

	var count int
	err := dbOrTx(ctx, s.pool).QueryRow(ctx,
		`SELECT COUNT(*) FROM token_families WHERE client_id = $1 AND status = 'active'`, clientID,
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
	ctx, span := s.tracer.Start(ctx, "Postgres.TokenRevokeByClientID")
	defer span.End()
	start := time.Now()

	result, err := dbOrTx(ctx, s.pool).Exec(ctx,
		`UPDATE token_families SET status = 'revoked', revoked_at = NOW() WHERE client_id = $1 AND status = 'active'`,
		clientID,
	)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return 0, fmt.Errorf("revoke families by client: %w", err)
	}

	s.metrics.DBOperationDuration.Record(ctx, time.Since(start).Seconds(), dbAttrs("token_revoke_by_client"))
	return int(result.RowsAffected()), nil
}

// RevokeByUserID revokes all active families for a user. Returns count revoked.
func (s *TokenStore) RevokeByUserID(ctx context.Context, userID string) (int, error) {
	ctx, span := s.tracer.Start(ctx, "Postgres.TokenRevokeByUserID")
	defer span.End()
	start := time.Now()

	result, err := dbOrTx(ctx, s.pool).Exec(ctx,
		`UPDATE token_families SET status = 'revoked', revoked_at = NOW() WHERE user_id = $1 AND status = 'active'`,
		userID,
	)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return 0, fmt.Errorf("revoke families by user: %w", err)
	}

	s.metrics.DBOperationDuration.Record(ctx, time.Since(start).Seconds(), dbAttrs("token_revoke_by_user"))
	return int(result.RowsAffected()), nil
}
