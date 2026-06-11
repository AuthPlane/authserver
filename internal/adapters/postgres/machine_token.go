package postgres

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/authplane/authserver/internal/domain/scope"
	"github.com/authplane/authserver/internal/domain/token"
	"github.com/authplane/authserver/internal/observability"
	"github.com/authplane/authserver/internal/ports/output"
)

var _ output.MachineTokenStore = (*MachineTokenStore)(nil)

// MachineTokenStore implements output.MachineTokenStore using PostgreSQL.
type MachineTokenStore struct {
	pool    *pgxpool.Pool
	logger  *slog.Logger
	tracer  trace.Tracer
	metrics *observability.Metrics
}

// Save persists a machine token record.
func (s *MachineTokenStore) Save(ctx context.Context, mt token.MachineToken) error {
	ctx, span := s.tracer.Start(ctx, "Postgres.MachineTokenSave")
	defer span.End()
	start := time.Now()

	_, err := dbOrTx(ctx, s.pool).Exec(ctx,
		`INSERT INTO machine_tokens (jti, client_id, scopes, resource, issued_at, expires_at, revoked)
		 VALUES ($1, $2, $3, $4, $5, $6, $7)`,
		mt.JTI,
		mt.ClientID,
		mt.Scopes.String(),
		mt.Resource,
		toUTC(mt.IssuedAt),
		toUTC(mt.ExpiresAt),
		mt.Revoked,
	)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return fmt.Errorf("save machine token: %w", err)
	}

	if s.metrics != nil && s.metrics.DBOperationDuration != nil {
		s.metrics.DBOperationDuration.Record(ctx, time.Since(start).Seconds(), dbAttrs("machine_token_save"))
	}

	return nil
}

// GetByJTI returns a machine token by its JTI.
// Returns nil, nil if not found.
func (s *MachineTokenStore) GetByJTI(ctx context.Context, jti string) (*token.MachineToken, error) {
	ctx, span := s.tracer.Start(ctx, "Postgres.MachineTokenGetByJTI")
	defer span.End()
	start := time.Now()

	var mt token.MachineToken
	var scopesStr string

	err := dbOrTx(ctx, s.pool).QueryRow(ctx,
		`SELECT jti, client_id, scopes, resource, issued_at, expires_at, revoked
		 FROM machine_tokens WHERE jti = $1`, jti,
	).Scan(&mt.JTI, &mt.ClientID, &scopesStr, &mt.Resource, &mt.IssuedAt, &mt.ExpiresAt, &mt.Revoked)
	if err != nil {
		if isNoRows(err) {
			return nil, nil
		}
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return nil, fmt.Errorf("get machine token by jti: %w", err)
	}

	mt.Scopes = scope.Parse(scopesStr)
	mt.IssuedAt = toUTC(mt.IssuedAt)
	mt.ExpiresAt = toUTC(mt.ExpiresAt)

	if s.metrics != nil && s.metrics.DBOperationDuration != nil {
		s.metrics.DBOperationDuration.Record(ctx, time.Since(start).Seconds(), dbAttrs("machine_token_get"))
	}

	return &mt, nil
}

// Revoke marks a machine token as revoked by JTI.
func (s *MachineTokenStore) Revoke(ctx context.Context, jti string) error {
	ctx, span := s.tracer.Start(ctx, "Postgres.MachineTokenRevoke")
	defer span.End()
	start := time.Now()

	_, err := dbOrTx(ctx, s.pool).Exec(ctx,
		`UPDATE machine_tokens SET revoked = TRUE WHERE jti = $1`, jti,
	)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return fmt.Errorf("revoke machine token: %w", err)
	}

	if s.metrics != nil && s.metrics.DBOperationDuration != nil {
		s.metrics.DBOperationDuration.Record(ctx, time.Since(start).Seconds(), dbAttrs("machine_token_revoke"))
	}

	return nil
}

// List returns machine tokens matching the filter.
func (s *MachineTokenStore) List(ctx context.Context, filter output.MachineTokenFilter) ([]token.MachineToken, int, error) {
	ctx, span := s.tracer.Start(ctx, "Postgres.MachineTokenList")
	defer span.End()
	start := time.Now()

	where := "WHERE revoked = FALSE AND expires_at > NOW()"
	args := []any{}
	argIdx := 1
	if filter.ClientID != "" {
		where += fmt.Sprintf(" AND client_id = $%d", argIdx)
		args = append(args, filter.ClientID)
		argIdx++
	}

	// Count total.
	var total int
	countQuery := "SELECT COUNT(*) FROM machine_tokens " + where
	if err := dbOrTx(ctx, s.pool).QueryRow(ctx, countQuery, args...).Scan(&total); err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return nil, 0, fmt.Errorf("count machine tokens: %w", err)
	}

	limit := filter.Limit
	if limit <= 0 {
		limit = 50
	}
	query := fmt.Sprintf(
		"SELECT jti, client_id, scopes, resource, issued_at, expires_at, revoked FROM machine_tokens %s ORDER BY issued_at DESC LIMIT $%d OFFSET $%d",
		where, argIdx, argIdx+1,
	)
	args = append(args, limit, filter.Offset)

	rows, err := dbOrTx(ctx, s.pool).Query(ctx, query, args...)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return nil, 0, fmt.Errorf("list machine tokens: %w", err)
	}
	defer rows.Close()

	var result []token.MachineToken
	for rows.Next() {
		var mt token.MachineToken
		var scopesStr string
		if err := rows.Scan(&mt.JTI, &mt.ClientID, &scopesStr, &mt.Resource, &mt.IssuedAt, &mt.ExpiresAt, &mt.Revoked); err != nil {
			return nil, 0, fmt.Errorf("scan machine token: %w", err)
		}
		mt.Scopes = scope.Parse(scopesStr)
		mt.IssuedAt = toUTC(mt.IssuedAt)
		mt.ExpiresAt = toUTC(mt.ExpiresAt)
		result = append(result, mt)
	}

	if s.metrics != nil && s.metrics.DBOperationDuration != nil {
		s.metrics.DBOperationDuration.Record(ctx, time.Since(start).Seconds(), dbAttrs("machine_token_list"))
	}

	return result, total, nil
}

// RevokeByClientID revokes all active machine tokens for a client.
func (s *MachineTokenStore) RevokeByClientID(ctx context.Context, clientID string) (int, error) {
	ctx, span := s.tracer.Start(ctx, "Postgres.MachineTokenRevokeByClientID")
	defer span.End()
	start := time.Now()

	result, err := dbOrTx(ctx, s.pool).Exec(ctx,
		`UPDATE machine_tokens SET revoked = TRUE WHERE client_id = $1 AND revoked = FALSE`,
		clientID,
	)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return 0, fmt.Errorf("revoke machine tokens by client: %w", err)
	}

	if s.metrics != nil && s.metrics.DBOperationDuration != nil {
		s.metrics.DBOperationDuration.Record(ctx, time.Since(start).Seconds(), dbAttrs("machine_token_revoke_by_client"))
	}

	return int(result.RowsAffected()), nil
}

// CountIssuedSince returns the number of machine tokens issued since the given unix timestamp.
func (s *MachineTokenStore) CountIssuedSince(ctx context.Context, since int64) (int, error) {
	ctx, span := s.tracer.Start(ctx, "Postgres.MachineTokenCountIssuedSince")
	defer span.End()

	sinceTime := time.Unix(since, 0).UTC()

	start := time.Now()
	var count int
	err := dbOrTx(ctx, s.pool).QueryRow(ctx,
		`SELECT COUNT(*) FROM machine_tokens WHERE issued_at >= $1`, sinceTime,
	).Scan(&count)
	if s.metrics != nil && s.metrics.DBOperationDuration != nil {
		s.metrics.DBOperationDuration.Record(ctx, time.Since(start).Seconds(), dbAttrs("machine_token_count_issued_since"))
	}

	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return 0, fmt.Errorf("count machine tokens issued since: %w", err)
	}
	return count, nil
}

// CountRevokedSince returns the number of machine tokens revoked since the given unix timestamp.
// Note: machine_tokens table tracks revoked as a boolean, not a timestamp.
// We approximate by counting revoked tokens that were issued since the given time.
func (s *MachineTokenStore) CountRevokedSince(ctx context.Context, since int64) (int, error) {
	ctx, span := s.tracer.Start(ctx, "Postgres.MachineTokenCountRevokedSince")
	defer span.End()

	sinceTime := time.Unix(since, 0).UTC()

	start := time.Now()
	var count int
	err := dbOrTx(ctx, s.pool).QueryRow(ctx,
		`SELECT COUNT(*) FROM machine_tokens WHERE revoked = TRUE AND issued_at >= $1`, sinceTime,
	).Scan(&count)
	if s.metrics != nil && s.metrics.DBOperationDuration != nil {
		s.metrics.DBOperationDuration.Record(ctx, time.Since(start).Seconds(), dbAttrs("machine_token_count_revoked_since"))
	}

	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return 0, fmt.Errorf("count machine tokens revoked since: %w", err)
	}
	return count, nil
}

// PurgeExpired removes expired machine tokens from storage.
func (s *MachineTokenStore) PurgeExpired(ctx context.Context) error {
	ctx, span := s.tracer.Start(ctx, "Postgres.MachineTokenPurgeExpired")
	defer span.End()
	start := time.Now()

	result, err := dbOrTx(ctx, s.pool).Exec(ctx,
		`DELETE FROM machine_tokens WHERE expires_at < NOW()`,
	)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return fmt.Errorf("purge expired machine tokens: %w", err)
	}

	if rows := result.RowsAffected(); rows > 0 {
		s.logger.InfoContext(ctx, "purged expired machine tokens", "count", rows)
	}

	if s.metrics != nil && s.metrics.DBOperationDuration != nil {
		s.metrics.DBOperationDuration.Record(ctx, time.Since(start).Seconds(), dbAttrs("machine_token_purge"))
	}

	return nil
}
