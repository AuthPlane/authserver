package sqlite

import (
	"context"
	"database/sql"
	"fmt"
	"log/slog"
	"time"

	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"

	"github.com/authplane/authserver/internal/domain/scope"
	"github.com/authplane/authserver/internal/domain/token"
	"github.com/authplane/authserver/internal/observability"
	"github.com/authplane/authserver/internal/ports/output"
)

var _ output.MachineTokenStore = (*MachineTokenStore)(nil)

// MachineTokenStore implements output.MachineTokenStore using SQLite.
type MachineTokenStore struct {
	db      *sql.DB
	logger  *slog.Logger
	tracer  trace.Tracer
	metrics *observability.Metrics
}

// Save persists a machine token record.
func (s *MachineTokenStore) Save(ctx context.Context, mt token.MachineToken) error {
	ctx, span := s.tracer.Start(ctx, "SQLite.MachineTokenSave")
	defer span.End()
	start := time.Now()

	_, err := dbOrTx(ctx, s.db).ExecContext(ctx,
		`INSERT INTO machine_tokens (jti, client_id, scopes, resource, issued_at, expires_at, revoked)
		 VALUES (?, ?, ?, ?, ?, ?, ?)`,
		mt.JTI,
		mt.ClientID,
		mt.Scopes.String(),
		mt.Resource,
		formatTime(mt.IssuedAt),
		formatTime(mt.ExpiresAt),
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
	ctx, span := s.tracer.Start(ctx, "SQLite.MachineTokenGetByJTI")
	defer span.End()
	start := time.Now()

	var mt token.MachineToken
	var scopesStr, issuedAtStr, expiresAtStr string

	err := dbOrTx(ctx, s.db).QueryRowContext(ctx,
		`SELECT jti, client_id, scopes, resource, issued_at, expires_at, revoked
		 FROM machine_tokens WHERE jti = ?`, jti,
	).Scan(&mt.JTI, &mt.ClientID, &scopesStr, &mt.Resource, &issuedAtStr, &expiresAtStr, &mt.Revoked)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return nil, fmt.Errorf("get machine token by jti: %w", err)
	}

	mt.Scopes = scope.Parse(scopesStr)
	mt.IssuedAt, err = scanTime(issuedAtStr)
	if err != nil {
		return nil, fmt.Errorf("parse issued_at: %w", err)
	}
	mt.ExpiresAt, err = scanTime(expiresAtStr)
	if err != nil {
		return nil, fmt.Errorf("parse expires_at: %w", err)
	}

	if s.metrics != nil && s.metrics.DBOperationDuration != nil {
		s.metrics.DBOperationDuration.Record(ctx, time.Since(start).Seconds(), dbAttrs("machine_token_get"))
	}

	return &mt, nil
}

// Revoke marks a machine token as revoked by JTI.
func (s *MachineTokenStore) Revoke(ctx context.Context, jti string) error {
	ctx, span := s.tracer.Start(ctx, "SQLite.MachineTokenRevoke")
	defer span.End()
	start := time.Now()

	_, err := dbOrTx(ctx, s.db).ExecContext(ctx,
		`UPDATE machine_tokens SET revoked = TRUE WHERE jti = ?`, jti,
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
	ctx, span := s.tracer.Start(ctx, "SQLite.MachineTokenList")
	defer span.End()
	start := time.Now()

	where := "WHERE revoked = FALSE AND expires_at > ?"
	args := []any{formatTime(time.Now().UTC())}
	if filter.ClientID != "" {
		where += " AND client_id = ?"
		args = append(args, filter.ClientID)
	}

	// Count total.
	var total int
	countQuery := "SELECT COUNT(*) FROM machine_tokens " + where
	if err := dbOrTx(ctx, s.db).QueryRowContext(ctx, countQuery, args...).Scan(&total); err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return nil, 0, fmt.Errorf("count machine tokens: %w", err)
	}

	limit := filter.Limit
	if limit <= 0 {
		limit = 50
	}
	query := fmt.Sprintf( //nolint:gosec // SQL WHERE clause is built from hardcoded column names, not user input
		"SELECT jti, client_id, scopes, resource, issued_at, expires_at, revoked FROM machine_tokens %s ORDER BY issued_at DESC LIMIT ? OFFSET ?",
		where,
	)
	args = append(args, limit, filter.Offset)

	rows, err := dbOrTx(ctx, s.db).QueryContext(ctx, query, args...)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return nil, 0, fmt.Errorf("list machine tokens: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var result []token.MachineToken
	for rows.Next() {
		var mt token.MachineToken
		var scopesStr, issuedAtStr, expiresAtStr string
		if err := rows.Scan(&mt.JTI, &mt.ClientID, &scopesStr, &mt.Resource, &issuedAtStr, &expiresAtStr, &mt.Revoked); err != nil {
			return nil, 0, fmt.Errorf("scan machine token: %w", err)
		}
		mt.Scopes = scope.Parse(scopesStr)
		mt.IssuedAt, _ = scanTime(issuedAtStr)
		mt.ExpiresAt, _ = scanTime(expiresAtStr)
		result = append(result, mt)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("iterate machine tokens: %w", err)
	}

	if s.metrics != nil && s.metrics.DBOperationDuration != nil {
		s.metrics.DBOperationDuration.Record(ctx, time.Since(start).Seconds(), dbAttrs("machine_token_list"))
	}

	return result, total, nil
}

// RevokeByClientID revokes all active machine tokens for a client.
func (s *MachineTokenStore) RevokeByClientID(ctx context.Context, clientID string) (int, error) {
	ctx, span := s.tracer.Start(ctx, "SQLite.MachineTokenRevokeByClientID")
	defer span.End()
	start := time.Now()

	result, err := dbOrTx(ctx, s.db).ExecContext(ctx,
		`UPDATE machine_tokens SET revoked = TRUE WHERE client_id = ? AND revoked = FALSE`,
		clientID,
	)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return 0, fmt.Errorf("revoke machine tokens by client: %w", err)
	}

	n, _ := result.RowsAffected()

	if s.metrics != nil && s.metrics.DBOperationDuration != nil {
		s.metrics.DBOperationDuration.Record(ctx, time.Since(start).Seconds(), dbAttrs("machine_token_revoke_by_client"))
	}

	return int(n), nil
}

// CountIssuedSince returns the number of machine tokens issued since the given unix timestamp.
func (s *MachineTokenStore) CountIssuedSince(ctx context.Context, since int64) (int, error) {
	ctx, span := s.tracer.Start(ctx, "SQLite.MachineTokenCountIssuedSince")
	defer span.End()

	sinceStr := formatTime(time.Unix(since, 0).UTC())

	start := time.Now()
	var count int
	err := dbOrTx(ctx, s.db).QueryRowContext(ctx,
		`SELECT COUNT(*) FROM machine_tokens WHERE issued_at >= ?`, sinceStr,
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
	ctx, span := s.tracer.Start(ctx, "SQLite.MachineTokenCountRevokedSince")
	defer span.End()

	sinceStr := formatTime(time.Unix(since, 0).UTC())

	start := time.Now()
	var count int
	err := dbOrTx(ctx, s.db).QueryRowContext(ctx,
		`SELECT COUNT(*) FROM machine_tokens WHERE revoked = TRUE AND issued_at >= ?`, sinceStr,
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
	ctx, span := s.tracer.Start(ctx, "SQLite.MachineTokenPurgeExpired")
	defer span.End()
	start := time.Now()

	result, err := dbOrTx(ctx, s.db).ExecContext(ctx,
		`DELETE FROM machine_tokens WHERE expires_at < ?`,
		formatTime(time.Now().UTC()),
	)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return fmt.Errorf("purge expired machine tokens: %w", err)
	}

	if rows, _ := result.RowsAffected(); rows > 0 {
		s.logger.InfoContext(ctx, "purged expired machine tokens", "count", rows)
	}

	if s.metrics != nil && s.metrics.DBOperationDuration != nil {
		s.metrics.DBOperationDuration.Record(ctx, time.Since(start).Seconds(), dbAttrs("machine_token_purge"))
	}

	return nil
}
