package sqlite

import (
	"context"
	"database/sql"
	"fmt"
	"log/slog"
	"time"

	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"

	"github.com/authplane/authserver/internal/crypto"
	"github.com/authplane/authserver/internal/domain"
	"github.com/authplane/authserver/internal/observability"
	"github.com/authplane/authserver/internal/ports/output"
)

var _ output.DPoPNonceStore = (*DPoPNonceStore)(nil)

// DPoPNonceStore implements output.DPoPNonceStore using SQLite.
type DPoPNonceStore struct {
	db      *sql.DB
	logger  *slog.Logger
	tracer  trace.Tracer
	metrics *observability.Metrics
}

// ConsumeJTI records a DPoP proof JTI. Returns domain.ErrDPoPReplay if already consumed.
func (s *DPoPNonceStore) ConsumeJTI(ctx context.Context, jti string, expiry time.Time) error {
	ctx, span := s.tracer.Start(ctx, "SQLite.DPoPConsumeJTI")
	defer span.End()
	start := time.Now()

	_, err := s.db.ExecContext(ctx,
		`INSERT INTO dpop_jtis (jti, expires_at) VALUES (?, ?)`,
		jti, formatTime(expiry),
	)
	if err != nil {
		if isUniqueViolation(err) {
			return domain.ErrDPoPReplay
		}
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return fmt.Errorf("consume dpop jti: %w", err)
	}

	if s.metrics != nil && s.metrics.DBOperationDuration != nil {
		s.metrics.DBOperationDuration.Record(ctx, time.Since(start).Seconds(), dbAttrs("dpop_consume_jti"))
	}

	return nil
}

// IssueNonce generates and stores a server nonce with the given TTL.
func (s *DPoPNonceStore) IssueNonce(ctx context.Context, ttl time.Duration) (string, error) {
	ctx, span := s.tracer.Start(ctx, "SQLite.DPoPIssueNonce")
	defer span.End()
	start := time.Now()

	nonce := crypto.GenerateNonce()
	expiresAt := time.Now().Add(ttl)

	_, err := s.db.ExecContext(ctx,
		`INSERT INTO dpop_nonces (nonce, expires_at) VALUES (?, ?)`,
		nonce, formatTime(expiresAt),
	)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return "", fmt.Errorf("issue dpop nonce: %w", err)
	}

	if s.metrics != nil && s.metrics.DBOperationDuration != nil {
		s.metrics.DBOperationDuration.Record(ctx, time.Since(start).Seconds(), dbAttrs("dpop_issue_nonce"))
	}

	return nonce, nil
}

// ValidateNonce checks that a nonce exists and has not expired.
func (s *DPoPNonceStore) ValidateNonce(ctx context.Context, nonce string) error {
	ctx, span := s.tracer.Start(ctx, "SQLite.DPoPValidateNonce")
	defer span.End()
	start := time.Now()

	var expiresAtStr string
	err := s.db.QueryRowContext(ctx,
		`SELECT expires_at FROM dpop_nonces WHERE nonce = ?`, nonce,
	).Scan(&expiresAtStr)
	if err != nil {
		if err == sql.ErrNoRows {
			return domain.ErrDPoPNonceMismatch
		}
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return fmt.Errorf("validate dpop nonce: %w", err)
	}

	expiresAt, err := scanTime(expiresAtStr)
	if err != nil {
		return fmt.Errorf("parse nonce expires_at: %w", err)
	}
	if time.Now().After(expiresAt) {
		return domain.ErrDPoPNonceMismatch
	}

	if s.metrics != nil && s.metrics.DBOperationDuration != nil {
		s.metrics.DBOperationDuration.Record(ctx, time.Since(start).Seconds(), dbAttrs("dpop_validate_nonce"))
	}

	return nil
}

// PurgeExpired removes expired JTIs and nonces from storage.
func (s *DPoPNonceStore) PurgeExpired(ctx context.Context) error {
	ctx, span := s.tracer.Start(ctx, "SQLite.DPoPPurgeExpired")
	defer span.End()
	start := time.Now()

	now := formatTime(time.Now().UTC())

	result, err := s.db.ExecContext(ctx, `DELETE FROM dpop_jtis WHERE expires_at < ?`, now)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return fmt.Errorf("purge expired dpop jtis: %w", err)
	}
	if rows, _ := result.RowsAffected(); rows > 0 {
		s.logger.InfoContext(ctx, "purged expired dpop jtis", "count", rows)
	}

	result, err = s.db.ExecContext(ctx, `DELETE FROM dpop_nonces WHERE expires_at < ?`, now)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return fmt.Errorf("purge expired dpop nonces: %w", err)
	}
	if rows, _ := result.RowsAffected(); rows > 0 {
		s.logger.InfoContext(ctx, "purged expired dpop nonces", "count", rows)
	}

	if s.metrics != nil && s.metrics.DBOperationDuration != nil {
		s.metrics.DBOperationDuration.Record(ctx, time.Since(start).Seconds(), dbAttrs("dpop_purge"))
	}

	return nil
}
