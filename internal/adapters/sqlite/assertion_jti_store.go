package sqlite

import (
	"context"
	"database/sql"
	"fmt"
	"log/slog"
	"time"

	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"

	"github.com/authplane/authserver/internal/domain"
	"github.com/authplane/authserver/internal/observability"
	"github.com/authplane/authserver/internal/ports/output"
)

var _ output.AssertionJTIStore = (*AssertionJTIStore)(nil)

// AssertionJTIStore implements output.AssertionJTIStore using SQLite.
type AssertionJTIStore struct {
	db      *sql.DB
	logger  *slog.Logger
	tracer  trace.Tracer
	metrics *observability.Metrics
}

// ConsumeJTI marks an assertion JTI as used. Returns domain.ErrAssertionReplay if already consumed.
func (s *AssertionJTIStore) ConsumeJTI(ctx context.Context, jti string, expiry time.Time) error {
	ctx, span := s.tracer.Start(ctx, "SQLite.AssertionConsumeJTI")
	defer span.End()
	start := time.Now()

	_, err := s.db.ExecContext(ctx,
		`INSERT INTO assertion_jtis (jti, expires_at) VALUES (?, ?)`,
		jti, formatTime(expiry),
	)
	if err != nil {
		if isUniqueViolation(err) {
			return domain.ErrAssertionReplay
		}
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return fmt.Errorf("consume assertion jti: %w", err)
	}

	if s.metrics != nil && s.metrics.DBOperationDuration != nil {
		s.metrics.DBOperationDuration.Record(ctx, time.Since(start).Seconds(), dbAttrs("assertion_consume_jti"))
	}
	return nil
}

// PurgeExpired removes expired assertion JTI records from storage.
func (s *AssertionJTIStore) PurgeExpired(ctx context.Context) error {
	ctx, span := s.tracer.Start(ctx, "SQLite.AssertionPurgeExpired")
	defer span.End()
	start := time.Now()

	now := formatTime(time.Now().UTC())
	result, err := s.db.ExecContext(ctx, `DELETE FROM assertion_jtis WHERE expires_at < ?`, now)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return fmt.Errorf("purge expired assertion jtis: %w", err)
	}
	if rows, _ := result.RowsAffected(); rows > 0 {
		s.logger.InfoContext(ctx, "purged expired assertion jtis", "count", rows)
	}

	if s.metrics != nil && s.metrics.DBOperationDuration != nil {
		s.metrics.DBOperationDuration.Record(ctx, time.Since(start).Seconds(), dbAttrs("assertion_purge"))
	}
	return nil
}
