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
	"github.com/authplane/authserver/internal/observability"
	"github.com/authplane/authserver/internal/ports/output"
)

var _ output.AssertionJTIStore = (*AssertionJTIStore)(nil)

// AssertionJTIStore implements output.AssertionJTIStore using PostgreSQL.
type AssertionJTIStore struct {
	pool    *pgxpool.Pool
	logger  *slog.Logger
	tracer  trace.Tracer
	metrics *observability.Metrics
}

// ConsumeJTI marks an assertion JTI as used. Returns domain.ErrAssertionReplay if already consumed.
func (s *AssertionJTIStore) ConsumeJTI(ctx context.Context, jti string, expiry time.Time) error {
	ctx, span := s.tracer.Start(ctx, "Postgres.AssertionConsumeJTI")
	defer span.End()
	start := time.Now()

	_, err := dbOrTx(ctx, s.pool).Exec(ctx,
		`INSERT INTO assertion_jtis (jti, expires_at) VALUES ($1, $2)`,
		jti, toUTC(expiry),
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
	ctx, span := s.tracer.Start(ctx, "Postgres.AssertionPurgeExpired")
	defer span.End()
	start := time.Now()

	result, err := dbOrTx(ctx, s.pool).Exec(ctx, `DELETE FROM assertion_jtis WHERE expires_at < NOW()`)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return fmt.Errorf("purge expired assertion jtis: %w", err)
	}
	if rows := result.RowsAffected(); rows > 0 {
		s.logger.InfoContext(ctx, "purged expired assertion jtis", "count", rows)
	}

	if s.metrics != nil && s.metrics.DBOperationDuration != nil {
		s.metrics.DBOperationDuration.Record(ctx, time.Since(start).Seconds(), dbAttrs("assertion_purge"))
	}
	return nil
}
