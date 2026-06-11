package postgres

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"

	"github.com/authplane/authserver/internal/observability"
	"github.com/authplane/authserver/internal/ports/output"
)

// RevocationStore implements output.RevocationStore for PostgreSQL.
type RevocationStore struct {
	pool    *pgxpool.Pool
	logger  *slog.Logger
	tracer  trace.Tracer
	metrics *observability.Metrics
}

var _ output.RevocationStore = (*RevocationStore)(nil)

// TrackJTI records that a JTI was issued for a given family with its expiry.
func (s *RevocationStore) TrackJTI(ctx context.Context, jti, familyID string, expiresAt time.Time) error {
	ctx, span := s.tracer.Start(ctx, "Postgres.TrackJTI")
	defer span.End()
	start := time.Now()

	_, err := dbOrTx(ctx, s.pool).Exec(ctx,
		`INSERT INTO access_token_jtis (jti, family_id, expires_at) VALUES ($1, $2, $3)
		 ON CONFLICT (jti) DO NOTHING`,
		jti, familyID, expiresAt.UTC(),
	)

	s.metrics.DBOperationDuration.Record(ctx, time.Since(start).Seconds(), dbAttrs("track_jti"))

	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return err
	}
	return nil
}

// RevokeByFamily adds all JTIs belonging to a family to the blacklist.
func (s *RevocationStore) RevokeByFamily(ctx context.Context, familyID string) error {
	ctx, span := s.tracer.Start(ctx, "Postgres.RevokeByFamily")
	defer span.End()
	start := time.Now()

	_, err := dbOrTx(ctx, s.pool).Exec(ctx,
		`INSERT INTO revoked_jtis (jti, expires_at)
		 SELECT jti, expires_at FROM access_token_jtis WHERE family_id = $1
		 ON CONFLICT (jti) DO NOTHING`,
		familyID,
	)

	s.metrics.DBOperationDuration.Record(ctx, time.Since(start).Seconds(), dbAttrs("revoke_by_family"))

	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return err
	}
	return nil
}

// RevokeJTI adds a single JTI to the blacklist.
func (s *RevocationStore) RevokeJTI(ctx context.Context, jti string) error {
	ctx, span := s.tracer.Start(ctx, "Postgres.RevokeJTI")
	defer span.End()
	start := time.Now()

	// Look up expiry from tracking table; fall back to 1 hour from now.
	var expiresAt time.Time
	err := dbOrTx(ctx, s.pool).QueryRow(ctx,
		`SELECT expires_at FROM access_token_jtis WHERE jti = $1`, jti,
	).Scan(&expiresAt)
	if err != nil {
		expiresAt = time.Now().Add(time.Hour).UTC()
	}

	_, err = dbOrTx(ctx, s.pool).Exec(ctx,
		`INSERT INTO revoked_jtis (jti, expires_at) VALUES ($1, $2)
		 ON CONFLICT (jti) DO NOTHING`,
		jti, expiresAt,
	)

	s.metrics.DBOperationDuration.Record(ctx, time.Since(start).Seconds(), dbAttrs("revoke_jti"))

	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return err
	}
	return nil
}

// IsRevoked checks if a JTI is in the blacklist.
func (s *RevocationStore) IsRevoked(ctx context.Context, jti string) (bool, error) {
	ctx, span := s.tracer.Start(ctx, "Postgres.IsRevoked")
	defer span.End()
	start := time.Now()

	var exists int
	err := dbOrTx(ctx, s.pool).QueryRow(ctx,
		`SELECT 1 FROM revoked_jtis WHERE jti = $1`, jti,
	).Scan(&exists)

	s.metrics.DBOperationDuration.Record(ctx, time.Since(start).Seconds(), dbAttrs("is_revoked"))

	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return false, err
	}
	return true, nil
}

// PurgeExpired removes expired JTI tracking and blacklist entries.
func (s *RevocationStore) PurgeExpired(ctx context.Context) (int64, error) {
	ctx, span := s.tracer.Start(ctx, "Postgres.PurgeExpired")
	defer span.End()
	start := time.Now()

	now := time.Now().UTC()

	res1, err := dbOrTx(ctx, s.pool).Exec(ctx,
		`DELETE FROM access_token_jtis WHERE expires_at < $1`, now,
	)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return 0, err
	}
	n1 := res1.RowsAffected()

	res2, err := dbOrTx(ctx, s.pool).Exec(ctx,
		`DELETE FROM revoked_jtis WHERE expires_at < $1`, now,
	)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return n1, err
	}
	n2 := res2.RowsAffected()

	s.metrics.DBOperationDuration.Record(ctx, time.Since(start).Seconds(), dbAttrs("purge_expired"))

	total := n1 + n2
	if total > 0 {
		s.logger.InfoContext(ctx, "purged expired JTI entries",
			"tracking_deleted", n1,
			"blacklist_deleted", n2,
		)
	}
	return total, nil
}
