package sqlite

import (
	"context"
	"database/sql"
	"log/slog"
	"time"

	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"

	"github.com/authplane/authserver/internal/observability"
	"github.com/authplane/authserver/internal/ports/output"
)

// RevocationStore implements output.RevocationStore for SQLite.
type RevocationStore struct {
	db      *sql.DB
	logger  *slog.Logger
	tracer  trace.Tracer
	metrics *observability.Metrics
}

var _ output.RevocationStore = (*RevocationStore)(nil)

// TrackJTI records that a JTI was issued for a given family with its expiry.
func (s *RevocationStore) TrackJTI(ctx context.Context, jti, familyID string, expiresAt time.Time) error {
	ctx, span := s.tracer.Start(ctx, "SQLite.TrackJTI")
	defer span.End()
	start := time.Now()

	_, err := dbOrTx(ctx, s.db).ExecContext(ctx,
		`INSERT OR IGNORE INTO access_token_jtis (jti, family_id, expires_at) VALUES (?, ?, ?)`,
		jti, familyID, formatTime(expiresAt),
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
	ctx, span := s.tracer.Start(ctx, "SQLite.RevokeByFamily")
	defer span.End()
	start := time.Now()

	_, err := dbOrTx(ctx, s.db).ExecContext(ctx,
		`INSERT OR IGNORE INTO revoked_jtis (jti, expires_at)
		 SELECT jti, expires_at FROM access_token_jtis WHERE family_id = ?`,
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
	ctx, span := s.tracer.Start(ctx, "SQLite.RevokeJTI")
	defer span.End()
	start := time.Now()

	// Look up expiry from tracking table; fall back to 1 hour from now.
	var expiresAt string
	err := dbOrTx(ctx, s.db).QueryRowContext(ctx,
		`SELECT expires_at FROM access_token_jtis WHERE jti = ?`, jti,
	).Scan(&expiresAt)
	if err != nil {
		expiresAt = formatTime(time.Now().Add(time.Hour))
	}

	_, err = dbOrTx(ctx, s.db).ExecContext(ctx,
		`INSERT OR IGNORE INTO revoked_jtis (jti, expires_at) VALUES (?, ?)`,
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
	ctx, span := s.tracer.Start(ctx, "SQLite.IsRevoked")
	defer span.End()
	start := time.Now()

	var exists int
	err := dbOrTx(ctx, s.db).QueryRowContext(ctx,
		`SELECT 1 FROM revoked_jtis WHERE jti = ?`, jti,
	).Scan(&exists)

	s.metrics.DBOperationDuration.Record(ctx, time.Since(start).Seconds(), dbAttrs("is_revoked"))

	if err == sql.ErrNoRows {
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
	ctx, span := s.tracer.Start(ctx, "SQLite.PurgeExpired")
	defer span.End()
	start := time.Now()

	now := formatTime(time.Now())

	res1, err := dbOrTx(ctx, s.db).ExecContext(ctx,
		`DELETE FROM access_token_jtis WHERE expires_at < ?`, now,
	)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return 0, err
	}
	n1, _ := res1.RowsAffected()

	res2, err := dbOrTx(ctx, s.db).ExecContext(ctx,
		`DELETE FROM revoked_jtis WHERE expires_at < ?`, now,
	)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return n1, err
	}
	n2, _ := res2.RowsAffected()

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
