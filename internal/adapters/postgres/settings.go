package postgres

import (
	"context"
	"errors"
	"log/slog"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"

	"github.com/authplane/authserver/internal/observability"
	"github.com/authplane/authserver/internal/ports/output"
)

// RuntimeSettingsStore implements output.RuntimeSettingsStore for PostgreSQL.
type RuntimeSettingsStore struct {
	pool    *pgxpool.Pool
	logger  *slog.Logger
	tracer  trace.Tracer
	metrics *observability.Metrics
}

var _ output.RuntimeSettingsStore = (*RuntimeSettingsStore)(nil)

// Get returns the value for a setting key. Returns "" if not found.
func (s *RuntimeSettingsStore) Get(ctx context.Context, key string) (string, error) {
	ctx, span := s.tracer.Start(ctx, "PostgreSQL.SettingsGet")
	defer span.End()

	var value string
	err := dbOrTx(ctx, s.pool).QueryRow(ctx,
		`SELECT value FROM runtime_settings WHERE key = $1`, key,
	).Scan(&value)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", nil
	}
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return "", err
	}
	return value, nil
}

// Set persists a setting key-value pair (upsert).
func (s *RuntimeSettingsStore) Set(ctx context.Context, key, value string) error {
	ctx, span := s.tracer.Start(ctx, "PostgreSQL.SettingsSet")
	defer span.End()

	_, err := dbOrTx(ctx, s.pool).Exec(ctx,
		`INSERT INTO runtime_settings (key, value, updated_at)
		 VALUES ($1, $2, NOW())
		 ON CONFLICT(key) DO UPDATE SET value = EXCLUDED.value, updated_at = NOW()`,
		key, value,
	)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return err
	}
	return nil
}
