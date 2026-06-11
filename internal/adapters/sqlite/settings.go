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

// RuntimeSettingsStore implements output.RuntimeSettingsStore for SQLite.
type RuntimeSettingsStore struct {
	db      *sql.DB
	logger  *slog.Logger
	tracer  trace.Tracer
	metrics *observability.Metrics
}

var _ output.RuntimeSettingsStore = (*RuntimeSettingsStore)(nil)

// Get returns the value for a setting key. Returns "" if not found.
func (s *RuntimeSettingsStore) Get(ctx context.Context, key string) (string, error) {
	ctx, span := s.tracer.Start(ctx, "SQLite.SettingsGet")
	defer span.End()

	var value string
	err := s.db.QueryRowContext(ctx,
		`SELECT value FROM runtime_settings WHERE key = ?`, key,
	).Scan(&value)
	if err == sql.ErrNoRows {
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
	ctx, span := s.tracer.Start(ctx, "SQLite.SettingsSet")
	defer span.End()

	now := formatTime(time.Now().UTC())
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO runtime_settings (key, value, updated_at)
		 VALUES (?, ?, ?)
		 ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at`,
		key, value, now,
	)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return err
	}
	return nil
}
