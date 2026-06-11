package postgres

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"

	"github.com/authplane/authserver/internal/observability"
)

// ConfigChangeListener subscribes to PostgreSQL LISTEN/NOTIFY on a named channel
// and triggers a reload callback when changes are detected.
//
// It uses a raw pgx.Conn (not a pool) because LISTEN requires a persistent
// connection. On disconnect, it reconnects with exponential backoff and
// falls back to polling until the connection is restored.
type ConfigChangeListener struct {
	dsn      string
	channel  string
	reloadFn func(context.Context) error
	logger   *slog.Logger
	tracer   trace.Tracer
}

// NewConfigChangeListener creates a listener that watches for config changes
// on the given PostgreSQL NOTIFY channel.
// reloadFn is called when a notification is received (typically CachedXxx.Reload).
func NewConfigChangeListener(
	dsn string,
	channel string,
	reloadFn func(context.Context) error,
	obs *observability.Provider,
) *ConfigChangeListener {
	return &ConfigChangeListener{
		dsn:      dsn,
		channel:  channel,
		reloadFn: reloadFn,
		logger:   obs.Logger.With("component", "config-listener", "channel", channel),
		tracer:   obs.Tracer,
	}
}

// Run starts the LISTEN loop. It blocks until ctx is canceled.
// On connection failure, it reconnects with exponential backoff and
// polls as a fallback while disconnected.
func (l *ConfigChangeListener) Run(ctx context.Context) error {
	backoff := listenReconnectMin

	for {
		if ctx.Err() != nil {
			return ctx.Err()
		}

		err := l.listenLoop(ctx)
		if ctx.Err() != nil {
			return ctx.Err()
		}

		// Connection lost — log and start fallback polling + reconnect.
		l.logger.WarnContext(ctx, "LISTEN connection lost, reconnecting",
			"error", err, "backoff", backoff,
		)

		// Fallback poll while waiting for reconnect backoff.
		l.fallbackPoll(ctx, backoff)

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(backoff):
		}

		// Exponential backoff: 1s -> 2s -> 4s -> ... -> 30s max.
		backoff *= 2
		if backoff > listenReconnectMax {
			backoff = listenReconnectMax
		}
	}
}

// listenLoop connects, issues LISTEN, and processes notifications until error or ctx cancel.
func (l *ConfigChangeListener) listenLoop(ctx context.Context) error {
	conn, err := pgx.Connect(ctx, l.dsn)
	if err != nil {
		return fmt.Errorf("connect: %w", err)
	}
	defer func() { _ = conn.Close(ctx) }()

	if _, err := conn.Exec(ctx, "LISTEN "+l.channel); err != nil {
		return fmt.Errorf("LISTEN: %w", err)
	}

	l.logger.InfoContext(ctx, "listening for config changes")

	for {
		notification, err := conn.WaitForNotification(ctx)
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return fmt.Errorf("wait for notification: %w", err)
		}

		l.handleNotification(ctx, notification.Payload)
	}
}

// handleNotification triggers a cache reload.
func (l *ConfigChangeListener) handleNotification(ctx context.Context, payload string) {
	ctx, span := l.tracer.Start(ctx, "ConfigChangeListener.HandleNotification")
	defer span.End()

	l.logger.InfoContext(ctx, "received config change notification", "payload", payload)

	start := time.Now()
	if err := l.reloadFn(ctx); err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		l.logger.ErrorContext(ctx, "reload after notification failed", "error", err)
		return
	}
	duration := time.Since(start)
	l.logger.InfoContext(ctx, "config reloaded after notification",
		"payload", payload, "reload_duration", duration,
	)
}

// fallbackPoll does a single reload as a fallback while the LISTEN connection is down.
func (l *ConfigChangeListener) fallbackPoll(ctx context.Context, waitDuration time.Duration) {
	// Only poll if the backoff is long enough that we might miss changes.
	if waitDuration < listenFallbackPollTime {
		return
	}

	l.logger.DebugContext(ctx, "fallback poll: reloading config")
	if err := l.reloadFn(ctx); err != nil {
		l.logger.WarnContext(ctx, "fallback poll reload failed", "error", err)
	}
}
