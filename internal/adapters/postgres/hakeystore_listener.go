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

const (
	signingKeyChannel      = "signing_key_change"
	listenReconnectMin     = 1 * time.Second
	listenReconnectMax     = 30 * time.Second
	listenFallbackPollTime = 30 * time.Second
)

// keyCacheInvalidator is the seam the listener needs from the key store: a way
// to clear the cached current key on a change notification. The caching
// decorator (signing.WrapKeyStore) satisfies it.
type keyCacheInvalidator interface {
	InvalidateCache(ctx context.Context) error
}

// KeyStoreListener subscribes to PostgreSQL LISTEN/NOTIFY on the
// signing_key_change channel and triggers cache invalidation + JWKS reload.
//
// It uses a raw pgx.Conn (not a pool) because LISTEN requires a persistent
// connection. On disconnect, it reconnects with exponential backoff and
// falls back to polling until the connection is restored.
type KeyStoreListener struct {
	dsn      string
	store    keyCacheInvalidator
	reloadFn func(context.Context) error
	logger   *slog.Logger
	tracer   trace.Tracer
}

// NewKeyStoreListener creates a listener that watches for signing key changes.
// reloadFn is called after cache invalidation (typically JWKSService.Reload).
func NewKeyStoreListener(dsn string, store keyCacheInvalidator, reloadFn func(context.Context) error, obs *observability.Provider) *KeyStoreListener {
	return &KeyStoreListener{
		dsn:      dsn,
		store:    store,
		reloadFn: reloadFn,
		logger:   obs.Logger.With("component", "keystore-listener"),
		tracer:   obs.Tracer,
	}
}

// Run starts the LISTEN loop. It blocks until ctx is canceled.
// On connection failure, it reconnects with exponential backoff and
// polls as a fallback while disconnected.
func (l *KeyStoreListener) Run(ctx context.Context) error {
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

		// Exponential backoff: 1s → 2s → 4s → ... → 30s max.
		backoff *= 2
		if backoff > listenReconnectMax {
			backoff = listenReconnectMax
		}
	}
}

// listenLoop connects, issues LISTEN, and processes notifications until error or ctx cancel.
func (l *KeyStoreListener) listenLoop(ctx context.Context) error {
	conn, err := pgx.Connect(ctx, l.dsn)
	if err != nil {
		return fmt.Errorf("connect: %w", err)
	}
	defer func() { _ = conn.Close(ctx) }()

	if _, err := conn.Exec(ctx, "LISTEN "+signingKeyChannel); err != nil {
		return fmt.Errorf("LISTEN: %w", err)
	}

	l.logger.InfoContext(ctx, "listening for signing key changes")

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

// handleNotification invalidates cache and triggers JWKS reload.
func (l *KeyStoreListener) handleNotification(ctx context.Context, kid string) {
	ctx, span := l.tracer.Start(ctx, "KeyStoreListener.HandleNotification")
	defer span.End()

	l.logger.InfoContext(ctx, "received signing key change notification", "kid", kid)

	if err := l.store.InvalidateCache(ctx); err != nil {
		// In-memory invalidation never fails; an out-of-tree cache might, leaving
		// the stale current key served until the next notification/reload.
		l.logger.WarnContext(ctx, "cache invalidation after notification failed", "kid", kid, "error", err)
	}

	start := time.Now()
	if err := l.reloadFn(ctx); err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		l.logger.ErrorContext(ctx, "JWKS reload after notification failed", "error", err)
		return
	}
	duration := time.Since(start)
	l.logger.InfoContext(ctx, "JWKS reloaded after notification",
		"kid", kid, "reload_duration", duration,
	)
}

// fallbackPoll does a single cache-invalidate + reload as a fallback
// while the LISTEN connection is down.
func (l *KeyStoreListener) fallbackPoll(ctx context.Context, waitDuration time.Duration) {
	// Only poll if the backoff is long enough that we might miss changes.
	if waitDuration < listenFallbackPollTime {
		return
	}

	l.logger.DebugContext(ctx, "fallback poll: invalidating cache and reloading")
	if err := l.store.InvalidateCache(ctx); err != nil {
		l.logger.WarnContext(ctx, "fallback poll cache invalidation failed", "error", err)
	}
	if err := l.reloadFn(ctx); err != nil {
		l.logger.WarnContext(ctx, "fallback poll reload failed", "error", err)
	}
}
