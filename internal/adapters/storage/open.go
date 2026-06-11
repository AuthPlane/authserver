// Package storage provides a factory for creating the configured DataStore backend.
package storage

import (
	"context"
	"fmt"

	"github.com/authplane/authserver/internal/adapters/postgres"
	"github.com/authplane/authserver/internal/adapters/sqlite"
	"github.com/authplane/authserver/internal/config"
	"github.com/authplane/authserver/internal/observability"
	"github.com/authplane/authserver/internal/ports/output"
)

// Open creates the storage backend for the configured driver.
// Both sqlite.DB and postgres.DB implement output.DataStore directly.
func Open(ctx context.Context, cfg config.StorageConfig, obs *observability.Provider) (output.DataStore, error) {
	switch cfg.Driver {
	case "sqlite":
		return sqlite.Open(sqlite.DSN(cfg.SQLite.Path), obs.WithComponent("sqlite"))
	case "postgres":
		poolCfg := postgres.PoolConfig{
			MaxConns:        int32(cfg.Postgres.MaxConns), //nolint:gosec // small config value
			MinConns:        int32(cfg.Postgres.MinConns), //nolint:gosec // small config value
			MaxConnLifetime: cfg.Postgres.MaxConnLifetime,
			MaxConnIdleTime: cfg.Postgres.MaxConnIdleTime,
		}
		return postgres.Open(ctx, cfg.Postgres.DSN, poolCfg, obs.WithComponent("postgres"))
	default:
		return nil, fmt.Errorf("unsupported storage driver: %q", cfg.Driver)
	}
}
