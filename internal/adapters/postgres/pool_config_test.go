package postgres

import (
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// TestApplyPoolConfig_AllFieldsPropagate is the unit test: every
// pgx pool knob exposed on PoolConfig must reach the pgxpool.Config the
// pool is built from. Asserts MaxConns + MinConns + MaxConnLifetime +
// MaxConnIdleTime — the four fields the adapter previously only partially
// applied.
func TestApplyPoolConfig_AllFieldsPropagate(t *testing.T) {
	cfg, err := pgxpool.ParseConfig("postgres://user:pass@localhost:5432/db")
	if err != nil {
		t.Fatalf("parse dsn: %v", err)
	}

	want := PoolConfig{
		MaxConns:        25,
		MinConns:        5,
		MaxConnLifetime: time.Hour,
		MaxConnIdleTime: 30 * time.Minute,
	}
	applyPoolConfig(cfg, want)

	if cfg.MaxConns != want.MaxConns {
		t.Errorf("MaxConns: got %d, want %d", cfg.MaxConns, want.MaxConns)
	}
	if cfg.MinConns != want.MinConns {
		t.Errorf("MinConns: got %d, want %d", cfg.MinConns, want.MinConns)
	}
	if cfg.MaxConnLifetime != want.MaxConnLifetime {
		t.Errorf("MaxConnLifetime: got %v, want %v", cfg.MaxConnLifetime, want.MaxConnLifetime)
	}
	if cfg.MaxConnIdleTime != want.MaxConnIdleTime {
		t.Errorf("MaxConnIdleTime: got %v, want %v", cfg.MaxConnIdleTime, want.MaxConnIdleTime)
	}
}

// TestApplyPoolConfig_ZeroValuesPreserveDefaults verifies zero PoolConfig
// fields do not clobber pgx-supplied defaults. This matters because Open()
// is called even when operators leave optional knobs blank in YAML.
func TestApplyPoolConfig_ZeroValuesPreserveDefaults(t *testing.T) {
	cfg, err := pgxpool.ParseConfig("postgres://user:pass@localhost:5432/db")
	if err != nil {
		t.Fatalf("parse dsn: %v", err)
	}
	defaults := PoolConfig{
		MaxConns:        cfg.MaxConns,
		MinConns:        cfg.MinConns,
		MaxConnLifetime: cfg.MaxConnLifetime,
		MaxConnIdleTime: cfg.MaxConnIdleTime,
	}

	applyPoolConfig(cfg, PoolConfig{})

	if cfg.MaxConns != defaults.MaxConns {
		t.Errorf("MaxConns clobbered: got %d, want %d", cfg.MaxConns, defaults.MaxConns)
	}
	if cfg.MinConns != defaults.MinConns {
		t.Errorf("MinConns clobbered: got %d, want %d", cfg.MinConns, defaults.MinConns)
	}
	if cfg.MaxConnLifetime != defaults.MaxConnLifetime {
		t.Errorf("MaxConnLifetime clobbered: got %v, want %v", cfg.MaxConnLifetime, defaults.MaxConnLifetime)
	}
	if cfg.MaxConnIdleTime != defaults.MaxConnIdleTime {
		t.Errorf("MaxConnIdleTime clobbered: got %v, want %v", cfg.MaxConnIdleTime, defaults.MaxConnIdleTime)
	}
}
