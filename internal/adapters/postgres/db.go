// Package postgres provides PostgreSQL implementations of the output port interfaces.
package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"sort"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"go.opentelemetry.io/otel/attribute"
	otelmetric "go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/trace"

	"github.com/authplane/authserver/internal/observability"
	"github.com/authplane/authserver/internal/ports/output"
	migrations "github.com/authplane/authserver/migrations/postgres"
)

// DB wraps a pgxpool.Pool with helpers and migration support.
// It implements output.DataStore.
type DB struct {
	Pool    *pgxpool.Pool
	stores  *Stores
	logger  *slog.Logger
	tracer  trace.Tracer
	metrics *observability.Metrics
}

var _ output.DataStore = (*DB)(nil)

// Stores groups all PostgreSQL store implementations.
type Stores struct {
	Client              *ClientStore
	User                *UserStore
	Session             *SessionStore
	Token               *TokenStore
	Audit               *AuditStore
	Revocation          *RevocationStore
	MachineToken        *MachineTokenStore
	DPoPNonce           *DPoPNonceStore
	RuntimeSettings     *RuntimeSettingsStore
	IDP                 *IDPStore
	AssertionJTI        *AssertionJTIStore
	XAAPolicy           *XAAPolicyStore
	SubjectMapping      *SubjectMappingStore
	Resource            *ResourceStore
	BrokerProvider      *BrokerProviderStore
	ConsentGrant        *ConsentGrantStore
	BrokerGrant         *BrokerGrantStore
	Issuance            *IssuanceStore
	ConnectPendingState *ConnectPendingStateStore
	FrontingLink        *FrontingLinkStore
	TransactionMgr      *TransactionManager
}

// PoolConfig captures the pool-tuning knobs the storage layer exposes.
// Zero values are left as pgx's defaults.
type PoolConfig struct {
	MaxConns        int32
	MinConns        int32
	MaxConnLifetime time.Duration
	MaxConnIdleTime time.Duration
}

// Open creates a new PostgreSQL connection pool with the given DSN.
// The pool is configured from PoolConfig; zero values use pgx defaults.
func Open(ctx context.Context, dsn string, poolCfg PoolConfig, obs *observability.Provider) (*DB, error) {
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, fmt.Errorf("parse postgres dsn: %w", err)
	}

	applyPoolConfig(cfg, poolCfg)

	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("create postgres pool: %w", err)
	}

	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("postgres ping: %w", err)
	}

	d := &DB{
		Pool:    pool,
		logger:  obs.Logger.With("component", "postgres"),
		tracer:  obs.Tracer,
		metrics: obs.Metrics,
	}
	d.stores = d.NewStores()
	return d, nil
}

// Migrate runs all pending SQL migrations from the embedded FS.
func (d *DB) Migrate(ctx context.Context) error {
	// Ensure schema_migrations table exists.
	if _, err := d.Pool.Exec(ctx,
		`CREATE TABLE IF NOT EXISTS schema_migrations (
			version    INTEGER PRIMARY KEY,
			applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
		)`); err != nil {
		return fmt.Errorf("create schema_migrations: %w", err)
	}

	// Get current version.
	var current int
	if err := d.Pool.QueryRow(ctx,
		`SELECT COALESCE(MAX(version), 0) FROM schema_migrations`,
	).Scan(&current); err != nil {
		return fmt.Errorf("get current version: %w", err)
	}

	// Discover available migrations.
	entries, err := fs.ReadDir(migrations.Migrations, ".")
	if err != nil {
		return fmt.Errorf("read migration dir: %w", err)
	}

	type mig struct {
		version int
		name    string
	}
	var pending []mig
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".up.sql") {
			continue
		}
		var v int
		if _, err := fmt.Sscanf(e.Name(), "%d_", &v); err != nil {
			continue
		}
		if v > current {
			pending = append(pending, mig{version: v, name: e.Name()})
		}
	}
	sort.Slice(pending, func(i, j int) bool { return pending[i].version < pending[j].version })

	for _, m := range pending {
		data, err := fs.ReadFile(migrations.Migrations, m.name)
		if err != nil {
			return fmt.Errorf("read migration %s: %w", m.name, err)
		}

		tx, err := d.Pool.Begin(ctx)
		if err != nil {
			return fmt.Errorf("begin tx for %s: %w", m.name, err)
		}

		if _, err := tx.Exec(ctx, string(data)); err != nil {
			_ = tx.Rollback(ctx)
			return fmt.Errorf("exec migration %s: %w", m.name, err)
		}

		if _, err := tx.Exec(ctx,
			`INSERT INTO schema_migrations (version) VALUES ($1)`, m.version); err != nil {
			_ = tx.Rollback(ctx)
			return fmt.Errorf("record migration %d: %w", m.version, err)
		}

		if err := tx.Commit(ctx); err != nil {
			return fmt.Errorf("commit migration %s: %w", m.name, err)
		}

		d.logger.InfoContext(ctx, "applied migration", "version", m.version, "file", m.name)
	}

	return nil
}

// NewStores returns all store implementations sharing this pool.
func (d *DB) NewStores() *Stores {
	return &Stores{
		Client:              &ClientStore{pool: d.Pool, logger: d.logger, tracer: d.tracer, metrics: d.metrics},
		User:                &UserStore{pool: d.Pool, logger: d.logger, tracer: d.tracer, metrics: d.metrics},
		Session:             &SessionStore{pool: d.Pool, logger: d.logger, tracer: d.tracer, metrics: d.metrics},
		Token:               &TokenStore{pool: d.Pool, logger: d.logger, tracer: d.tracer, metrics: d.metrics},
		Audit:               &AuditStore{pool: d.Pool, logger: d.logger, tracer: d.tracer, metrics: d.metrics},
		Revocation:          &RevocationStore{pool: d.Pool, logger: d.logger, tracer: d.tracer, metrics: d.metrics},
		MachineToken:        &MachineTokenStore{pool: d.Pool, logger: d.logger, tracer: d.tracer, metrics: d.metrics},
		DPoPNonce:           &DPoPNonceStore{pool: d.Pool, logger: d.logger, tracer: d.tracer, metrics: d.metrics},
		RuntimeSettings:     &RuntimeSettingsStore{pool: d.Pool, logger: d.logger, tracer: d.tracer, metrics: d.metrics},
		IDP:                 &IDPStore{pool: d.Pool, logger: d.logger, tracer: d.tracer, metrics: d.metrics},
		AssertionJTI:        &AssertionJTIStore{pool: d.Pool, logger: d.logger, tracer: d.tracer, metrics: d.metrics},
		XAAPolicy:           &XAAPolicyStore{pool: d.Pool, logger: d.logger, tracer: d.tracer, metrics: d.metrics},
		SubjectMapping:      &SubjectMappingStore{pool: d.Pool, logger: d.logger, tracer: d.tracer, metrics: d.metrics},
		Resource:            &ResourceStore{pool: d.Pool, logger: d.logger, tracer: d.tracer, metrics: d.metrics},
		BrokerProvider:      &BrokerProviderStore{pool: d.Pool, logger: d.logger, tracer: d.tracer, metrics: d.metrics},
		ConsentGrant:        &ConsentGrantStore{pool: d.Pool, logger: d.logger, tracer: d.tracer, metrics: d.metrics},
		BrokerGrant:         &BrokerGrantStore{pool: d.Pool, logger: d.logger, tracer: d.tracer, metrics: d.metrics},
		Issuance:            &IssuanceStore{pool: d.Pool, logger: d.logger, tracer: d.tracer, metrics: d.metrics},
		ConnectPendingState: &ConnectPendingStateStore{pool: d.Pool, logger: d.logger, tracer: d.tracer, metrics: d.metrics},
		FrontingLink:        &FrontingLinkStore{pool: d.Pool, logger: d.logger, tracer: d.tracer, metrics: d.metrics},
		TransactionMgr:      &TransactionManager{pool: d.Pool},
	}
}

// applyPoolConfig propagates non-zero PoolConfig fields onto a parsed
// pgxpool.Config. Used by Open(); also reused by tests that want to
// assert the config wiring without spinning up a pool.
func applyPoolConfig(cfg *pgxpool.Config, p PoolConfig) {
	if p.MaxConns > 0 {
		cfg.MaxConns = p.MaxConns
	}
	if p.MinConns > 0 {
		cfg.MinConns = p.MinConns
	}
	if p.MaxConnLifetime > 0 {
		cfg.MaxConnLifetime = p.MaxConnLifetime
	}
	if p.MaxConnIdleTime > 0 {
		cfg.MaxConnIdleTime = p.MaxConnIdleTime
	}
}

// WrapPool creates a DB using an externally-managed pool.
// Intended for tests where the pool lifecycle is controlled externally.
func WrapPool(pool *pgxpool.Pool, obs *observability.Provider) *DB {
	d := &DB{
		Pool:    pool,
		logger:  obs.Logger.With("component", "postgres"),
		tracer:  obs.Tracer,
		metrics: obs.Metrics,
	}
	d.stores = d.NewStores()
	return d
}

// Close closes the connection pool.
func (d *DB) Close() error {
	d.Pool.Close()
	return nil
}

// Ping verifies the database connection is alive.
func (d *DB) Ping(ctx context.Context) error {
	return d.Pool.Ping(ctx)
}

// --- output.DataStore accessor methods ---

// Client returns the client store.
func (d *DB) Client() output.ClientStore { return d.stores.Client }

// User returns the user store.
func (d *DB) User() output.UserStore { return d.stores.User }

// Session returns the session store.
func (d *DB) Session() output.SessionStore { return d.stores.Session }

// Token returns the token store.
func (d *DB) Token() output.TokenStore { return d.stores.Token }

// Audit returns the audit store.
func (d *DB) Audit() output.AuditStore { return d.stores.Audit }

// Revocation returns the revocation store.
func (d *DB) Revocation() output.RevocationStore { return d.stores.Revocation }

// MachineToken returns the machine token store.
func (d *DB) MachineToken() output.MachineTokenStore { return d.stores.MachineToken }

// DPoPNonce returns the DPoP nonce store.
func (d *DB) DPoPNonce() output.DPoPNonceStore { return d.stores.DPoPNonce }

// RuntimeSettings returns the runtime settings store.
func (d *DB) RuntimeSettings() output.RuntimeSettingsStore { return d.stores.RuntimeSettings }

// IDP returns the identity provider store.
func (d *DB) IDP() output.IDPStore { return d.stores.IDP }

// AssertionJTI returns the assertion JTI store.
func (d *DB) AssertionJTI() output.AssertionJTIStore { return d.stores.AssertionJTI }

// XAAPolicy returns the XAA policy store.
func (d *DB) XAAPolicy() output.XAAPolicyStore { return d.stores.XAAPolicy }

// SubjectMapping returns the subject mapping store.
func (d *DB) SubjectMapping() output.SubjectMappingStore { return d.stores.SubjectMapping }

// Resource returns the unified Resource store.
func (d *DB) Resource() output.ResourceStore { return d.stores.Resource }

// BrokerProvider returns the BrokerProvider store.
func (d *DB) BrokerProvider() output.BrokerProviderStore { return d.stores.BrokerProvider }

// ConsentGrant returns the unified ConsentGrant store.
func (d *DB) ConsentGrant() output.ConsentGrantStore { return d.stores.ConsentGrant }

// BrokerGrant returns the BrokerGrant store.
func (d *DB) BrokerGrant() output.BrokerGrantStore { return d.stores.BrokerGrant }

// Issuance returns the unified IssuanceStore.
func (d *DB) Issuance() output.IssuanceStore { return d.stores.Issuance }

// ConnectPendingState returns the ConnectPendingStateStore.
func (d *DB) ConnectPendingState() output.ConnectPendingStateStore {
	return d.stores.ConnectPendingState
}

// FrontingLink returns the FrontingLinkStore.
func (d *DB) FrontingLink() output.FrontingLinkStore { return d.stores.FrontingLink }

// Transaction returns the transaction manager.
func (d *DB) Transaction() output.TransactionManager { return d.stores.TransactionMgr }

// --- Shared helpers ---

// dbAttrs returns OTel metric attributes for DB operation timing.
func dbAttrs(operation string) otelmetric.MeasurementOption {
	return otelmetric.WithAttributes(
		attribute.String("operation", operation),
		attribute.String("store", "postgres"),
	)
}

// isUniqueViolation checks if the error is a PostgreSQL unique constraint violation (code 23505).
func isUniqueViolation(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "23505"
}

// isNoRows checks if the error is pgx.ErrNoRows.
func isNoRows(err error) bool {
	return errors.Is(err, pgx.ErrNoRows)
}

// marshalStringSlice encodes a []string as JSON for JSONB storage.
func marshalStringSlice(ss []string) []byte {
	if ss == nil {
		ss = []string{}
	}
	data, _ := json.Marshal(ss)
	return data
}

// unmarshalStringSlice decodes a JSONB-scanned []byte into []string.
func unmarshalStringSlice(data []byte) ([]string, error) {
	var ss []string
	if err := json.Unmarshal(data, &ss); err != nil {
		return nil, err
	}
	return ss, nil
}

// toUTC returns t in UTC, or a zero time if t is already zero.
func toUTC(t time.Time) time.Time {
	return t.UTC()
}
