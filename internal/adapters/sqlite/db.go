// Package sqlite provides SQLite implementations of the output port interfaces.
package sqlite

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"go.opentelemetry.io/otel/attribute"
	otelmetric "go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/trace"

	"github.com/authplane/authserver/internal/observability"
	"github.com/authplane/authserver/internal/ports/output"
	migrations "github.com/authplane/authserver/migrations/sqlite"

	// SQLite driver (pure Go, no CGO).
	_ "modernc.org/sqlite"
)

// DB wraps a *sql.DB with helpers and migration support.
// It implements output.DataStore.
type DB struct {
	DB      *sql.DB
	stores  *Stores
	logger  *slog.Logger
	tracer  trace.Tracer
	metrics *observability.Metrics
}

var _ output.DataStore = (*DB)(nil)

// Stores groups all SQLite store implementations.
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

// Open creates a new SQLite connection with appropriate pragmas.
func Open(dsn string, obs *observability.Provider) (*DB, error) {
	// Extract the file path from the DSN (before any query parameters) and
	// ensure the parent directory exists. Skip for in-memory databases.
	filePath := strings.SplitN(dsn, "?", 2)[0]
	if filePath != "" && filePath != ":memory:" {
		if err := os.MkdirAll(filepath.Dir(filePath), 0o750); err != nil {
			return nil, fmt.Errorf("create db directory: %w", err)
		}
	}

	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("sqlite open: %w", err)
	}

	// SQLite single-writer model: 1 connection avoids SQLITE_BUSY.
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)

	ctx := context.Background()
	if err := db.PingContext(ctx); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("sqlite ping: %w", err)
	}

	// Enable foreign keys and WAL mode regardless of DSN (covers :memory:).
	for _, pragma := range []string{
		"PRAGMA foreign_keys = ON",
		"PRAGMA journal_mode = WAL",
		"PRAGMA busy_timeout = 5000",
	} {
		if _, err := db.ExecContext(ctx, pragma); err != nil {
			_ = db.Close()
			return nil, fmt.Errorf("exec %s: %w", pragma, err)
		}
	}

	d := &DB{
		DB:      db,
		logger:  obs.Logger.With("component", "sqlite"),
		tracer:  obs.Tracer,
		metrics: obs.Metrics,
	}
	d.stores = d.NewStores()
	return d, nil
}

// DSN builds a SQLite DSN with WAL mode and foreign keys enabled.
func DSN(path string) string {
	return path + "?_pragma=journal_mode(wal)&_pragma=foreign_keys(1)&_pragma=busy_timeout(5000)"
}

// Migrate runs all pending SQL migrations from the embedded FS.
func (d *DB) Migrate(ctx context.Context) error {
	// Ensure schema_migrations table exists.
	if _, err := d.DB.ExecContext(ctx,
		`CREATE TABLE IF NOT EXISTS schema_migrations (
			version INTEGER PRIMARY KEY,
			applied_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%f', 'now'))
		)`); err != nil {
		return fmt.Errorf("create schema_migrations: %w", err)
	}

	// Get current version.
	var current int
	if err := d.DB.QueryRowContext(ctx,
		`SELECT COALESCE(MAX(version), 0) FROM schema_migrations`).Scan(&current); err != nil {
		return fmt.Errorf("get current version: %w", err)
	}

	// Discover available migrations.
	entries, err := fs.ReadDir(migrations.Migrations, ".")
	if err != nil {
		return fmt.Errorf("read migration dir: %w", err)
	}

	// Collect up migrations sorted by version.
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

		tx, err := d.DB.BeginTx(ctx, nil)
		if err != nil {
			return fmt.Errorf("begin tx for %s: %w", m.name, err)
		}

		if _, err := tx.ExecContext(ctx, string(data)); err != nil {
			_ = tx.Rollback()
			return fmt.Errorf("exec migration %s: %w", m.name, err)
		}

		if _, err := tx.ExecContext(ctx,
			`INSERT INTO schema_migrations (version) VALUES (?)`, m.version); err != nil {
			_ = tx.Rollback()
			return fmt.Errorf("record migration %d: %w", m.version, err)
		}

		if err := tx.Commit(); err != nil {
			return fmt.Errorf("commit migration %s: %w", m.name, err)
		}

		d.logger.InfoContext(ctx, "applied migration", "version", m.version, "file", m.name)
	}

	return nil
}

// NewStores returns all store implementations sharing this DB connection.
func (d *DB) NewStores() *Stores {
	return &Stores{
		Client:              &ClientStore{db: d.DB, logger: d.logger, tracer: d.tracer, metrics: d.metrics},
		User:                &UserStore{db: d.DB, logger: d.logger, tracer: d.tracer, metrics: d.metrics},
		Session:             &SessionStore{db: d.DB, logger: d.logger, tracer: d.tracer, metrics: d.metrics},
		Token:               &TokenStore{db: d.DB, logger: d.logger, tracer: d.tracer, metrics: d.metrics},
		Audit:               &AuditStore{db: d.DB, logger: d.logger, tracer: d.tracer, metrics: d.metrics},
		Revocation:          &RevocationStore{db: d.DB, logger: d.logger, tracer: d.tracer, metrics: d.metrics},
		MachineToken:        &MachineTokenStore{db: d.DB, logger: d.logger, tracer: d.tracer, metrics: d.metrics},
		DPoPNonce:           &DPoPNonceStore{db: d.DB, logger: d.logger, tracer: d.tracer, metrics: d.metrics},
		RuntimeSettings:     &RuntimeSettingsStore{db: d.DB, logger: d.logger, tracer: d.tracer, metrics: d.metrics},
		IDP:                 &IDPStore{db: d.DB, logger: d.logger, tracer: d.tracer, metrics: d.metrics},
		AssertionJTI:        &AssertionJTIStore{db: d.DB, logger: d.logger, tracer: d.tracer, metrics: d.metrics},
		XAAPolicy:           &XAAPolicyStore{db: d.DB, logger: d.logger, tracer: d.tracer, metrics: d.metrics},
		SubjectMapping:      &SubjectMappingStore{db: d.DB, logger: d.logger, tracer: d.tracer, metrics: d.metrics},
		Resource:            &ResourceStore{db: d.DB, logger: d.logger, tracer: d.tracer, metrics: d.metrics},
		BrokerProvider:      &BrokerProviderStore{db: d.DB, logger: d.logger, tracer: d.tracer, metrics: d.metrics},
		ConsentGrant:        &ConsentGrantStore{db: d.DB, logger: d.logger, tracer: d.tracer, metrics: d.metrics},
		BrokerGrant:         &BrokerGrantStore{db: d.DB, logger: d.logger, tracer: d.tracer, metrics: d.metrics},
		Issuance:            &IssuanceStore{db: d.DB, logger: d.logger, tracer: d.tracer, metrics: d.metrics},
		ConnectPendingState: &ConnectPendingStateStore{db: d.DB, logger: d.logger, tracer: d.tracer, metrics: d.metrics},
		FrontingLink:        &FrontingLinkStore{db: d.DB, logger: d.logger, tracer: d.tracer, metrics: d.metrics},
		TransactionMgr:      &TransactionManager{db: d.DB},
	}
}

// Close closes the underlying database connection.
func (d *DB) Close() error {
	return d.DB.Close()
}

// Ping verifies the database connection is alive.
func (d *DB) Ping(ctx context.Context) error {
	return d.DB.PingContext(ctx)
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
		attribute.String("store", "sqlite"),
	)
}

// formatTime formats a time.Time as RFC3339Nano for storage.
func formatTime(t time.Time) string {
	return t.UTC().Format(time.RFC3339Nano)
}

// scanTime parses an RFC3339Nano string from the database.
func scanTime(s string) (time.Time, error) {
	return time.Parse(time.RFC3339Nano, s)
}

// formatNullableTime formats a *time.Time as a sql.NullString.
func formatNullableTime(t *time.Time) sql.NullString {
	if t == nil {
		return sql.NullString{}
	}
	return sql.NullString{String: t.UTC().Format(time.RFC3339Nano), Valid: true}
}

// scanNullableTime parses a nullable RFC3339Nano column into *time.Time.
func scanNullableTime(ns sql.NullString) (*time.Time, error) {
	if !ns.Valid {
		return nil, nil
	}
	t, err := time.Parse(time.RFC3339Nano, ns.String)
	if err != nil {
		return nil, err
	}
	return &t, nil
}

// marshalStringSlice encodes a []string as JSON for storage.
func marshalStringSlice(ss []string) string {
	if ss == nil {
		ss = []string{}
	}
	data, _ := json.Marshal(ss)
	return string(data)
}

// unmarshalStringSlice decodes a JSON array string into []string.
func unmarshalStringSlice(s string) ([]string, error) {
	var ss []string
	if err := json.Unmarshal([]byte(s), &ss); err != nil {
		return nil, err
	}
	return ss, nil
}

// isUniqueViolation checks if the error is a SQLite UNIQUE constraint violation.
func isUniqueViolation(err error) bool {
	if err == nil {
		return false
	}
	return strings.Contains(err.Error(), "UNIQUE constraint failed")
}
