// Package signing provides a factory for creating the configured KeyStore backend.
// This follows the same pattern as internal/adapters/storage/open.go.
package signing

import (
	"context"
	"fmt"
	"io"

	"github.com/authplane/authserver/internal/adapters/cache"
	"github.com/authplane/authserver/internal/adapters/hcvault"
	"github.com/authplane/authserver/internal/adapters/keyfile"
	"github.com/authplane/authserver/internal/adapters/postgres"
	"github.com/authplane/authserver/internal/config"
	"github.com/authplane/authserver/internal/observability"
	"github.com/authplane/authserver/internal/ports/output"
)

// openOptions holds optional dependencies threaded into the chosen KeyStore.
type openOptions struct {
	signingKeyCache output.Cache[*output.SigningKey]
}

// Option configures Open.
type Option func(*openOptions)

// WithSigningKeyCache injects the cache for the current signing key. It is
// threaded into the caching decorator (WrapKeyStore) for the postgres_key
// backend; other drivers ignore it. The default is a process-global single-slot
// cache.
func WithSigningKeyCache(c output.Cache[*output.SigningKey]) Option {
	return func(o *openOptions) { o.signingKeyCache = c }
}

// OpenResult holds the factory output.
type OpenResult struct {
	// Store is the KeyStore implementation.
	Store output.KeyStore

	// Closer holds a resource that must be closed on shutdown.
	// Non-nil for vault_transit (Vault client cleanup).
	Closer io.Closer

	// RunNotify starts a LISTEN/NOTIFY listener goroutine (postgres_key only).
	// The reload func is called when a key change notification arrives.
	// nil for drivers that don't support push notifications.
	RunNotify func(ctx context.Context, reload func(context.Context) error)
}

// Open creates the KeyStore for the configured signing driver.
//
// Parameters:
//   - ds: the DataStore (used to extract a pgxpool.Pool for postgres_key; may be nil)
//   - encryptor: the DataEncryptor (may be nil if data_encryption is not configured)
//
// Driver-specific details (Postgres pool, Vault client sharing) are resolved
// internally via type assertions — callers pass generic interfaces only.
func Open(ctx context.Context, cfg *config.Config, ds output.DataStore, encryptor output.DataEncryptor, obs *observability.Provider, opts ...Option) (*OpenResult, error) {
	var o openOptions
	for _, opt := range opts {
		opt(&o)
	}

	switch cfg.Signing.KeyStore {
	case "keyfile", "":
		store, err := keyfile.New(cfg.Signing.KeyPath, obs.WithComponent("keyfile"))
		if err != nil {
			return nil, fmt.Errorf("keyfile store: %w", err)
		}
		return &OpenResult{Store: store}, nil

	case "vault_transit":
		return openVaultTransit(ctx, cfg, encryptor, obs)

	case "postgres_key":
		return openPostgresKey(cfg, ds, encryptor, obs, &o)

	default:
		return nil, fmt.Errorf("unsupported signing.key_store: %q", cfg.Signing.KeyStore)
	}
}

// openVaultTransit creates a Vault Transit KeyStore with its client.
// If encryptor is an *hcvault.Encryptor targeting the same address+mount,
// its client is reused.
func openVaultTransit(ctx context.Context, cfg *config.Config, encryptor output.DataEncryptor, obs *observability.Provider) (*OpenResult, error) {
	vt := cfg.Signing.VaultTransit

	// Try to reuse the encryption client if it targets the same Vault.
	if enc, ok := encryptor.(*hcvault.Encryptor); ok {
		c := enc.Client()
		if c.Address() == vt.Address && c.Mount() == vt.Mount {
			store := hcvault.NewStore(c, vt.KeyName, cfg.Signing.Algorithm, obs.WithComponent("vault-transit"))
			return &OpenResult{Store: store}, nil
		}
	}

	var appRole *hcvault.AppRoleAuth
	if vt.AppRole.RoleID != "" {
		appRole = &hcvault.AppRoleAuth{
			RoleID:   vt.AppRole.RoleID,
			SecretID: vt.AppRole.SecretID,
			Mount:    vt.AppRole.Mount,
		}
	}

	client, err := hcvault.NewClient(ctx, hcvault.ClientConfig{
		Address: vt.Address,
		Token:   vt.Token,
		Mount:   vt.Mount,
		AppRole: appRole,
		Timeout: vt.Timeout,
	}, obs.WithComponent("vault-client"))
	if err != nil {
		return nil, fmt.Errorf("vault transit client: %w", err)
	}

	store := hcvault.NewStore(client, vt.KeyName, cfg.Signing.Algorithm, obs.WithComponent("vault-transit"))
	return &OpenResult{Store: store, Closer: closerFunc(client.Close)}, nil
}

// closerFunc adapts a func() to io.Closer.
type closerFunc func()

// Close implements io.Closer.
func (f closerFunc) Close() error {
	f()
	return nil
}

// underlyingDataStore walks any decorator DataStores (those exposing
// `Unwrap() output.DataStore`, e.g. the user-cache wrapper) to reach the
// concrete adapter, so driver-specific factories can type-assert it regardless
// of how the store was wrapped before reaching Open.
func underlyingDataStore(ds output.DataStore) output.DataStore {
	for {
		u, ok := ds.(interface{ Unwrap() output.DataStore })
		if !ok {
			return ds
		}
		next := u.Unwrap()
		if next == nil {
			return ds
		}
		ds = next
	}
}

// openPostgresKey creates an HA PostgreSQL KeyStore with a LISTEN/NOTIFY starter.
//
// The HAKeyStore itself does no caching; a WrapKeyStore decorator provides the
// single-slot fast-path cache (default process-global, overridable via
// WithSigningKeyCache). The listener invalidates that decorator on NOTIFY.
func openPostgresKey(cfg *config.Config, ds output.DataStore, encryptor output.DataEncryptor, obs *observability.Provider, o *openOptions) (*OpenResult, error) {
	// The DataStore may be fronted by decorators (e.g. the user cache) that hide
	// the concrete adapter, so unwrap before type-asserting.
	pgDB, ok := underlyingDataStore(ds).(*postgres.DB)
	if !ok || pgDB == nil {
		return nil, fmt.Errorf("postgres_key requires postgres storage driver")
	}
	if encryptor == nil {
		return nil, fmt.Errorf("postgres_key requires data_encryption to be configured")
	}

	haStore := postgres.NewHAKeyStore(pgDB.Pool, encryptor, obs.WithComponent("ha-keystore"))

	keyCache := o.signingKeyCache
	if keyCache == nil {
		keyCache = cache.NewMemory[*output.SigningKey]()
	}
	cachedStore := WrapKeyStore(haStore, keyCache, obs)

	return &OpenResult{
		Store: cachedStore,
		RunNotify: func(ctx context.Context, reload func(context.Context) error) {
			listener := postgres.NewKeyStoreListener(
				cfg.Storage.Postgres.DSN,
				cachedStore,
				reload,
				obs.WithComponent("keystore-listener"),
			)
			go func() {
				defer func() {
					if r := recover(); r != nil {
						obs.Logger.Error("panic in keystore listener goroutine", "panic", r)
					}
				}()
				if err := listener.Run(ctx); err != nil && ctx.Err() == nil {
					obs.Logger.Error("keystore listener stopped", "error", err)
				}
			}()
		},
	}, nil
}
