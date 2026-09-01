package main

import (
	"context"
	"fmt"
	"io"
	"os"

	"github.com/go-jose/go-jose/v4"
	"github.com/spf13/cobra"

	"github.com/authplane/authserver/internal/adapters/cache"
	"github.com/authplane/authserver/internal/adapters/encryption"
	adaptersigning "github.com/authplane/authserver/internal/adapters/signing"
	"github.com/authplane/authserver/internal/adapters/static"
	"github.com/authplane/authserver/internal/adapters/storage"
	"github.com/authplane/authserver/internal/config"
	"github.com/authplane/authserver/internal/observability"
	"github.com/authplane/authserver/internal/ports/input"
	"github.com/authplane/authserver/internal/ports/output"
	"github.com/authplane/authserver/internal/services"
)

// cliEnv holds the common dependencies needed by CLI subcommands that
// interact with storage and admin services (user create, scope register, etc.).
type cliEnv struct {
	cfg      *config.Config
	ds       output.DataStore
	obs      *observability.Provider
	adminSvc *services.AdminService

	resourceAdminSvc       input.ResourceAdminPort
	brokerProviderAdminSvc input.BrokerProviderAdminPort
	grantAdminSvc          input.GrantAdminPort
	issuanceAdminSvc       input.IssuanceAdminPort
	frontingAdminSvc       input.FrontingAdminPort
}

// loadConfig loads config using the --config flag or auto-detect. It also
// enforces the OSS admin API-key policy (ValidateAdminAPIKey), which is not
// part of the shared config.Validate() so that deployments fronting the admin
// API with external authentication can opt out of the built-in API-key gate.
func loadConfig() (*config.Config, error) {
	cfg, err := config.Load(cfgFile)
	if err != nil {
		return nil, err
	}
	if err := cfg.ValidateAdminAPIKey(); err != nil {
		return nil, fmt.Errorf("invalid configuration: %w", err)
	}
	return cfg, nil
}

// openCLIEnv is the cliEnv-opener seam used by the unified-resource admin
// subcommands (resource / provider / grant / issuance). Tests override this
// with a stubbed cliEnv so the cobra commands can be exercised in-process
// without standing up storage. Defaults to the production openAdminCLI.
var openCLIEnv = openAdminCLI

// openAdminCLI sets up config, storage, migrations, and admin service
// for CLI subcommands. Returns a cleanup function that must be deferred.
func openAdminCLI() (*cliEnv, func(), error) {
	cfg, err := loadConfig()
	if err != nil {
		return nil, nil, fmt.Errorf("load config: %w", err)
	}

	obs := observability.NewNoop()

	// Setup data encryptor if configured so CLI-driven broker-provider creates
	// can route inline secrets onto the encrypted-column path, matching serve.go.
	var dataEncryptor output.DataEncryptor
	if cfg.DataEncryption.Driver != "" {
		dataEncryptor, err = encryption.Open(context.Background(), cfg.DataEncryption, obs)
		if err != nil {
			return nil, nil, fmt.Errorf("setup data encryptor: %w", err)
		}
	}
	closeEncryptor := func() {
		if c, ok := dataEncryptor.(io.Closer); ok {
			_ = c.Close()
		}
	}

	ds, err := storage.Open(context.Background(), cfg.Storage, obs)
	if err != nil {
		closeEncryptor()
		return nil, nil, fmt.Errorf("open database: %w", err)
	}

	if err := ds.Migrate(context.Background()); err != nil {
		_ = ds.Close()
		closeEncryptor()
		return nil, nil, fmt.Errorf("migrate: %w", err)
	}

	var fieldEnc output.FieldEncryptor
	if dataEncryptor != nil {
		fieldEnc = static.NewDataEncryptorFieldEncryptor(dataEncryptor)
	}
	brokerConfigSecrets := static.NewConfigSecretBackend(fieldEnc)

	auditSvc := services.NewAuditService(ds.Audit(), obs.WithComponent("audit"))
	grantsProvider := static.NewEnabledGrantsProvider(config.EnabledGrantTypes(cfg))
	adminSvc := services.NewAdminService(
		ds.Client(), ds.User(), ds.Token(), ds.Audit(),
		obs.WithComponent("admin"), auditSvc,
		services.WithMachineTokenStore(ds.MachineToken()),
		services.WithRevocationStore(ds.Revocation()),
		services.WithTransactionManager(ds.Transaction()),
		services.WithEnabledGrants(grantsProvider),
		// Same bound as the served admin API — the CLI reads the same feed and
		// must not have a wider or narrower view of it than HTTP callers.
		services.WithAuditQueryConfig(static.NewAuditQueryConfigProvider(output.AuditQueryConfig{
			DefaultLookback: cfg.Admin.AuditDefaultLookback,
			MaxLookback:     cfg.Admin.AuditMaxLookback,
		})),
	)

	frontingAdminSvc := services.NewFrontingService(
		ds.FrontingLink(), ds.Resource(), ds.Transaction(),
		obs.WithComponent("fronting-admin"), auditSvc,
	)
	resourceAdminSvc := services.NewResourceAdminService(
		ds.Resource(), ds.BrokerProvider(), ds.Client(),
		obs.WithComponent("resource-admin"), auditSvc,
		services.WithFrontingValidator(frontingAdminSvc),
		services.WithResourceAdminTransactionManager(ds.Transaction()),
	)
	brokerProviderAdminSvc := services.NewBrokerProviderAdminService(
		ds.BrokerProvider(),
		obs.WithComponent("broker-provider-admin"), auditSvc,
		brokerConfigSecrets,
	)
	grantAdminSvc := services.NewGrantAdminService(
		ds.ConsentGrant(), ds.BrokerGrant(), ds.Issuance(),
		obs.WithComponent("grant-admin"), auditSvc,
	)
	issuanceAdminSvc := services.NewIssuanceAdminService(
		ds.Issuance(),
		obs.WithComponent("issuance-admin"), auditSvc,
	)

	env := &cliEnv{
		cfg: cfg, ds: ds, obs: obs, adminSvc: adminSvc,
		resourceAdminSvc:       resourceAdminSvc,
		brokerProviderAdminSvc: brokerProviderAdminSvc,
		grantAdminSvc:          grantAdminSvc,
		issuanceAdminSvc:       issuanceAdminSvc,
		frontingAdminSvc:       frontingAdminSvc,
	}
	cleanup := func() {
		_ = ds.Close()
		closeEncryptor()
	}
	return env, cleanup, nil
}

// openKeyRotationCLI sets up config, storage, key store, and JWKS service
// for key rotation commands (which need the signing key store, not just admin).
func openKeyRotationCLI() (*services.JWKSService, func(), error) {
	cfg, err := loadConfig()
	if err != nil {
		return nil, nil, fmt.Errorf("load config: %w", err)
	}

	obs := observability.NewNoop()

	// Setup data encryptor if configured (needed for postgres_key).
	var dataEncryptor output.DataEncryptor
	if cfg.DataEncryption.Driver != "" {
		dataEncryptor, err = encryption.Open(context.Background(), cfg.DataEncryption, obs)
		if err != nil {
			return nil, nil, fmt.Errorf("setup data encryptor: %w", err)
		}
	}

	ds, err := storage.Open(context.Background(), cfg.Storage, obs)
	if err != nil {
		if c, ok := dataEncryptor.(io.Closer); ok {
			_ = c.Close()
		}
		return nil, nil, fmt.Errorf("open database: %w", err)
	}

	keyResult, err := adaptersigning.Open(context.Background(), cfg, ds, dataEncryptor, obs)
	if err != nil {
		_ = ds.Close()
		if c, ok := dataEncryptor.(io.Closer); ok {
			_ = c.Close()
		}
		return nil, nil, fmt.Errorf("create key store: %w", err)
	}

	jwksSvc := services.NewJWKSService(keyResult.Store, cache.NewMemory[*jose.JSONWebKeySet](), cfg.Signing.Algorithm, obs.WithComponent("jwks"))

	cleanup := func() {
		if keyResult.Closer != nil {
			_ = keyResult.Closer.Close()
		}
		_ = ds.Close()
		if c, ok := dataEncryptor.(io.Closer); ok {
			_ = c.Close()
		}
	}
	return jwksSvc, cleanup, nil
}

// bindEnv checks os.Getenv for a flag value if the flag was not explicitly set.
func bindEnv(cmd *cobra.Command, flagName, envVar string) {
	if !cmd.Flags().Changed(flagName) {
		if v := os.Getenv(envVar); v != "" {
			_ = cmd.Flags().Set(flagName, v)
		}
	}
}
