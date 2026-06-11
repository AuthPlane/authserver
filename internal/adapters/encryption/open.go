// Package encryption provides a factory for creating the configured DataEncryptor backend.
// This follows the same pattern as internal/adapters/storage/open.go.
package encryption

import (
	"context"
	"fmt"
	"os"

	"github.com/authplane/authserver/internal/adapters/aesmaster"
	"github.com/authplane/authserver/internal/adapters/hcvault"
	"github.com/authplane/authserver/internal/config"
	"github.com/authplane/authserver/internal/observability"
	"github.com/authplane/authserver/internal/ports/output"
)

// Open creates the DataEncryptor for the configured driver.
func Open(ctx context.Context, cfg config.DataEncryptionConfig, obs *observability.Provider) (output.DataEncryptor, error) {
	switch cfg.Driver {
	case "aes_master":
		keyHex := os.Getenv(cfg.AESMaster.KeyEnv)
		var opts []aesmaster.Option
		if cfg.AESMaster.OldKeyEnv != "" {
			if oldKeyHex := os.Getenv(cfg.AESMaster.OldKeyEnv); oldKeyHex != "" {
				opts = append(opts, aesmaster.WithOldKey(oldKeyHex))
			}
		}
		return aesmaster.New(keyHex, obs.WithComponent("aesmaster"), opts...)

	case "vault_transit_encrypt":
		return openVaultTransit(ctx, cfg.VaultTransitEncrypt, obs)

	default:
		return nil, fmt.Errorf("unsupported data_encryption.driver: %q", cfg.Driver)
	}
}

func openVaultTransit(ctx context.Context, vtc config.VaultTransitEncryptConfig, obs *observability.Provider) (output.DataEncryptor, error) {
	token := ""
	if vtc.TokenEnv != "" {
		token = os.Getenv(vtc.TokenEnv)
	}
	mountPath := vtc.MountPath
	if mountPath == "" {
		mountPath = "transit"
	}

	client, err := hcvault.NewClient(ctx, hcvault.ClientConfig{
		Address: vtc.Address,
		Token:   token,
		Mount:   mountPath,
	}, obs.WithComponent("vault-enc-client"))
	if err != nil {
		return nil, fmt.Errorf("vault transit encrypt client: %w", err)
	}

	return hcvault.NewEncryptor(client, vtc.KeyName, obs.WithComponent("vaulttransitenc")), nil
}
