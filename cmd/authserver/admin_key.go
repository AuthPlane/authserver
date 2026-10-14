package main

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	"github.com/authplane/authserver/internal/config"
)

// keyCmd is the parent for signing key management subcommands.
var keyCmd = &cobra.Command{
	Use:   "key",
	Short: "Manage signing keys",
	Args:  cobra.NoArgs, // unknown subcommand → loud error (see admin.go)
	RunE:  func(cmd *cobra.Command, _ []string) error { return cmd.Help() },
}

// --- key rotate ---

var keyRotateCmd = &cobra.Command{
	Use:   "rotate",
	Short: "Rotate the signing key",
	Long: "Rotate the signing key in the key store the server uses. Pass the " +
		"server's own config file with --config (the Helm chart mounts it at " +
		"/etc/authplane/config.yaml), or set AUTHPLANE_SIGNING_KEY_STORE or " +
		"AUTHPLANE_SIGNING_KEY_PATH as the server does. With neither, the " +
		"command refuses to run rather than rotate a default key store the " +
		"server never reads. The key store acted on is printed first.",
	RunE: func(cmd *cobra.Command, args []string) error {
		jwksSvc, cfg, cleanup, err := openKeyRotationCLI()
		if err != nil {
			return err
		}
		defer cleanup()

		out := cmd.OutOrStdout()
		_, _ = fmt.Fprintf(out, "key store: %s\n", describeKeyStore(cfg))

		key, err := jwksSvc.RotateKey(context.Background())
		if err != nil {
			return fmt.Errorf("rotate key: %w", err)
		}

		_, _ = fmt.Fprintf(out, "key rotated: kid=%s alg=%s\n", key.KeyID, key.Algorithm)
		return nil
	},
}

// --- key list ---

var keyListCmd = &cobra.Command{
	Use:   "list",
	Short: "List signing keys",
	Long: "List the signing keys in the key store the server uses. Takes the " +
		"same --config or AUTHPLANE_SIGNING_KEY_STORE / AUTHPLANE_SIGNING_KEY_PATH " +
		"as key rotate, refuses to run without one, and prints the key store " +
		"it read first.",
	RunE: func(cmd *cobra.Command, args []string) error {
		jwksSvc, cfg, cleanup, err := openKeyRotationCLI()
		if err != nil {
			return err
		}
		defer cleanup()

		out := cmd.OutOrStdout()
		_, _ = fmt.Fprintf(out, "key store: %s\n", describeKeyStore(cfg))

		ctx := context.Background()
		jwks, err := jwksSvc.BuildJWKS(ctx)
		if err != nil {
			return fmt.Errorf("build jwks: %w", err)
		}
		// The JWKS leaves out a key that cannot be used, so its first entry
		// is not necessarily the current key: label by the store's own.
		current, currentErr := jwksSvc.CurrentKey(ctx)
		currentKID := ""
		if currentErr == nil && current != nil {
			currentKID = current.KeyID
		}

		for _, k := range jwks.Keys {
			status := "previous"
			if k.KeyID == currentKID {
				status = "current"
			}
			_, _ = fmt.Fprintf(out, "kid=%s alg=%s use=%s status=%s\n", k.KeyID, k.Algorithm, k.Use, status)
		}
		if len(jwks.Keys) == 0 {
			_, _ = fmt.Fprintln(out, "no signing keys found")
		}
		// The JWKS skips an unusable previous key too, and the CLI's logger
		// discards the store's warning, so report it here.
		if _, err := jwksSvc.PreviousKey(ctx); err != nil {
			_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "warning: cannot load the previous signing key (%v); if it is unusable, tokens it signed fail verification; a rotation from a usable current key replaces it\n", err)
		}
		if currentErr != nil {
			return fmt.Errorf("cannot load the current signing key, and token requests fail until it loads; if the key itself is unusable, replace it with `authserver admin key rotate`: %w", currentErr)
		}
		return nil
	},
}

func init() {
	keyCmd.AddCommand(keyRotateCmd)
	keyCmd.AddCommand(keyListCmd)
}

// keyStoreEnvVars are the environment variables that select a signing key
// store without a config file. Env-only deployments (the docker compose
// stacks) set one of them on the server, and an exec'd key command inherits
// it, so either one counts as the operator having named the server's store.
// A variable that is set but empty does not count.
var keyStoreEnvVars = []string{"AUTHPLANE_SIGNING_KEY_STORE", "AUTHPLANE_SIGNING_KEY_PATH"}

// requireKeyStoreSource refuses to run a key command that would act on the
// built-in default key store. config.Load treats an empty or nonexistent
// --config as "use defaults", which for the server is a convenience but for
// a key command is a trap: the defaults put a keyfile store at a path
// relative to the working directory, so `admin key rotate` run without the
// server's --config writes a fresh key there, reports success, and leaves
// the key the server signs with untouched.
func requireKeyStoreSource(path string) error {
	if path != "" {
		if _, err := os.Stat(path); !errors.Is(err, fs.ErrNotExist) {
			// The file exists (or is unreadable, which config.Load reports).
			return nil
		}
	}
	for _, name := range keyStoreEnvVars {
		if os.Getenv(name) != "" {
			return nil
		}
	}
	reason := "no --config file was given"
	if path != "" {
		reason = fmt.Sprintf("config file %q does not exist", path)
	}
	return fmt.Errorf(
		"%s and neither %s is set, so this command would act on the built-in default key store "+
			"(a keyfile store at %q, relative to the working directory) instead of the one the server uses; "+
			"pass the server's config file with --config (the Helm chart mounts it at /etc/authplane/config.yaml)",
		reason, strings.Join(keyStoreEnvVars, " nor "), config.DefaultConfig().Signing.KeyPath,
	)
}

// describeKeyStore names the key store a key command acted on and where it
// lives, so an operator can tell from the output alone whether it was the
// server's. It never prints credentials.
func describeKeyStore(cfg *config.Config) string {
	s := cfg.Signing
	switch s.KeyStore {
	case "keyfile", "":
		path := s.KeyPath
		if abs, err := filepath.Abs(path); err == nil {
			path = abs
		}
		return fmt.Sprintf("keyfile (key_path %s)", path)
	case "vault_transit":
		return fmt.Sprintf("vault_transit (key %q on mount %q at %s)", s.VaultTransit.KeyName, s.VaultTransit.Mount, describeVaultAddress(s.VaultTransit.Address))
	case "postgres_key":
		return fmt.Sprintf("postgres_key (%s)", describePostgresDSN(cfg.Storage.Postgres.DSN))
	default:
		return s.KeyStore
	}
}

// describeVaultAddress prints the Vault address without any userinfo
// (user:password@), query or fragment it may carry, any of which can hold a
// credential. An address that does not parse as a URL is not echoed at all.
func describeVaultAddress(addr string) string {
	u, err := url.Parse(addr)
	if err != nil || u.Host == "" {
		return "the configured signing.vault_transit.address"
	}
	u.User = nil
	u.RawQuery = ""
	u.ForceQuery = false
	u.Fragment = ""
	u.RawFragment = ""
	return u.String()
}

// describePostgresDSN reduces a DSN to host and database name, dropping the
// user and password. A DSN that is not in URL form is not echoed at all.
func describePostgresDSN(dsn string) string {
	u, err := url.Parse(dsn)
	if err != nil || (u.Scheme != "postgres" && u.Scheme != "postgresql") || u.Host == "" {
		return "the storage.postgres database"
	}
	return fmt.Sprintf("postgres database %s/%s", u.Host, strings.TrimPrefix(u.Path, "/"))
}
