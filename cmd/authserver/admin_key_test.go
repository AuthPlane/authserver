package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/authplane/authserver/internal/config"
)

// unsetKeyStoreEnv removes the key-store env vars for the test's lifetime.
// t.Setenv registers the restore; the Unsetenv makes them truly absent, which
// matters because config.Load treats a set-but-empty AUTHPLANE_SIGNING_KEY_PATH
// as an override to "".
func unsetKeyStoreEnv(t *testing.T) {
	t.Helper()
	for _, name := range keyStoreEnvVars {
		t.Setenv(name, "")
		if err := os.Unsetenv(name); err != nil {
			t.Fatal(err)
		}
	}
}

// writeKeyTestConfig writes a config file whose SQLite database and keyfile
// store both live under dir, and returns its path and the key path.
func writeKeyTestConfig(t *testing.T, dir string) (cfgPath, keyPath string) {
	t.Helper()
	cfg := config.DefaultConfig()
	cfg.Storage.Driver = "sqlite"
	cfg.Storage.SQLite.Path = filepath.Join(dir, "authserver.db")
	cfg.Signing.KeyStore = "keyfile"
	cfg.Signing.KeyPath = filepath.Join(dir, "keys")
	cfg.Admin.APIKey = "key-cmd-test-admin-api-key-0123456789abcdef"

	data, err := yaml.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	cfgPath = filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(cfgPath, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return cfgPath, cfg.Signing.KeyPath
}

// TestKeyCommands_RefuseDefaultKeyStore covers the trap the guard exists
// for: without the server's config file (absent, or a path that does not
// exist — config.Load silently treats both as "use defaults") and without a
// key-store env var, the key commands must fail before touching any store,
// and must not leave a default keyfile store in the working directory.
func TestKeyCommands_RefuseDefaultKeyStore(t *testing.T) {
	cases := []struct {
		name string
		cmd  []string
		args []string
		want string
	}{
		{"rotate without --config", []string{"rotate"}, nil, "no --config file was given"},
		{"list without --config", []string{"list"}, nil, "no --config file was given"},
		{"rotate with missing --config", []string{"rotate"}, []string{"--config", "does-not-exist.yaml"}, `config file "does-not-exist.yaml" does not exist`},
		{"list with missing --config", []string{"list"}, []string{"--config", "does-not-exist.yaml"}, `config file "does-not-exist.yaml" does not exist`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			unsetKeyStoreEnv(t)
			wd := t.TempDir()
			t.Chdir(wd)

			sub := keyRotateCmd
			if tc.cmd[0] == "list" {
				sub = keyListCmd
			}
			out, err := dispatchRoot(t, sub, tc.args)
			if err == nil {
				t.Fatalf("expected refusal, got success; output:\n%s", out)
			}
			msg := err.Error()
			for _, want := range []string{tc.want, "--config", "AUTHPLANE_SIGNING_KEY_STORE", "AUTHPLANE_SIGNING_KEY_PATH"} {
				if !strings.Contains(msg, want) {
					t.Errorf("error %q does not mention %q", msg, want)
				}
			}
			if strings.Contains(out, "key rotated") {
				t.Errorf("refused command still reported a rotation:\n%s", out)
			}
			entries, readErr := os.ReadDir(wd)
			if readErr != nil {
				t.Fatal(readErr)
			}
			if len(entries) != 0 {
				t.Errorf("refused command created files in the working directory: %v", entries)
			}
		})
	}
}

// TestKeyRotate_WithConfigFile_ActsOnConfiguredStore is the success path:
// with an explicit config file, rotate and list run, print the configured
// keyfile path, and the rotated key lands in that directory.
func TestKeyRotate_WithConfigFile_ActsOnConfiguredStore(t *testing.T) {
	unsetKeyStoreEnv(t)
	dir := t.TempDir()
	cfgPath, keyPath := writeKeyTestConfig(t, dir)

	out, err := dispatchRoot(t, keyRotateCmd, []string{"--config", cfgPath})
	if err != nil {
		t.Fatalf("rotate: %v\n%s", err, out)
	}
	if !strings.Contains(out, "key store: keyfile (key_path "+keyPath+")") {
		t.Errorf("rotate output does not name the configured key store %s:\n%s", keyPath, out)
	}
	if !strings.Contains(out, "key rotated: kid=") {
		t.Errorf("rotate output missing the rotation line:\n%s", out)
	}
	entries, err := os.ReadDir(keyPath)
	if err != nil {
		t.Fatalf("configured key path was not written: %v", err)
	}
	if len(entries) == 0 {
		t.Fatalf("configured key path %s is empty after rotate", keyPath)
	}

	out, err = dispatchRoot(t, keyListCmd, []string{"--config", cfgPath})
	if err != nil {
		t.Fatalf("list: %v\n%s", err, out)
	}
	if !strings.Contains(out, "key store: keyfile (key_path "+keyPath+")") {
		t.Errorf("list output does not name the configured key store:\n%s", out)
	}
	if !strings.Contains(out, "status=current") {
		t.Errorf("list output shows no current key:\n%s", out)
	}
}

// TestKeyList_LabelsTheStoresCurrentKey: list labels keys by the store's
// current key, not by their position in the JWKS. The JWKS leaves out an
// unusable key, so with a broken current key file the previous key comes
// first; list must not call it current, and must fail naming the fix. A
// rotation then replaces the broken key and keeps the previous one; a broken
// previous key gets a warning.
func TestKeyList_LabelsTheStoresCurrentKey(t *testing.T) {
	unsetKeyStoreEnv(t)
	dir := t.TempDir()
	cfgPath, keyPath := writeKeyTestConfig(t, dir)
	args := []string{"--config", cfgPath}

	rotate := func() string {
		t.Helper()
		out, err := dispatchRoot(t, keyRotateCmd, args)
		if err != nil {
			t.Fatalf("rotate: %v\n%s", err, out)
		}
		_, rest, ok := strings.Cut(out, "key rotated: kid=")
		if !ok {
			t.Fatalf("rotate output has no rotated kid:\n%s", out)
		}
		kid, _, _ := strings.Cut(rest, " ")
		return kid
	}
	// list keeps stdout and stderr apart, unlike dispatchRoot: the
	// previous-key warning must go to stderr, and must appear only when a
	// key is unusable.
	list := func() (stdout, stderr string, err error) {
		t.Helper()
		resetCobraFlags(rootCmd)
		var o, e bytes.Buffer
		rootCmd.SetOut(&o)
		rootCmd.SetErr(&e)
		rootCmd.SetArgs(append(pathFromRoot(keyListCmd), args...))
		t.Cleanup(func() {
			rootCmd.SetArgs(nil)
			rootCmd.SetOut(nil)
			rootCmd.SetErr(nil)
		})
		err = rootCmd.Execute()
		return o.String(), e.String(), err
	}
	noWarning := func(when, stderr string) {
		t.Helper()
		if strings.Contains(stderr, "warning:") {
			t.Errorf("list warned %s:\n%s", when, stderr)
		}
	}
	statusOf := func(out, kid string) string {
		t.Helper()
		for _, line := range strings.Split(out, "\n") {
			if strings.HasPrefix(line, "kid="+kid+" ") {
				_, status, _ := strings.Cut(line, "status=")
				return status
			}
		}
		return ""
	}

	out, stderr, err := list()
	if err != nil || !strings.Contains(out, "no signing keys found") {
		t.Fatalf("list on an empty store: err=%v\n%s", err, out)
	}
	noWarning("on an empty store", stderr)

	prev := rotate()
	cur := rotate()
	out, stderr, err = list()
	if err != nil {
		t.Fatalf("list: %v\n%s", err, out)
	}
	noWarning("with two usable keys", stderr)
	if got := statusOf(out, cur); got != "current" {
		t.Errorf("rotated-in key %s: status %q, want current\n%s", cur, got, out)
	}
	if got := statusOf(out, prev); got != "previous" {
		t.Errorf("earlier key %s: status %q, want previous\n%s", prev, got, out)
	}

	if err = os.WriteFile(filepath.Join(keyPath, "current.pem"), []byte("not a pem\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	out, _, err = list()
	if err == nil {
		t.Fatalf("list succeeded with an unusable current key:\n%s", out)
	}
	if !strings.Contains(err.Error(), "admin key rotate") {
		t.Errorf("list error does not name the fix: %v", err)
	}
	if got := statusOf(out, prev); got != "previous" {
		t.Errorf("previous key %s: status %q, want previous\n%s", prev, got, out)
	}
	if strings.Contains(out, "status=current") {
		t.Errorf("list labeled a key current while the current key is unusable:\n%s", out)
	}

	repaired := rotate()
	out, stderr, err = list()
	if err != nil {
		t.Fatalf("list after repair: %v\n%s", err, out)
	}
	noWarning("after the repair", stderr)
	if got := statusOf(out, repaired); got != "current" {
		t.Errorf("replacement key %s: status %q, want current\n%s", repaired, got, out)
	}
	if got := statusOf(out, prev); got != "previous" {
		t.Errorf("rotation did not keep previous key %s: status %q\n%s", prev, got, out)
	}

	// An unusable previous key drops out of the JWKS; list still succeeds
	// with the current key but warns.
	if err = os.WriteFile(filepath.Join(keyPath, "previous.pem"), []byte("not a pem\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	out, stderr, err = list()
	if err != nil {
		t.Fatalf("list with an unusable previous key: %v\n%s", err, out)
	}
	if got := statusOf(out, repaired); got != "current" {
		t.Errorf("current key %s: status %q, want current\n%s", repaired, got, out)
	}
	if !strings.Contains(stderr, "warning: cannot load the previous signing key") {
		t.Errorf("list did not warn on stderr about the unusable previous key:\nstdout:\n%s\nstderr:\n%s", out, stderr)
	}
	if strings.Contains(out, "warning:") {
		t.Errorf("list wrote the warning to stdout:\n%s", out)
	}
}

// TestKeyRotate_EnvOnly_Allowed keeps env-only deployments working: the
// docker compose stacks configure the server with AUTHPLANE_SIGNING_KEY_PATH
// and no config file, and an exec'd key command inherits that.
func TestKeyRotate_EnvOnly_Allowed(t *testing.T) {
	unsetKeyStoreEnv(t)
	dir := t.TempDir()
	t.Chdir(dir) // default SQLite path is relative to the working directory
	keyPath := filepath.Join(dir, "env-keys")
	t.Setenv("AUTHPLANE_SIGNING_KEY_PATH", keyPath)

	out, err := dispatchRoot(t, keyRotateCmd, nil)
	if err != nil {
		t.Fatalf("rotate: %v\n%s", err, out)
	}
	if !strings.Contains(out, "key store: keyfile (key_path "+keyPath+")") {
		t.Errorf("rotate output does not name the env-configured key store:\n%s", out)
	}
	if entries, err := os.ReadDir(keyPath); err != nil || len(entries) == 0 {
		t.Fatalf("env-configured key path %s was not written (err=%v)", keyPath, err)
	}
}

func TestDescribeKeyStore(t *testing.T) {
	vault := config.DefaultConfig()
	vault.Signing.KeyStore = "vault_transit"
	vault.Signing.VaultTransit.Address = "https://vault.example:8200"
	vault.Signing.VaultTransit.Mount = "transit"
	vault.Signing.VaultTransit.KeyName = "authserver-signing"
	vault.Signing.VaultTransit.Token = "s.secret-token"

	vaultUserinfo := config.DefaultConfig()
	vaultUserinfo.Signing.KeyStore = "vault_transit"
	vaultUserinfo.Signing.VaultTransit.Address = "https://ops:vault-pass@vault.example:8200/"
	vaultUserinfo.Signing.VaultTransit.Mount = "transit"
	vaultUserinfo.Signing.VaultTransit.KeyName = "authserver-signing"

	vaultUnparseable := config.DefaultConfig()
	vaultUnparseable.Signing.KeyStore = "vault_transit"
	vaultUnparseable.Signing.VaultTransit.Address = "ops:vault-pass@vault.example:8200"
	vaultUnparseable.Signing.VaultTransit.Mount = "transit"
	vaultUnparseable.Signing.VaultTransit.KeyName = "authserver-signing"

	vaultQuery := config.DefaultConfig()
	vaultQuery.Signing.KeyStore = "vault_transit"
	vaultQuery.Signing.VaultTransit.Address = "https://vault/x?token=s.abc#frag"
	vaultQuery.Signing.VaultTransit.Mount = "transit"
	vaultQuery.Signing.VaultTransit.KeyName = "authserver-signing"

	pg := config.DefaultConfig()
	pg.Signing.KeyStore = "postgres_key"
	pg.Storage.Postgres.DSN = "postgres://authplane:hunter2@db.example:5432/authplane?sslmode=require"

	pgKV := config.DefaultConfig()
	pgKV.Signing.KeyStore = "postgres_key"
	pgKV.Storage.Postgres.DSN = "host=db.example user=authplane password=hunter2 dbname=authplane"

	cases := []struct {
		name    string
		cfg     *config.Config
		want    string
		secrets []string
	}{
		{"vault", vault, `vault_transit (key "authserver-signing" on mount "transit" at https://vault.example:8200)`, []string{"s.secret-token"}},
		{"vault address with userinfo", vaultUserinfo, `vault_transit (key "authserver-signing" on mount "transit" at https://vault.example:8200/)`, []string{"vault-pass", "ops"}},
		{"vault address not a URL", vaultUnparseable, `vault_transit (key "authserver-signing" on mount "transit" at the configured signing.vault_transit.address)`, []string{"vault-pass"}},
		{"vault address with query and fragment", vaultQuery, `vault_transit (key "authserver-signing" on mount "transit" at https://vault/x)`, []string{"s.abc", "token", "frag", "?", "#"}},
		{"postgres url", pg, "postgres_key (postgres database db.example:5432/authplane)", []string{"hunter2"}},
		{"postgres key=value", pgKV, "postgres_key (the storage.postgres database)", []string{"hunter2"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := describeKeyStore(tc.cfg)
			if got != tc.want {
				t.Errorf("describeKeyStore = %q, want %q", got, tc.want)
			}
			for _, s := range tc.secrets {
				if strings.Contains(got, s) {
					t.Errorf("describeKeyStore leaked %q: %q", s, got)
				}
			}
		})
	}
}
