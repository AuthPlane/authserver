package configast

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// writeFixture writes a tiny config package fixture under a tmp
// directory and returns its path. The fixture mimics the real
// authserver internal/config layout closely enough to exercise
// every walker in this package: nested structs, slice-of-struct,
// duration defaults, env-var bindings spread across helper
// functions, and a validate.go "required when X" rule.
func writeFixture(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()

	configGo := `package config

import "time"

type Config struct {
	Server  ServerConfig  ` + "`yaml:\"server\"`" + `
	Storage StorageConfig ` + "`yaml:\"storage\"`" + `
}

// ServerConfig configures the public listener.
type ServerConfig struct {
	Issuer       string        ` + "`yaml:\"issuer\"`" + `
	Address      string        ` + "`yaml:\"address\"`" + ` // host:port
	ReadTimeout  time.Duration ` + "`yaml:\"read_timeout\"`" + `
}

// StorageConfig configures the database.
type StorageConfig struct {
	Driver string       ` + "`yaml:\"driver\"`" + ` // "sqlite" or "postgres"
	SQLite SQLiteConfig ` + "`yaml:\"sqlite\"`" + `
}

type SQLiteConfig struct {
	Path string ` + "`yaml:\"path\"`" + `
	WAL  bool   ` + "`yaml:\"wal\"`" + `
}
`

	loaderGo := `package config

import (
	"os"
	"time"
)

func DefaultConfig() *Config {
	return &Config{
		Server: ServerConfig{
			Issuer:      "http://localhost:9000",
			Address:     ":9000",
			ReadTimeout: 30 * time.Second,
		},
		Storage: StorageConfig{
			Driver: "sqlite",
			SQLite: SQLiteConfig{
				Path: "data/authserver.db",
				WAL:  true,
			},
		},
	}
}

func loadServerFromEnv(cfg *ServerConfig) {
	cfg.Issuer = getEnv("AUTHPLANE_SERVER_ISSUER", cfg.Issuer)
	cfg.Address = getEnv("AUTHPLANE_SERVER_ADDRESS", cfg.Address)
	cfg.ReadTimeout = getEnvDuration("AUTHPLANE_SERVER_READ_TIMEOUT", cfg.ReadTimeout)
}

func loadStorageFromEnv(cfg *StorageConfig) {
	cfg.Driver = getEnv("AUTHPLANE_STORAGE_DRIVER", cfg.Driver)
	cfg.SQLite.Path = getEnv("AUTHPLANE_STORAGE_SQLITE_PATH", cfg.SQLite.Path)
	cfg.SQLite.WAL = getEnvBool("AUTHPLANE_STORAGE_SQLITE_WAL", cfg.SQLite.WAL)
	if _, ok := os.LookupEnv("AUTHPLANE_STORAGE_DEBUG"); ok {
		// pretend
	}
}

func getEnv(k, d string) string             { return "" }
func getEnvBool(k string, d bool) bool       { return d }
func getEnvDuration(k string, d time.Duration) time.Duration { return d }
`

	validateGo := `package config

import "errors"

func (c *Config) Validate() error {
	if c.Storage.Driver == "sqlite" {
		if c.Storage.SQLite.Path == "" {
			return errors.New("storage.sqlite.path is required when driver is sqlite")
		}
	}
	return nil
}
`

	for name, body := range map[string]string{
		"config.go":   configGo,
		"loader.go":   loaderGo,
		"validate.go": validateGo,
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}
	return dir
}

func TestParse_FieldsAndDefaults(t *testing.T) {
	dir := writeFixture(t)
	m, err := Parse(dir)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}

	byPath := map[string]Field{}
	for _, f := range m.Fields {
		byPath[f.YAMLPath] = f
	}

	cases := map[string]struct {
		typ     string
		def     string
		envVar  string
		section string
	}{
		"server.issuer":       {"string", "http://localhost:9000", "AUTHPLANE_SERVER_ISSUER", "server"},
		"server.address":      {"string", ":9000", "AUTHPLANE_SERVER_ADDRESS", "server"},
		"server.read_timeout": {"duration", "30s", "AUTHPLANE_SERVER_READ_TIMEOUT", "server"},
		"storage.driver":      {"string", "sqlite", "AUTHPLANE_STORAGE_DRIVER", "storage"},
		"storage.sqlite.path": {"string", "data/authserver.db", "AUTHPLANE_STORAGE_SQLITE_PATH", "storage"},
		"storage.sqlite.wal":  {"bool", "true", "AUTHPLANE_STORAGE_SQLITE_WAL", "storage"},
	}
	for path, want := range cases {
		got, ok := byPath[path]
		if !ok {
			t.Errorf("missing field %s", path)
			continue
		}
		if got.HumanType != want.typ {
			t.Errorf("%s type: got %q want %q", path, got.HumanType, want.typ)
		}
		if got.Default != want.def {
			t.Errorf("%s default: got %q want %q", path, got.Default, want.def)
		}
		if got.EnvVar != want.envVar {
			t.Errorf("%s envvar: got %q want %q", path, got.EnvVar, want.envVar)
		}
		if got.Section != want.section {
			t.Errorf("%s section: got %q want %q", path, got.Section, want.section)
		}
	}
}

func TestParse_RequiredWhenFromValidate(t *testing.T) {
	dir := writeFixture(t)
	m, err := Parse(dir)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	for _, f := range m.Fields {
		if f.YAMLPath != "storage.sqlite.path" {
			continue
		}
		if f.RequiredWhen != "driver is sqlite" {
			t.Errorf("RequiredWhen for storage.sqlite.path = %q, want %q", f.RequiredWhen, "driver is sqlite")
		}
	}
}

func TestParse_EnvVarsContainsAllNames(t *testing.T) {
	dir := writeFixture(t)
	m, err := Parse(dir)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	names := map[string]bool{}
	for _, e := range m.EnvVars {
		names[e.Name] = true
	}
	for _, want := range []string{
		"AUTHPLANE_SERVER_ISSUER",
		"AUTHPLANE_SERVER_ADDRESS",
		"AUTHPLANE_SERVER_READ_TIMEOUT",
		"AUTHPLANE_STORAGE_DRIVER",
		"AUTHPLANE_STORAGE_SQLITE_PATH",
		"AUTHPLANE_STORAGE_SQLITE_WAL",
		"AUTHPLANE_STORAGE_DEBUG",
	} {
		if !names[want] {
			t.Errorf("EnvVars missing %s", want)
		}
	}
}

func TestParse_SectionsInDeclarationOrder(t *testing.T) {
	dir := writeFixture(t)
	m, err := Parse(dir)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	want := []string{"server", "storage"}
	if len(m.TopLevelSections) != len(want) {
		t.Fatalf("got %d sections, want %d", len(m.TopLevelSections), len(want))
	}
	for i, s := range m.TopLevelSections {
		if s.YAMLKey != want[i] {
			t.Errorf("section[%d] = %q, want %q", i, s.YAMLKey, want[i])
		}
	}
}

func TestParse_MissingValidateIsNonFatal(t *testing.T) {
	dir := writeFixture(t)
	if err := os.Remove(filepath.Join(dir, "validate.go")); err != nil {
		t.Fatalf("remove validate.go: %v", err)
	}
	m, err := Parse(dir)
	if err != nil {
		t.Fatalf("Parse without validate.go: %v", err)
	}
	for _, f := range m.Fields {
		if f.RequiredWhen != "" {
			t.Errorf("expected empty RequiredWhen for %s, got %q", f.YAMLPath, f.RequiredWhen)
		}
	}
}

func TestParse_RealConfigPackage(t *testing.T) {
	// Sanity-check against the real authserver config package. We
	// resolve the path relative to this test file's location so
	// the test runs from any working directory.
	dir, err := filepath.Abs("../../../../internal/config")
	if err != nil {
		t.Fatalf("abs: %v", err)
	}
	if _, statErr := os.Stat(filepath.Join(dir, "config.go")); statErr != nil {
		t.Skipf("real config package not reachable: %v", statErr)
	}
	m, err := Parse(dir)
	if err != nil {
		t.Fatalf("Parse real config: %v", err)
	}
	// Spot-check the four audit-flagged defaults — DefaultConfig()
	// does NOT set these, so the walker must report empty.
	byPath := map[string]string{}
	for _, f := range m.Fields {
		byPath[f.YAMLPath] = f.Default
	}
	for _, path := range []string{
		"data_encryption.driver",
		"data_encryption.vault_transit_encrypt.mount_path",
		"data_encryption.vault_transit_encrypt.key_name",
		"data_encryption.vault_transit_encrypt.auth_method",
	} {
		if byPath[path] != "" {
			t.Errorf("audit-flagged default for %s should be empty, got %q", path, byPath[path])
		}
	}
	// And cross-check one non-empty default to make sure we're
	// actually reading DefaultConfig().
	if !strings.Contains(byPath["server.issuer"], "localhost") {
		t.Errorf("server.issuer default missing localhost: %q", byPath["server.issuer"])
	}
}
