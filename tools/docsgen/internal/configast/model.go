// Package configast provides an AST-driven model of the authserver's
// configuration package. It parses internal/config/config.go,
// internal/config/loader.go and (when present) internal/config/validate.go
// to surface every YAML key, env-var binding, default value and
// "required when X" rule the generators in cmd/env.go and cmd/config.go
// need.
//
// The package is intentionally narrow: it walks Go ASTs once at the
// start of a docsgen run and produces a flat, immutable view callers
// can iterate over. No I/O happens after Parse returns.
package configast

import (
	"go/token"
)

// Model is the flat, immutable view of the config package.
type Model struct {
	// Fset holds every parsed position so callers can format
	// "file:line" source references via internal/srcref.
	Fset *token.FileSet

	// Fields lists every leaf YAML field in dotted-path order
	// (e.g. "storage.sqlite.path"). Top-level keys without nested
	// structs (none exist today but the walker handles them) also
	// appear here as a single-segment dotted path.
	Fields []Field

	// EnvVars lists every AUTHPLANE_* env-var binding found in
	// loader.go, in the order the walker discovered them.
	EnvVars []EnvVar

	// TopLevelSections lists the top-level YAML keys of the root
	// Config struct in declaration order — used to drive the H2
	// sections in configuration.md.
	TopLevelSections []Section
}

// Field is a leaf configuration field with its YAML dotted path,
// Go type rendered as Markdown, optional default (rendered like
// the user would write it in YAML), env-var name (if bound) and
// the "required when X" hint extracted from validate.go.
type Field struct {
	// YAMLPath is the dotted path the operator types in config.yaml
	// (e.g. "data_encryption.aes_master.key_env").
	YAMLPath string

	// Section is the top-level YAML key this field lives under
	// (e.g. "data_encryption"). For root-level scalar fields
	// (none today), Section equals YAMLPath.
	Section string

	// GoType is the Go type spelling as it appears in the source —
	// without the package prefix when it's the local config
	// package (e.g. "string", "time.Duration", "[]string",
	// "SQLiteConfig"). For map[K]V and slice-of-struct fields
	// it's rendered with the angle/bracket spelling.
	GoType string

	// HumanType is GoType normalised for the docs (e.g.
	// "duration" instead of "time.Duration", "bool" stays "bool").
	HumanType string

	// Comment is the leading or trailing comment on the field,
	// stripped of comment markers and surrounding whitespace.
	Comment string

	// Default is the value DefaultConfig() sets for this field,
	// rendered the way an operator would write it in YAML
	// (e.g. "1h", "true", ":9000"). Empty string when
	// DefaultConfig() does not set the field.
	Default string

	// EnvVar is the AUTHPLANE_* env-var bound to this field in
	// loader.go, or "" when the field has no env-var binding.
	EnvVar string

	// RequiredWhen is the trigger phrase parsed from validate.go
	// — e.g. "driver is aes_master". Empty when no rule names
	// this field.
	RequiredWhen string

	// Pos is the AST position of the field declaration in
	// config.go; rendered via internal/srcref.
	Pos token.Pos
}

// EnvVar represents a single AUTHPLANE_* binding in loader.go.
type EnvVar struct {
	// Name is the literal env-var string, e.g. "AUTHPLANE_SERVER_ISSUER".
	Name string

	// YAMLPath is the dotted YAML path the env-var sets, e.g.
	// "server.issuer". Derived from the loader function's receiver
	// chain; empty when the walker can't resolve the chain (which
	// indicates a bug — every binding in loader.go today maps to
	// a struct field).
	YAMLPath string

	// Helper names the getEnv* function used — "getEnv",
	// "getEnvBool", "getEnvInt", "getEnvFloat64",
	// "getEnvDuration", "getEnvStringSlice", or "os.LookupEnv" /
	// "os.Getenv" for direct calls.
	Helper string

	// Pos is the AST position of the binding call so srcref can
	// render "loader.go:347".
	Pos token.Pos
}

// Section is a top-level YAML key on the root Config struct.
type Section struct {
	// YAMLKey is the YAML name (e.g. "server", "storage").
	YAMLKey string

	// GoTypeName is the Go type used for the section
	// (e.g. "ServerConfig"). Used to pull the type-level
	// doc comment as the section preamble fallback.
	GoTypeName string

	// Comment is the leading doc-comment on the section's Go type
	// — used as the section preamble when no hand-written
	// preamble file exists.
	Comment string

	// Pos points at the section's field declaration on Config.
	Pos token.Pos
}
