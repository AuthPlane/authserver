package cmd

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/spf13/cobra"

	"github.com/authplane/authserver/tools/docsgen/internal/configast"
	"github.com/authplane/authserver/tools/docsgen/internal/mdwriter"
	"github.com/authplane/authserver/tools/docsgen/internal/srcref"
)

// configSourceDir is the package directory the env/config generators walk.
// Relative to the repo root; the generators resolve it via repoRoot() so
// `go run ./tools/docsgen env` works from any cwd.
const configSourceDir = "internal/config"

// newEnvCmd returns the `docsgen env` subcommand. It walks
// internal/config/loader.go to capture every AUTHPLANE_* environment
// variable plus its YAML key, type, default, "required when" rule and
// source-line reference, and emits a single docs/reference/env-vars.md.
func newEnvCmd() *cobra.Command {
	c := &cobra.Command{
		Use:   "env",
		Short: "Generate the environment variables reference (docs/reference/env-vars.md)",
		RunE: func(cmd *cobra.Command, args []string) error {
			outDir, err := cmd.Flags().GetString("out")
			if err != nil {
				return err
			}
			target, err := runEnvGen(outDir)
			if err != nil {
				// Stay on the safe side: if the real generator
				// fails, fall back to the stub so the build /
				// `make docs-gen` target stays green.
				stub, stubErr := writeStub(outDir, "env-vars.md",
					"Environment Variables",
					"Auto-generated environment-variable reference failed: "+err.Error())
				if stubErr != nil {
					return err
				}
				_, _ = fmt.Fprintf(cmd.OutOrStdout(), "wrote %s (fallback stub: %v)\n", stub, err)
				return nil
			}
			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "wrote %s\n", target)
			return nil
		},
	}
	return c
}

// runEnvGen is the testable entry point: parse, render, write. Returns the
// path of the file written.
func runEnvGen(outDir string) (string, error) {
	root, err := repoRoot()
	if err != nil {
		return "", fmt.Errorf("locate repo root: %w", err)
	}
	srcDir := filepath.Join(root, configSourceDir)

	model, err := configast.Parse(srcDir)
	if err != nil {
		return "", fmt.Errorf("parse config package: %w", err)
	}

	body := renderEnvDoc(model, root)

	if err := os.MkdirAll(outDir, 0o755); err != nil { //nolint:gosec // G301: docs/ dir is world-readable by design
		return "", fmt.Errorf("create out dir: %w", err)
	}
	target := filepath.Join(outDir, "env-vars.md")
	if err := os.WriteFile(target, []byte(body), 0o644); err != nil { //nolint:gosec // G306: generated docs are world-readable by design
		return "", fmt.Errorf("write %s: %w", target, err)
	}
	return target, nil
}

// renderEnvDoc returns the full env-vars.md document body.
func renderEnvDoc(model *configast.Model, repoRootPath string) string {
	src := srcref.New(model.Fset)

	// Build a path -> field lookup so we can pull type/default/required
	// hints for each env-var row.
	fieldByPath := map[string]configast.Field{}
	for _, f := range model.Fields {
		fieldByPath[f.YAMLPath] = f
	}

	// Sort env-vars by name for stable, operator-friendly output.
	envs := make([]configast.EnvVar, len(model.EnvVars))
	copy(envs, model.EnvVars)
	sort.SliceStable(envs, func(i, j int) bool {
		return envs[i].Name < envs[j].Name
	})

	var b strings.Builder
	b.WriteString(GeneratedByHeader)
	b.WriteString("\n\n")
	b.WriteString("# Environment Variables\n\n")
	b.WriteString(envPreamble())
	b.WriteString("\n\n")

	t := &mdwriter.Table{
		Headers: []string{"Env var", "YAML key", "Type", "Default", "Required when", "Source"},
	}
	for _, e := range envs {
		yamlCell := dashOr(codeOr(e.YAMLPath))
		typeCell := "—"
		defaultCell := "—"
		requiredCell := "—"
		if f, ok := fieldByPath[e.YAMLPath]; ok {
			if f.HumanType != "" {
				typeCell = "`" + f.HumanType + "`"
			}
			if f.Default != "" {
				defaultCell = "`" + f.Default + "`"
			}
			if f.RequiredWhen != "" {
				requiredCell = f.RequiredWhen
			}
		}
		sourceCell := "—"
		if ref := src.Format(e.Pos, repoRootPath); ref != "" {
			sourceCell = "[`" + ref + "`](../../" + ref + ")"
		}
		t.Rows = append(t.Rows, []string{
			"`" + e.Name + "`",
			yamlCell,
			typeCell,
			defaultCell,
			requiredCell,
			sourceCell,
		})
	}
	b.WriteString(t.Render())
	return b.String()
}

// envPreamble is the one-paragraph explainer that follows the H1. Static
// content lives here so the generator stays self-contained; the docs team
// can revise wording by editing this string.
func envPreamble() string {
	return "Every setting in the on-disk YAML configuration can also be supplied " +
		"via an `AUTHPLANE_*` environment variable. Env vars are evaluated " +
		"after the YAML file is loaded and override matching YAML keys, " +
		"making them the recommended channel for secrets and per-environment " +
		"overrides (Docker `-e`, Kubernetes `env:`, systemd `Environment=`). " +
		"See the [configuration reference](./configuration.md) for the full " +
		"YAML schema and the deploy guides for environment-specific examples."
}

// codeOr wraps a non-empty string in Markdown inline-code backticks.
func codeOr(s string) string {
	if s == "" {
		return ""
	}
	return "`" + s + "`"
}

// dashOr returns the literal em-dash glyph when s is empty; otherwise s.
// Used to keep table cells visually consistent.
func dashOr(s string) string {
	if s == "" {
		return "—"
	}
	return s
}
