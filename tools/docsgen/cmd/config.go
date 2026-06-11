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
)

// configPreambleDir is the optional directory holding per-section preamble
// snippets (e.g. tools/docsgen/preambles/configuration/server.md). When a
// file is present it's prepended verbatim to the section table; absent files
// are silently ignored. Operators / tech writers can use this to add
// hand-written context without touching the generator.
const configPreambleDir = "tools/docsgen/preambles/configuration"

// newConfigCmd returns the `docsgen config` subcommand. It walks the
// canonical config struct in internal/config/config.go and emits a
// schema-style reference for the on-disk YAML configuration in
// docs/reference/configuration.md.
func newConfigCmd() *cobra.Command {
	c := &cobra.Command{
		Use:   "config",
		Short: "Generate the configuration reference (docs/reference/configuration.md)",
		RunE: func(cmd *cobra.Command, args []string) error {
			outDir, err := cmd.Flags().GetString("out")
			if err != nil {
				return err
			}
			target, err := runConfigGen(outDir)
			if err != nil {
				// On failure, drop a stub so the rest of
				// docsgen still produces a tree the docs site
				// can serve. Surface the underlying error to
				// the operator via the stub body + log line.
				stub, stubErr := writeStub(outDir, "configuration.md",
					"Configuration Reference",
					"Auto-generated configuration reference failed: "+err.Error())
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

// runConfigGen is the testable entry point: parse, render, write. Returns
// the path of the file written.
func runConfigGen(outDir string) (string, error) {
	root, err := repoRoot()
	if err != nil {
		return "", fmt.Errorf("locate repo root: %w", err)
	}
	srcDir := filepath.Join(root, configSourceDir)

	model, err := configast.Parse(srcDir)
	if err != nil {
		return "", fmt.Errorf("parse config package: %w", err)
	}

	body := renderConfigDoc(model, root)

	if err := os.MkdirAll(outDir, 0o755); err != nil { //nolint:gosec // G301: docs/ dir is world-readable by design
		return "", fmt.Errorf("create out dir: %w", err)
	}
	target := filepath.Join(outDir, "configuration.md")
	if err := os.WriteFile(target, []byte(body), 0o644); err != nil { //nolint:gosec // G306: generated docs are world-readable by design
		return "", fmt.Errorf("write %s: %w", target, err)
	}
	return target, nil
}

// renderConfigDoc returns the full configuration.md document body. It
// emits one H2 per top-level YAML section in declaration order, with a
// stable HTML-comment anchor and a Markdown table of every leaf YAML key
// underneath that section.
func renderConfigDoc(model *configast.Model, repoRootPath string) string {
	// Group fields by their top-level YAML section. Each section's slice
	// keeps insertion order so the rendered tables follow the struct
	// declaration order in config.go.
	bySection := map[string][]configast.Field{}
	for _, f := range model.Fields {
		bySection[f.Section] = append(bySection[f.Section], f)
	}

	var b strings.Builder
	b.WriteString(GeneratedByHeader)
	b.WriteString("\n\n")
	b.WriteString("# Configuration Reference\n\n")
	b.WriteString(configPreamble())
	b.WriteString("\n\n")

	// Table of contents — one entry per top-level section so readers
	// can jump straight to the area they're configuring.
	b.WriteString("## Sections\n\n")
	for _, sec := range model.TopLevelSections {
		b.WriteString("- [`")
		b.WriteString(sec.YAMLKey)
		b.WriteString("`](#")
		b.WriteString(sectionAnchorSlug(sec.YAMLKey))
		b.WriteString(")\n")
	}
	b.WriteString("\n")

	for _, sec := range model.TopLevelSections {
		b.WriteString(renderConfigSection(sec, bySection[sec.YAMLKey], repoRootPath))
	}
	return b.String()
}

// renderConfigSection emits one H2 block for sec: heading, anchor, an
// optional hand-written preamble snippet, the section's struct-level
// doc-comment as the default preamble, and the per-key table.
func renderConfigSection(sec configast.Section, fields []configast.Field, repoRootPath string) string {
	var b strings.Builder
	b.WriteString("## `")
	b.WriteString(sec.YAMLKey)
	b.WriteString("`\n\n")
	b.WriteString(`<a id="config-`)
	b.WriteString(mdwriter.Slug(sec.YAMLKey))
	b.WriteString("\"></a>\n\n")

	// Hand-written preamble snippet wins over the Go-level doc-comment.
	preamble := strings.TrimSpace(loadSectionPreamble(repoRootPath, sec.YAMLKey))
	if preamble == "" {
		preamble = strings.TrimSpace(sec.Comment)
	}
	if preamble != "" {
		b.WriteString(preamble)
		b.WriteString("\n\n")
	}

	// Sort the leaf rows alphabetically by YAML path. The original
	// struct order is preserved by configast, but operators usually
	// scan tables alphabetically — and stable sort means an arbitrary
	// re-order of fields in config.go doesn't churn the diff.
	rows := make([]configast.Field, len(fields))
	copy(rows, fields)
	sort.SliceStable(rows, func(i, j int) bool {
		return rows[i].YAMLPath < rows[j].YAMLPath
	})

	t := &mdwriter.Table{
		Headers: []string{"Key", "Type", "Default", "Env var", "Notes"},
	}
	for _, f := range rows {
		typeCell := "—"
		if f.HumanType != "" {
			typeCell = "`" + f.HumanType + "`"
		}
		defaultCell := "—"
		if f.Default != "" {
			defaultCell = "`" + f.Default + "`"
		}
		envCell := "—"
		if f.EnvVar != "" {
			envCell = "`" + f.EnvVar + "`"
		}
		notes := strings.TrimSpace(f.Comment)
		if f.RequiredWhen != "" {
			req := "Required when " + f.RequiredWhen + "."
			if notes == "" {
				notes = req
			} else {
				notes = notes + " " + req
			}
		}
		if notes == "" {
			notes = "—"
		}
		t.Rows = append(t.Rows, []string{
			"`" + f.YAMLPath + "`",
			typeCell,
			defaultCell,
			envCell,
			notes,
		})
	}
	b.WriteString(t.Render())
	b.WriteString("\n")
	return b.String()
}

// sectionAnchorSlug is the anchor slug used in TOC links and the HTML
// comment marker; kept in sync with renderConfigSection.
func sectionAnchorSlug(key string) string {
	return "config-" + mdwriter.Slug(key)
}

// loadSectionPreamble reads tools/docsgen/preambles/configuration/<section>.md
// if it exists. An absent file is the common case and is not an error;
// returns "" so the caller falls back to the Go-level doc-comment.
func loadSectionPreamble(repoRootPath, section string) string {
	path := filepath.Join(repoRootPath, configPreambleDir, section+".md")
	data, err := os.ReadFile(path) //nolint:gosec // G304: reading a curated preamble file
	if err != nil {
		return ""
	}
	return string(data)
}

// configPreamble is the one-paragraph header that follows the H1. Lists
// the precedence rules so operators know which channel wins for a given
// setting and points at the env-vars reference for the override surface.
func configPreamble() string {
	return "Authplane reads its configuration from a single YAML file " +
		"(typically `/etc/authserver/config.yaml`). Every leaf key " +
		"documented below can be overridden by an `AUTHPLANE_*` " +
		"environment variable — see the [environment variables " +
		"reference](./env-vars.md) for the complete mapping and " +
		"precedence rules. Defaults shown in the tables come straight " +
		"from `DefaultConfig()` in `internal/config/loader.go`; a `—` " +
		"means the field has no built-in default and must be supplied " +
		"by YAML, env var, or (for secrets) the referenced env-var " +
		"helper. Required-when conditions come from `Validate()` in " +
		"`internal/config/validate.go`."
}
