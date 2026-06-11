package main

import (
	"fmt"
	"strings"

	"github.com/spf13/cobra"

	"github.com/authplane/authserver/internal/admin/dto"
	"github.com/authplane/authserver/internal/domain/resource"
	"github.com/authplane/authserver/internal/ports/input"
)

// frontingCmd is the parent for fronting-link admin subcommands.
// Mirrors `admin resource` ergonomics: list, get, create, update, delete.
var frontingCmd = &cobra.Command{
	Use:   "fronting",
	Short: "Manage cross-Mint fronting links",
	Long: "Manage operator-declared fronting links. A fronting link " +
		"declares that a Mint Resource (`source`) may mint tokens for a " +
		"downstream Resource (`target`) via RFC 8693 token-exchange, " +
		"translating scopes per the supplied scope-map. The runtime path " +
		"that consumes these rows lands in (Inc N+1).",
	Args: cobra.NoArgs,
	RunE: func(cmd *cobra.Command, _ []string) error { return cmd.Help() },
}

// --- fronting list ---

var frontingListCmd = &cobra.Command{
	Use:   "list",
	Short: "List fronting links",
	RunE: func(cmd *cobra.Command, _ []string) error {
		filter := input.FrontingLinkFilter{}
		if v, _ := cmd.Flags().GetString("source"); v != "" {
			filter.Source = v
		}
		if v, _ := cmd.Flags().GetString("target"); v != "" {
			filter.Target = v
		}

		env, cleanup, err := openCLIEnv()
		if err != nil {
			return err
		}
		defer cleanup()

		rows, err := env.frontingAdminSvc.List(cmd.Context(), filter)
		if err != nil {
			return fmt.Errorf("list fronting links: %w", err)
		}

		jsonOut, _ := cmd.Flags().GetBool("json")
		if jsonOut {
			views := make([]dto.FrontingLinkView, len(rows))
			for i, l := range rows {
				views[i] = dto.FrontingLinkToView(l)
			}
			return writeJSON(cmd.OutOrStdout(), views)
		}

		if len(rows) == 0 {
			_, _ = fmt.Fprintln(cmd.OutOrStdout(), "no fronting links found")
			return nil
		}
		for _, l := range rows {
			_, _ = fmt.Fprintf(cmd.OutOrStdout(),
				"source=%s target=%s scope_map=%s created_by=%s\n",
				l.SourceSlug, l.TargetSlug, formatScopeMap(l.ScopeMap), l.CreatedBy)
		}
		return nil
	},
}

// --- fronting get ---

var frontingGetCmd = &cobra.Command{
	Use:   "get",
	Short: "Get a fronting link by (source, target)",
	RunE: func(cmd *cobra.Command, _ []string) error {
		source, _ := cmd.Flags().GetString("source")
		target, _ := cmd.Flags().GetString("target")
		if source == "" || target == "" {
			return fmt.Errorf("--source and --target are required")
		}

		env, cleanup, err := openCLIEnv()
		if err != nil {
			return err
		}
		defer cleanup()

		l, err := env.frontingAdminSvc.Get(cmd.Context(), source, target)
		if err != nil {
			return fmt.Errorf("get fronting link: %w", err)
		}

		jsonOut, _ := cmd.Flags().GetBool("json")
		if jsonOut {
			return writeJSON(cmd.OutOrStdout(), dto.FrontingLinkToView(l))
		}
		_, _ = fmt.Fprintf(cmd.OutOrStdout(),
			"source=%s target=%s scope_map=%s created_by=%s\n",
			l.SourceSlug, l.TargetSlug, formatScopeMap(l.ScopeMap), l.CreatedBy)
		return nil
	},
}

// --- fronting create ---

var frontingCreateCmd = &cobra.Command{
	Use:   "create",
	Short: "Create a fronting link",
	Long: "Create a fronting link. --scope-map encodes the source→target " +
		"scope translation as comma-separated entries; each entry may carry " +
		"multiple targets via '+'.\n\n" +
		"Examples:\n" +
		"  --scope-map A:AA,B:BB                source=A→[AA]; source=B→[BB]\n" +
		"  --scope-map read:repo+org,write:repo source=read→[repo,org]; source=write→[repo]\n" +
		"\n" +
		"Pass --dry-run to validate without persisting (the service runs " +
		"every pre-write rule including cycle detection).",
	RunE: func(cmd *cobra.Command, _ []string) error {
		source, _ := cmd.Flags().GetString("source")
		target, _ := cmd.Flags().GetString("target")
		scopeMapRaw, _ := cmd.Flags().GetString("scope-map")
		dryRun, _ := cmd.Flags().GetBool("dry-run")

		if source == "" {
			return fmt.Errorf("--source is required")
		}
		if target == "" {
			return fmt.Errorf("--target is required")
		}

		scopeMap, err := parseScopeMapFlag(scopeMapRaw)
		if err != nil {
			return err
		}

		env, cleanup, err := openCLIEnv()
		if err != nil {
			return err
		}
		defer cleanup()

		link := &resource.FrontingLink{
			SourceSlug: source,
			TargetSlug: target,
			ScopeMap:   scopeMap,
		}

		if dryRun {
			if err := env.frontingAdminSvc.Validate(cmd.Context(), link); err != nil {
				return fmt.Errorf("validate fronting link: %w", err)
			}
			_, _ = fmt.Fprintf(cmd.OutOrStdout(),
				"validation OK: source=%s target=%s scope_map=%s\n",
				source, target, formatScopeMap(scopeMap))
			return nil
		}

		if err := env.frontingAdminSvc.Create(cmd.Context(), link, "cli"); err != nil {
			return fmt.Errorf("create fronting link: %w", err)
		}
		_, _ = fmt.Fprintf(cmd.OutOrStdout(),
			"fronting link created: source=%s target=%s\n", source, target)
		return nil
	},
}

// --- fronting update ---

var frontingUpdateCmd = &cobra.Command{
	Use:   "update",
	Short: "Update a fronting link's scope_map (PATCH)",
	Long: "Replace the scope_map of an existing fronting link. Only " +
		"--scope-map is patchable; rewiring source/target requires " +
		"delete + create. Omitting --scope-map leaves the existing map " +
		"untouched.",
	RunE: func(cmd *cobra.Command, _ []string) error {
		source, _ := cmd.Flags().GetString("source")
		target, _ := cmd.Flags().GetString("target")
		if source == "" || target == "" {
			return fmt.Errorf("--source and --target are required")
		}

		patch := input.FrontingLinkPatch{}
		if cmd.Flags().Changed("scope-map") {
			raw, _ := cmd.Flags().GetString("scope-map")
			scopeMap, err := parseScopeMapFlag(raw)
			if err != nil {
				return err
			}
			patch.ScopeMap = &scopeMap
		}

		env, cleanup, err := openCLIEnv()
		if err != nil {
			return err
		}
		defer cleanup()

		updated, err := env.frontingAdminSvc.Patch(cmd.Context(), source, target, patch, "cli")
		if err != nil {
			return fmt.Errorf("update fronting link: %w", err)
		}
		_, _ = fmt.Fprintf(cmd.OutOrStdout(),
			"fronting link updated: source=%s target=%s scope_map=%s\n",
			updated.SourceSlug, updated.TargetSlug, formatScopeMap(updated.ScopeMap))
		return nil
	},
}

// --- fronting delete ---

var frontingDeleteCmd = &cobra.Command{
	Use:   "delete",
	Short: "Delete a fronting link",
	RunE: func(cmd *cobra.Command, _ []string) error {
		source, _ := cmd.Flags().GetString("source")
		target, _ := cmd.Flags().GetString("target")
		if source == "" || target == "" {
			return fmt.Errorf("--source and --target are required")
		}

		env, cleanup, err := openCLIEnv()
		if err != nil {
			return err
		}
		defer cleanup()

		if err := env.frontingAdminSvc.Delete(cmd.Context(), source, target, "cli"); err != nil {
			return fmt.Errorf("delete fronting link: %w", err)
		}
		_, _ = fmt.Fprintf(cmd.OutOrStdout(),
			"fronting link deleted: source=%s target=%s\n", source, target)
		return nil
	},
}

// parseScopeMapFlag decodes the --scope-map flag into a resource.ScopeMap.
//
// Grammar:
//
//	"src:tgt"                 → {src: [tgt]}
//	"src1:tgt1,src2:tgt2"     → {src1: [tgt1], src2: [tgt2]}
//	"src:tgt1+tgt2,src2:tgt3" → {src: [tgt1, tgt2], src2: [tgt3]}
//
// Whitespace around tokens is trimmed. Empty key or empty target list is
// rejected. Repeated source keys append to the existing target list (so
// `--scope-map read:a,read:b` produces `{read: [a, b]}` — the same shape
// as `--scope-map read:a+b`).
func parseScopeMapFlag(raw string) (resource.ScopeMap, error) {
	if strings.TrimSpace(raw) == "" {
		return nil, fmt.Errorf("--scope-map must not be empty")
	}
	out := resource.ScopeMap{}
	for _, entry := range strings.Split(raw, ",") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		colon := strings.Index(entry, ":")
		if colon <= 0 {
			return nil, fmt.Errorf("--scope-map entry %q: expected 'source:target' shape", entry)
		}
		src := strings.TrimSpace(entry[:colon])
		tgts := strings.TrimSpace(entry[colon+1:])
		if src == "" {
			return nil, fmt.Errorf("--scope-map entry %q: source key is empty", entry)
		}
		if tgts == "" {
			return nil, fmt.Errorf("--scope-map entry %q: target list is empty", entry)
		}
		for _, t := range strings.Split(tgts, "+") {
			t = strings.TrimSpace(t)
			if t == "" {
				return nil, fmt.Errorf("--scope-map entry %q: target list contains an empty value", entry)
			}
			out[src] = append(out[src], t)
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("--scope-map produced no entries")
	}
	return out, nil
}

// formatScopeMap renders a ScopeMap as a stable, compact string for human
// output. Mirrors the audit-detail format from the service.
func formatScopeMap(m resource.ScopeMap) string {
	if len(m) == 0 {
		return "{}"
	}
	srcs := m.SourceScopes()
	parts := make([]string, 0, len(srcs))
	for _, src := range srcs {
		tgts := append([]string(nil), m[src]...)
		parts = append(parts, src+"->"+strings.Join(tgts, "+"))
	}
	return "{" + strings.Join(parts, ",") + "}"
}

func init() {
	frontingListCmd.Flags().String("source", "", "Filter by source slug")
	frontingListCmd.Flags().String("target", "", "Filter by target slug")
	frontingListCmd.Flags().Bool("json", false, "Emit JSON instead of human-readable lines")

	frontingGetCmd.Flags().String("source", "", "Source slug (required)")
	frontingGetCmd.Flags().String("target", "", "Target slug (required)")
	frontingGetCmd.Flags().Bool("json", false, "Emit JSON instead of human-readable lines")

	frontingCreateCmd.Flags().String("source", "", "Source slug (required)")
	frontingCreateCmd.Flags().String("target", "", "Target slug (required)")
	frontingCreateCmd.Flags().String("scope-map", "",
		"Scope map: 'src:tgt[+tgt2],src2:tgt3' (required)")
	frontingCreateCmd.Flags().Bool("dry-run", false,
		"Validate without persisting (runs all pre-write rules)")

	frontingUpdateCmd.Flags().String("source", "", "Source slug (required)")
	frontingUpdateCmd.Flags().String("target", "", "Target slug (required)")
	frontingUpdateCmd.Flags().String("scope-map", "",
		"Replacement scope_map (omitting leaves the current map unchanged)")

	frontingDeleteCmd.Flags().String("source", "", "Source slug (required)")
	frontingDeleteCmd.Flags().String("target", "", "Target slug (required)")

	frontingCmd.AddCommand(frontingListCmd)
	frontingCmd.AddCommand(frontingGetCmd)
	frontingCmd.AddCommand(frontingCreateCmd)
	frontingCmd.AddCommand(frontingUpdateCmd)
	frontingCmd.AddCommand(frontingDeleteCmd)
}
