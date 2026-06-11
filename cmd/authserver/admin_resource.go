package main

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/spf13/cobra"

	"github.com/authplane/authserver/internal/admin/dto"
	"github.com/authplane/authserver/internal/domain/resource"
	"github.com/authplane/authserver/internal/ports/input"
)

// resourceCmd is the parent for unified-resource management subcommands.
// The `update` verb maps to the underlying `Patch` port method
// (operator-friendly naming; PATCH semantics).
var resourceCmd = &cobra.Command{
	Use:   "resource",
	Short: "Manage unified resources (mint + broker)",
	Long: "Manage unified resources. backend_kind=mint resources are JWT-signed " +
		"by the AS; backend_kind=broker resources are vended via a broker " +
		"adapter against an upstream provider.",
	Args: cobra.NoArgs, // unknown subcommand → loud error (see admin.go)
	RunE: func(cmd *cobra.Command, _ []string) error { return cmd.Help() },
}

// --- resource list ---

var resourceListCmd = &cobra.Command{
	Use:   "list",
	Short: "List resources",
	RunE: func(cmd *cobra.Command, args []string) error {
		filter := input.ResourceFilter{}
		if v, _ := cmd.Flags().GetString("backend-kind"); v != "" {
			switch resource.BackendKind(v) {
			case resource.BackendMint, resource.BackendBroker:
				filter.BackendKind = resource.BackendKind(v)
			default:
				return fmt.Errorf("--backend-kind must be mint or broker, got %q", v)
			}
		}
		if v, _ := cmd.Flags().GetString("broker-provider"); v != "" {
			filter.BrokerProviderID = v
		}

		env, cleanup, err := openCLIEnv()
		if err != nil {
			return err
		}
		defer cleanup()

		rows, err := env.resourceAdminSvc.List(cmd.Context(), filter)
		if err != nil {
			return fmt.Errorf("list resources: %w", err)
		}

		jsonOut, _ := cmd.Flags().GetBool("json")
		if jsonOut {
			views := make([]dto.ResourceView, len(rows))
			for i, r := range rows {
				views[i] = dto.ResourceToView(r)
			}
			return writeJSON(cmd.OutOrStdout(), views)
		}

		if len(rows) == 0 {
			_, _ = fmt.Fprintln(cmd.OutOrStdout(), "no resources found")
			return nil
		}
		for _, r := range rows {
			_, _ = fmt.Fprintf(cmd.OutOrStdout(),
				"id=%s slug=%s backend_kind=%s broker_provider_id=%s uri=%s scopes=%s\n",
				r.ID, r.Slug, r.BackendKind, r.BrokerProviderID, r.URI, formatScopes(r.Scopes))
		}
		return nil
	},
}

// --- resource get ---

var resourceGetCmd = &cobra.Command{
	Use:   "get",
	Short: "Get a resource by id",
	RunE: func(cmd *cobra.Command, args []string) error {
		id, _ := cmd.Flags().GetString("id")
		if id == "" {
			return fmt.Errorf("--id is required")
		}

		env, cleanup, err := openCLIEnv()
		if err != nil {
			return err
		}
		defer cleanup()

		r, err := env.resourceAdminSvc.GetByID(cmd.Context(), id)
		if err != nil {
			return fmt.Errorf("get resource: %w", err)
		}

		jsonOut, _ := cmd.Flags().GetBool("json")
		if jsonOut {
			return writeJSON(cmd.OutOrStdout(), dto.ResourceToView(r))
		}
		_, _ = fmt.Fprintf(cmd.OutOrStdout(),
			"id=%s slug=%s backend_kind=%s broker_provider_id=%s uri=%s display_name=%q scopes=%s\n",
			r.ID, r.Slug, r.BackendKind, r.BrokerProviderID, r.URI, r.DisplayName, formatScopes(r.Scopes))
		return nil
	},
}

// --- resource create ---

var resourceCreateCmd = &cobra.Command{
	Use:   "create",
	Short: "Create a resource",
	Long: "Create a resource. --scopes is repeatable; each value is a tuple " +
		"'name|upstream|description'. Example: --scopes 'repo|repo|Repository read/write'. " +
		"For Mint resources upstream is conventionally empty: --scopes 'tasks:summarize||'. " +
		"--scopes-file is the bulk JSON form (mutually exclusive with --scopes).",
	RunE: func(cmd *cobra.Command, args []string) error {
		slug, _ := cmd.Flags().GetString("slug")
		uri, _ := cmd.Flags().GetString("uri")
		backendKindRaw, _ := cmd.Flags().GetString("backend-kind")
		brokerProviderID, _ := cmd.Flags().GetString("broker-provider")
		displayName, _ := cmd.Flags().GetString("display-name")

		if slug == "" {
			return fmt.Errorf("--slug is required")
		}
		if backendKindRaw == "" {
			return fmt.Errorf("--backend-kind is required (mint or broker)")
		}

		scopes, err := readScopesFromFlags(cmd)
		if err != nil {
			return err
		}

		policy := readPolicyFromFlags(cmd)

		env, cleanup, err := openCLIEnv()
		if err != nil {
			return err
		}
		defer cleanup()

		r := &resource.Resource{
			Slug:             slug,
			URI:              uri,
			BackendKind:      resource.BackendKind(backendKindRaw),
			BrokerProviderID: brokerProviderID,
			DisplayName:      displayName,
			Scopes:           scopes,
		}
		if policy != nil {
			r.Policy = *policy
		}
		if createErr := env.resourceAdminSvc.Create(cmd.Context(), r); createErr != nil {
			return fmt.Errorf("create resource: %w", createErr)
		}

		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "resource created: id=%s slug=%s\n", r.ID, r.Slug)
		return nil
	},
}

// --- resource update ---

var resourceUpdateCmd = &cobra.Command{
	Use:   "update",
	Short: "Update a resource (PATCH)",
	Long: "Update a resource with PATCH semantics: omitted flags leave their " +
		"fields UNCHANGED. Use --scopes-clear / --policy-clear to wipe a " +
		"field explicitly. The CLI verb is `update` for operator " +
		"friendliness; the underlying port method is `Patch`.",
	RunE: func(cmd *cobra.Command, args []string) error {
		id, _ := cmd.Flags().GetString("id")
		if id == "" {
			return fmt.Errorf("--id is required")
		}

		patch := input.ResourcePatch{}

		if cmd.Flags().Changed("slug") {
			v, _ := cmd.Flags().GetString("slug")
			patch.Slug = &v
		}
		if cmd.Flags().Changed("uri") {
			v, _ := cmd.Flags().GetString("uri")
			patch.URI = &v
		}
		if cmd.Flags().Changed("backend-kind") {
			v, _ := cmd.Flags().GetString("backend-kind")
			bk := resource.BackendKind(v)
			patch.BackendKind = &bk
		}
		if cmd.Flags().Changed("broker-provider") {
			v, _ := cmd.Flags().GetString("broker-provider")
			patch.BrokerProviderID = &v
		}
		if cmd.Flags().Changed("display-name") {
			v, _ := cmd.Flags().GetString("display-name")
			patch.DisplayName = &v
		}

		// --scopes / --scopes-file / --scopes-clear: at most one form.
		scopesClear, _ := cmd.Flags().GetBool("scopes-clear")
		if scopesClear && (cmd.Flags().Changed("scopes") || cmd.Flags().Changed("scopes-file")) {
			return fmt.Errorf("--scopes-clear is mutually exclusive with --scopes / --scopes-file")
		}
		switch {
		case scopesClear:
			empty := []resource.Scope{}
			patch.Scopes = &empty
		case cmd.Flags().Changed("scopes") || cmd.Flags().Changed("scopes-file"):
			scopes, err := readScopesFromFlags(cmd)
			if err != nil {
				return err
			}
			patch.Scopes = &scopes
		}

		// --policy-clear OR explicit policy flags. Mutually exclusive.
		policyClear, _ := cmd.Flags().GetBool("policy-clear")
		policyTouched := cmd.Flags().Changed("policy-allowed-clients") ||
			cmd.Flags().Changed("policy-allowed-return-urls") ||
			cmd.Flags().Changed("policy-runtime-client-ids")
		if policyClear && policyTouched {
			return fmt.Errorf("--policy-clear is mutually exclusive with --policy-allowed-clients / --policy-allowed-return-urls / --policy-runtime-client-ids")
		}
		switch {
		case policyClear:
			patch.Policy = &resource.Policy{}
		case policyTouched:
			patch.Policy = readPolicyFromFlags(cmd)
		}

		env, cleanup, err := openCLIEnv()
		if err != nil {
			return err
		}
		defer cleanup()

		updated, err := env.resourceAdminSvc.Patch(cmd.Context(), id, patch)
		if err != nil {
			return fmt.Errorf("update resource: %w", err)
		}
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "resource updated: id=%s slug=%s\n", updated.ID, updated.Slug)
		return nil
	},
}

// --- resource runtime-client ---

// resourceRuntimeClientCmd groups add / remove / list against
// policy.runtime.client_ids — the operator surface for declaring which OAuth
// clients may act AS a Resource at /oauth/token. Replaces the implicit
// slug==client_id convention removed.
var resourceRuntimeClientCmd = &cobra.Command{
	Use:   "runtime-client",
	Short: "Manage policy.runtime.client_ids on a resource",
	Long: "Manage the OAuth client_ids authorized to act AS this Resource at " +
		"runtime. Empty list = no client may act as this Resource " +
		"(default-deny); multi-entry models multi-tier deployments where each " +
		"tier authenticates with its own credentials but maps to the same Resource.",
	Args: cobra.NoArgs,
	RunE: func(cmd *cobra.Command, _ []string) error { return cmd.Help() },
}

var resourceRuntimeClientAddCmd = &cobra.Command{
	Use:   "add",
	Short: "Authorize a client to act AS the resource",
	RunE: func(cmd *cobra.Command, args []string) error {
		slug, _ := cmd.Flags().GetString("slug")
		clientID, _ := cmd.Flags().GetString("client-id")
		if slug == "" {
			return fmt.Errorf("--slug is required")
		}
		if clientID == "" {
			return fmt.Errorf("--client-id is required")
		}

		env, cleanup, err := openCLIEnv()
		if err != nil {
			return err
		}
		defer cleanup()

		ids, err := env.resourceAdminSvc.AddRuntimeClientID(cmd.Context(), slug, clientID)
		if err != nil {
			return fmt.Errorf("add runtime client_id: %w", err)
		}
		_, _ = fmt.Fprintf(cmd.OutOrStdout(),
			"runtime client added: slug=%s client_id=%s client_ids=[%s]\n",
			slug, clientID, strings.Join(ids, ","))
		return nil
	},
}

var resourceRuntimeClientRemoveCmd = &cobra.Command{
	Use:   "remove",
	Short: "Revoke a client's authorization to act AS the resource",
	RunE: func(cmd *cobra.Command, args []string) error {
		slug, _ := cmd.Flags().GetString("slug")
		clientID, _ := cmd.Flags().GetString("client-id")
		if slug == "" {
			return fmt.Errorf("--slug is required")
		}
		if clientID == "" {
			return fmt.Errorf("--client-id is required")
		}

		env, cleanup, err := openCLIEnv()
		if err != nil {
			return err
		}
		defer cleanup()

		ids, err := env.resourceAdminSvc.RemoveRuntimeClientID(cmd.Context(), slug, clientID)
		if err != nil {
			return fmt.Errorf("remove runtime client_id: %w", err)
		}
		_, _ = fmt.Fprintf(cmd.OutOrStdout(),
			"runtime client removed: slug=%s client_id=%s client_ids=[%s]\n",
			slug, clientID, strings.Join(ids, ","))
		return nil
	},
}

var resourceRuntimeClientListCmd = &cobra.Command{
	Use:   "list",
	Short: "List runtime client_ids on a resource",
	RunE: func(cmd *cobra.Command, args []string) error {
		slug, _ := cmd.Flags().GetString("slug")
		if slug == "" {
			return fmt.Errorf("--slug is required")
		}

		env, cleanup, err := openCLIEnv()
		if err != nil {
			return err
		}
		defer cleanup()

		ids, err := env.resourceAdminSvc.ListRuntimeClientIDs(cmd.Context(), slug)
		if err != nil {
			return fmt.Errorf("list runtime client_ids: %w", err)
		}
		jsonOut, _ := cmd.Flags().GetBool("json")
		if jsonOut {
			return writeJSON(cmd.OutOrStdout(), map[string]any{"client_ids": orEmpty(ids)})
		}
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "slug=%s client_ids=[%s]\n", slug, strings.Join(ids, ","))
		return nil
	},
}

// orEmpty mirrors the HTTP layer's nil→[] normalization so JSON CLI output
// emits an array, not null.
func orEmpty(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

// --- resource delete ---

var resourceDeleteCmd = &cobra.Command{
	Use:   "delete",
	Short: "Delete a resource",
	RunE: func(cmd *cobra.Command, args []string) error {
		id, _ := cmd.Flags().GetString("id")
		if id == "" {
			return fmt.Errorf("--id is required")
		}

		env, cleanup, err := openCLIEnv()
		if err != nil {
			return err
		}
		defer cleanup()

		if err := env.resourceAdminSvc.Delete(cmd.Context(), id); err != nil {
			return fmt.Errorf("delete resource: %w", err)
		}
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "resource deleted: id=%s\n", id)
		return nil
	},
}

// readScopesFromFlags parses --scopes (repeated, pipe-delimited) and
// --scopes-file (JSON array). The two are mutually exclusive; absence of
// both returns nil (let the caller decide what "absent" means).
func readScopesFromFlags(cmd *cobra.Command) ([]resource.Scope, error) {
	scopesFlag, _ := cmd.Flags().GetStringArray("scopes")
	scopesFile, _ := cmd.Flags().GetString("scopes-file")

	if len(scopesFlag) > 0 && scopesFile != "" {
		return nil, fmt.Errorf("--scopes and --scopes-file are mutually exclusive")
	}
	if scopesFile != "" {
		raw, err := readJSONFile(scopesFile, "scopes-file")
		if err != nil {
			return nil, err
		}
		var entries []scopeFileEntry
		if err := json.Unmarshal(raw, &entries); err != nil {
			return nil, fmt.Errorf("--scopes-file: parse JSON: %w", err)
		}
		out := make([]resource.Scope, len(entries))
		for i, e := range entries {
			out[i] = resource.Scope{Name: e.Name, Upstream: e.Upstream, Description: e.Description}
		}
		return out, nil
	}
	if len(scopesFlag) == 0 {
		return nil, nil
	}
	return parseScopeTuples(scopesFlag)
}

// parseScopeTuples decodes one --scopes value per element. Tuple grammar:
//
//	"name|upstream|description"   — full form (any field may be empty)
//	"name|upstream"               — description elided
//	"name|"                       — upstream + description elided (Mint scope)
//	"name"                        — bare name (single-token, both elided)
//
// Pipe is the separator because OAuth scope names and upstream URIs use
// colons (`read:user`, `https://...`); pipe is unreserved in those values.
func parseScopeTuples(raw []string) ([]resource.Scope, error) {
	out := make([]resource.Scope, 0, len(raw))
	for _, r := range raw {
		parts := strings.SplitN(r, "|", 3)
		name := strings.TrimSpace(parts[0])
		if name == "" {
			return nil, fmt.Errorf("--scopes %q: name part is empty", r)
		}
		s := resource.Scope{Name: name}
		if len(parts) >= 2 {
			s.Upstream = parts[1]
		}
		if len(parts) >= 3 {
			s.Description = parts[2]
		}
		out = append(out, s)
	}
	return out, nil
}

// scopeFileEntry mirrors the JSON shape consumed by --scopes-file.
type scopeFileEntry struct {
	Name        string `json:"name"`
	Upstream    string `json:"upstream"`
	Description string `json:"description"`
}

// readPolicyFromFlags assembles a resource.Policy from --policy-allowed-clients
// + --policy-allowed-return-urls + --policy-runtime-client-ids. Returns nil if
// none of the flags was supplied (caller decides whether absence means "leave
// unchanged" via PATCH or "use permissive default" via Create).
func readPolicyFromFlags(cmd *cobra.Command) *resource.Policy {
	clientsTouched := cmd.Flags().Changed("policy-allowed-clients")
	urlsTouched := cmd.Flags().Changed("policy-allowed-return-urls")
	runtimeTouched := cmd.Flags().Changed("policy-runtime-client-ids")
	if !clientsTouched && !urlsTouched && !runtimeTouched {
		return nil
	}

	out := &resource.Policy{}
	if clientsTouched {
		v, _ := cmd.Flags().GetStringSlice("policy-allowed-clients")
		out.Exchange = resource.ExchangePolicy{AllowedClientIDs: filterEmpty(v)}
	}
	if urlsTouched {
		v, _ := cmd.Flags().GetStringSlice("policy-allowed-return-urls")
		out.Connect = resource.ConnectPolicy{AllowedReturnURLs: filterEmpty(v)}
	}
	if runtimeTouched {
		v, _ := cmd.Flags().GetStringSlice("policy-runtime-client-ids")
		out.Runtime = resource.RuntimePolicy{ClientIDs: filterEmpty(v)}
	}
	return out
}

func filterEmpty(in []string) []string {
	out := make([]string, 0, len(in))
	for _, s := range in {
		if s != "" {
			out = append(out, s)
		}
	}
	return out
}

// formatScopes renders a slice of scopes as a compact human-readable
// summary used by `resource list` / `resource get`. Shows the scope name
// plus the upstream mapping for Broker resources.
func formatScopes(scopes []resource.Scope) string {
	if len(scopes) == 0 {
		return "[]"
	}
	parts := make([]string, len(scopes))
	for i, s := range scopes {
		if s.Upstream != "" && s.Upstream != s.Name {
			parts[i] = s.Name + "→" + s.Upstream
		} else {
			parts[i] = s.Name
		}
	}
	return "[" + strings.Join(parts, ",") + "]"
}

func init() {
	resourceListCmd.Flags().String("backend-kind", "", "Filter by backend kind: mint | broker")
	resourceListCmd.Flags().String("broker-provider", "", "Filter by broker provider id")
	resourceListCmd.Flags().Bool("json", false, "Emit JSON instead of human-readable lines")

	resourceGetCmd.Flags().String("id", "", "Resource id (required)")
	resourceGetCmd.Flags().Bool("json", false, "Emit JSON instead of human-readable lines")

	resourceCreateCmd.Flags().String("slug", "", "Resource slug (required)")
	resourceCreateCmd.Flags().String("uri", "", "Resource URI (optional)")
	resourceCreateCmd.Flags().String("backend-kind", "", "Backend kind: mint | broker (required)")
	resourceCreateCmd.Flags().String("broker-provider", "", "Broker provider id (required for broker resources)")
	resourceCreateCmd.Flags().String("display-name", "", "Human-readable display name")
	resourceCreateCmd.Flags().String("description", "", "Free-form description (kept for forward compat; not persisted today)")
	resourceCreateCmd.Flags().StringArray("scopes", nil,
		"Repeatable scope tuple 'name|upstream|description' (any field optional). "+
			"Mutually exclusive with --scopes-file.")
	resourceCreateCmd.Flags().String("scopes-file", "",
		"Path to JSON file holding an array of {name, upstream, description}. "+
			"Mutually exclusive with --scopes.")
	resourceCreateCmd.Flags().StringSlice("policy-allowed-clients", nil,
		"Comma-separated client_ids permitted to act as the actor at /oauth/token. Empty = any.")
	resourceCreateCmd.Flags().StringSlice("policy-allowed-return-urls", nil,
		"Comma-separated return URLs accepted by the broker connect flow.")
	resourceCreateCmd.Flags().StringSlice("policy-runtime-client-ids", nil,
		"Comma-separated client_ids authorized to act AS this Resource at runtime "+
			". Empty = default-deny (no client may act as this Resource).")

	resourceUpdateCmd.Flags().String("id", "", "Resource id (required)")
	resourceUpdateCmd.Flags().String("slug", "", "New slug")
	resourceUpdateCmd.Flags().String("uri", "", "New URI")
	resourceUpdateCmd.Flags().String("backend-kind", "", "New backend kind: mint | broker")
	resourceUpdateCmd.Flags().String("broker-provider", "", "New broker provider id")
	resourceUpdateCmd.Flags().String("display-name", "", "New display name")
	resourceUpdateCmd.Flags().StringArray("scopes", nil, "Replacement scope tuples (see `create --help`)")
	resourceUpdateCmd.Flags().String("scopes-file", "", "Path to JSON file with replacement scopes")
	resourceUpdateCmd.Flags().Bool("scopes-clear", false, "Clear scopes (set to empty)")
	resourceUpdateCmd.Flags().StringSlice("policy-allowed-clients", nil, "Replacement allowlist of client_ids")
	resourceUpdateCmd.Flags().StringSlice("policy-allowed-return-urls", nil, "Replacement allowlist of return URLs")
	resourceUpdateCmd.Flags().StringSlice("policy-runtime-client-ids", nil, "Replacement runtime.client_ids list")
	resourceUpdateCmd.Flags().Bool("policy-clear", false, "Clear the entire policy field (allowlists become empty)")

	resourceDeleteCmd.Flags().String("id", "", "Resource id (required)")

	resourceRuntimeClientAddCmd.Flags().String("slug", "", "Resource slug (required)")
	resourceRuntimeClientAddCmd.Flags().String("client-id", "", "OAuth client_id to authorize as this Resource (required)")
	resourceRuntimeClientRemoveCmd.Flags().String("slug", "", "Resource slug (required)")
	resourceRuntimeClientRemoveCmd.Flags().String("client-id", "", "OAuth client_id to remove (required)")
	resourceRuntimeClientListCmd.Flags().String("slug", "", "Resource slug (required)")
	resourceRuntimeClientListCmd.Flags().Bool("json", false, "Emit JSON instead of human-readable lines")
	resourceRuntimeClientCmd.AddCommand(resourceRuntimeClientAddCmd)
	resourceRuntimeClientCmd.AddCommand(resourceRuntimeClientRemoveCmd)
	resourceRuntimeClientCmd.AddCommand(resourceRuntimeClientListCmd)

	resourceCmd.AddCommand(resourceListCmd)
	resourceCmd.AddCommand(resourceGetCmd)
	resourceCmd.AddCommand(resourceCreateCmd)
	resourceCmd.AddCommand(resourceUpdateCmd)
	resourceCmd.AddCommand(resourceDeleteCmd)
	resourceCmd.AddCommand(resourceRuntimeClientCmd)
}
