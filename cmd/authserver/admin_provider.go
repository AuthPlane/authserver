package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/spf13/cobra"

	"github.com/authplane/authserver/internal/admin/dto"
	"github.com/authplane/authserver/internal/domain/resource"
	"github.com/authplane/authserver/internal/ports/input"
)

// providerCmd is the parent for broker-provider management subcommands.
// Replaces the legacy `connector` subcommand (the backing
// connector_config service is gone).
var providerCmd = &cobra.Command{
	Use:   "provider",
	Short: "Manage broker providers",
	Long: "Manage broker providers (upstream OAuth apps, API-key vendors, " +
		"service-account JSON owners) shared by Broker resources.",
	Args: cobra.NoArgs, // unknown subcommand → loud error (see admin.go)
	RunE: func(cmd *cobra.Command, _ []string) error { return cmd.Help() },
}

// --- provider list ---

var providerListCmd = &cobra.Command{
	Use:   "list",
	Short: "List broker providers",
	RunE: func(cmd *cobra.Command, args []string) error {
		env, cleanup, err := openCLIEnv()
		if err != nil {
			return err
		}
		defer cleanup()

		rows, err := env.brokerProviderAdminSvc.List(cmd.Context())
		if err != nil {
			return fmt.Errorf("list providers: %w", err)
		}

		jsonOut, _ := cmd.Flags().GetBool("json")
		if jsonOut {
			views := make([]dto.BrokerProviderView, len(rows))
			for i, p := range rows {
				views[i] = dto.BrokerProviderToView(p)
			}
			return writeJSON(cmd.OutOrStdout(), views)
		}

		if len(rows) == 0 {
			_, _ = fmt.Fprintln(cmd.OutOrStdout(), "no providers found")
			return nil
		}
		for _, p := range rows {
			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "id=%s slug=%s display_name=%q protocol=%s\n",
				p.ID, p.Slug, p.DisplayName, p.Protocol)
		}
		return nil
	},
}

// --- provider get ---

var providerGetCmd = &cobra.Command{
	Use:   "get",
	Short: "Get a broker provider by id",
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

		p, err := env.brokerProviderAdminSvc.GetByID(cmd.Context(), id)
		if err != nil {
			return fmt.Errorf("get provider: %w", err)
		}

		jsonOut, _ := cmd.Flags().GetBool("json")
		if jsonOut {
			return writeJSON(cmd.OutOrStdout(), dto.BrokerProviderToView(p))
		}
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "id=%s slug=%s display_name=%q protocol=%s\n",
			p.ID, p.Slug, p.DisplayName, p.Protocol)
		return nil
	},
}

// --- provider create ---

var providerCreateCmd = &cobra.Command{
	Use:   "create",
	Short: "Create a broker provider",
	Long: "Create a broker provider. --config-data points to a file holding " +
		"the protocol-specific JSON. For OAuth providers the JSON's " +
		"`client_secret_ref` field carries the NAME of the env var the " +
		"AS will look up at runtime, NOT the secret value itself.",
	RunE: func(cmd *cobra.Command, args []string) error {
		slug, _ := cmd.Flags().GetString("slug")
		displayName, _ := cmd.Flags().GetString("display-name")
		protocol, _ := cmd.Flags().GetString("protocol")
		configPath, _ := cmd.Flags().GetString("config-data")

		if slug == "" {
			return fmt.Errorf("--slug is required")
		}
		if displayName == "" {
			return fmt.Errorf("--display-name is required")
		}
		if protocol == "" {
			return fmt.Errorf("--protocol is required")
		}
		if configPath == "" {
			return fmt.Errorf("--config-data is required (path to JSON file)")
		}

		raw, err := readJSONFile(configPath, "config-data")
		if err != nil {
			return err
		}

		env, cleanup, err := openCLIEnv()
		if err != nil {
			return err
		}
		defer cleanup()

		p := &resource.BrokerProvider{
			Slug:        slug,
			DisplayName: displayName,
			Protocol:    resource.Protocol(protocol),
			ConfigData:  raw,
		}
		if createErr := env.brokerProviderAdminSvc.Create(cmd.Context(), p); createErr != nil {
			return fmt.Errorf("create provider: %w", createErr)
		}

		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "provider created: id=%s slug=%s\n", p.ID, p.Slug)
		return nil
	},
}

// --- provider update ---

var providerUpdateCmd = &cobra.Command{
	Use:   "update",
	Short: "Update a broker provider (PATCH)",
	Long: "Update a broker provider with PATCH semantics: omitted flags " +
		"leave their fields unchanged.",
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

		var patch input.BrokerProviderPatch
		if cmd.Flags().Changed("slug") {
			v, _ := cmd.Flags().GetString("slug")
			patch.Slug = &v
		}
		if cmd.Flags().Changed("display-name") {
			v, _ := cmd.Flags().GetString("display-name")
			patch.DisplayName = &v
		}
		if cmd.Flags().Changed("protocol") {
			v, _ := cmd.Flags().GetString("protocol")
			proto := resource.Protocol(v)
			patch.Protocol = &proto
		}
		if cmd.Flags().Changed("config-data") {
			path, _ := cmd.Flags().GetString("config-data")
			raw, readErr := readJSONFile(path, "config-data")
			if readErr != nil {
				return readErr
			}
			rm := json.RawMessage(raw)
			patch.ConfigData = &rm
		}

		updated, err := env.brokerProviderAdminSvc.Patch(cmd.Context(), id, patch)
		if err != nil {
			return fmt.Errorf("update provider: %w", err)
		}
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "provider updated: id=%s slug=%s\n", updated.ID, updated.Slug)
		return nil
	},
}

// --- provider delete ---

var providerDeleteCmd = &cobra.Command{
	Use:   "delete",
	Short: "Delete a broker provider",
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

		if err := env.brokerProviderAdminSvc.Delete(cmd.Context(), id); err != nil {
			return fmt.Errorf("delete provider: %w", err)
		}
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "provider deleted: id=%s\n", id)
		return nil
	},
}

// readJSONFile loads a JSON document from path and returns its bytes.
// Validates that the file exists, is under maxJSONFileSize bytes, and is
// syntactically valid JSON; the service layer owns schema validation.
func readJSONFile(path, flag string) ([]byte, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("read --%s file %q: %w", flag, path, err)
	}
	if info.Size() > maxJSONFileSize {
		return nil, fmt.Errorf("--%s file %q exceeds %d bytes", flag, path, maxJSONFileSize)
	}
	raw, err := os.ReadFile(path) // #nosec G304 — path is operator-supplied via CLI flag; bounded by the size cap above.
	if err != nil {
		return nil, fmt.Errorf("read --%s file %q: %w", flag, path, err)
	}
	if !json.Valid(raw) {
		return nil, fmt.Errorf("--%s file %q is not valid JSON", flag, path)
	}
	return raw, nil
}

// maxJSONFileSize bounds operator-supplied JSON files (--config-data,
// --scopes-file). 1 MB matches the HTTP admin layer's body cap.
const maxJSONFileSize = 1 << 20

// writeJSON emits indented JSON to w with a trailing newline. Shared by the
// resource / provider / grant / issuance subcommands' --json output.
func writeJSON(w io.Writer, v any) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

func init() {
	providerListCmd.Flags().Bool("json", false, "Emit JSON instead of human-readable lines")

	providerGetCmd.Flags().String("id", "", "Provider id (required)")
	providerGetCmd.Flags().Bool("json", false, "Emit JSON instead of human-readable lines")

	providerCreateCmd.Flags().String("slug", "", "Provider slug (required)")
	providerCreateCmd.Flags().String("display-name", "", "Human-readable name (required)")
	providerCreateCmd.Flags().String("protocol", "", "Protocol: oauth | api_key | service_account (required)")
	providerCreateCmd.Flags().String("config-data", "",
		"Path to JSON file holding the provider's protocol-specific config "+
			"(required). For OAuth, client_secret_ref is the env var NAME, not the secret.")

	providerUpdateCmd.Flags().String("id", "", "Provider id (required)")
	providerUpdateCmd.Flags().String("slug", "", "New slug")
	providerUpdateCmd.Flags().String("display-name", "", "New display name")
	providerUpdateCmd.Flags().String("protocol", "", "New protocol: oauth | api_key | service_account")
	providerUpdateCmd.Flags().String("config-data", "", "Path to JSON file with replacement config")

	providerDeleteCmd.Flags().String("id", "", "Provider id (required)")

	providerCmd.AddCommand(providerListCmd)
	providerCmd.AddCommand(providerGetCmd)
	providerCmd.AddCommand(providerCreateCmd)
	providerCmd.AddCommand(providerUpdateCmd)
	providerCmd.AddCommand(providerDeleteCmd)
}
