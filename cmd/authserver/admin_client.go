package main

import (
	"context"
	"fmt"
	"strings"

	"github.com/spf13/cobra"

	"github.com/authplane/authserver/internal/ports/input"
)

// clientCmd is the parent for client management subcommands.
var clientCmd = &cobra.Command{
	Use:   "client",
	Short: "Manage OAuth clients",
	Args:  cobra.NoArgs, // unknown subcommand → loud error (see admin.go)
	RunE:  func(cmd *cobra.Command, _ []string) error { return cmd.Help() },
}

// --- client create ---

var clientCreateCmd = &cobra.Command{
	Use:   "create",
	Short: "Create a new OAuth client",
	RunE: func(cmd *cobra.Command, args []string) error {
		bindEnv(cmd, "name", "AUTHSERVER_CLIENT_NAME")
		bindEnv(cmd, "grant-types", "AUTHSERVER_CLIENT_GRANT_TYPES")
		bindEnv(cmd, "redirect-uris", "AUTHSERVER_CLIENT_REDIRECT_URIS")
		bindEnv(cmd, "scope", "AUTHSERVER_CLIENT_SCOPE")
		bindEnv(cmd, "auth-method", "AUTHSERVER_CLIENT_AUTH_METHOD")

		name, _ := cmd.Flags().GetString("name")
		grantTypesStr, _ := cmd.Flags().GetString("grant-types")
		redirectURIsStr, _ := cmd.Flags().GetString("redirect-uris")
		scopeStr, _ := cmd.Flags().GetString("scope")
		authMethod, _ := cmd.Flags().GetString("auth-method")
		isAgent, _ := cmd.Flags().GetBool("agent")
		agentDesc, _ := cmd.Flags().GetString("agent-description")

		if name == "" {
			return fmt.Errorf("--name is required")
		}

		var grantTypes []string
		if grantTypesStr != "" {
			grantTypes = strings.Split(grantTypesStr, ",")
		}
		var redirectURIs []string
		if redirectURIsStr != "" {
			redirectURIs = strings.Split(redirectURIsStr, ",")
		}

		env, cleanup, err := openAdminCLI()
		if err != nil {
			return err
		}
		defer cleanup()

		resp, err := env.adminSvc.CreateClient(context.Background(), input.CreateClientRequest{
			Name:                    name,
			RedirectURIs:            redirectURIs,
			GrantTypes:              grantTypes,
			TokenEndpointAuthMethod: authMethod,
			Scope:                   scopeStr,
			IsAgent:                 isAgent,
			AgentDescription:        agentDesc,
		})
		if err != nil {
			return fmt.Errorf("create client: %w", err)
		}

		fmt.Printf("client created: id=%s name=%s\n", resp.Client.ID, resp.Client.Name)
		if resp.ClientSecret != "" {
			fmt.Printf("client_secret=%s (shown once, store securely)\n", resp.ClientSecret)
		}
		return nil
	},
}

// --- client update ---

var clientUpdateCmd = &cobra.Command{
	Use:   "update",
	Short: "Update an existing client",
	RunE: func(cmd *cobra.Command, args []string) error {
		bindEnv(cmd, "id", "AUTHSERVER_CLIENT_ID")
		clientID, _ := cmd.Flags().GetString("id")

		if clientID == "" {
			return fmt.Errorf("--id is required")
		}

		env, cleanup, err := openAdminCLI()
		if err != nil {
			return err
		}
		defer cleanup()

		var req input.UpdateClientRequest

		if cmd.Flags().Changed("name") {
			v, _ := cmd.Flags().GetString("name")
			req.Name = &v
		}
		if cmd.Flags().Changed("redirect-uris") {
			v, _ := cmd.Flags().GetString("redirect-uris")
			uris := strings.Split(v, ",")
			req.RedirectURIs = &uris
		}
		if cmd.Flags().Changed("grant-types") {
			v, _ := cmd.Flags().GetString("grant-types")
			gts := strings.Split(v, ",")
			req.GrantTypes = &gts
		}
		if cmd.Flags().Changed("scope") {
			v, _ := cmd.Flags().GetString("scope")
			req.Scope = &v
		}

		updated, err := env.adminSvc.UpdateClient(context.Background(), clientID, req)
		if err != nil {
			return fmt.Errorf("update client: %w", err)
		}

		fmt.Printf("client updated: id=%s name=%s\n", updated.ID, updated.Name)
		return nil
	},
}

// --- client delete ---

var clientDeleteCmd = &cobra.Command{
	Use:   "delete",
	Short: "Permanently delete a client",
	RunE: func(cmd *cobra.Command, args []string) error {
		bindEnv(cmd, "id", "AUTHSERVER_CLIENT_ID")
		clientID, _ := cmd.Flags().GetString("id")
		force, _ := cmd.Flags().GetBool("force")

		if clientID == "" {
			return fmt.Errorf("--id is required")
		}

		env, cleanup, err := openAdminCLI()
		if err != nil {
			return err
		}
		defer cleanup()

		if err := env.adminSvc.DeleteClient(context.Background(), clientID, force); err != nil {
			return fmt.Errorf("delete client: %w", err)
		}

		fmt.Printf("client deleted: id=%s\n", clientID)
		return nil
	},
}

// --- client rotate-secret ---

var clientRotateSecretCmd = &cobra.Command{
	Use:   "rotate-secret",
	Short: "Rotate a client's secret",
	RunE: func(cmd *cobra.Command, args []string) error {
		bindEnv(cmd, "id", "AUTHSERVER_CLIENT_ID")
		clientID, _ := cmd.Flags().GetString("id")

		if clientID == "" {
			return fmt.Errorf("--id is required")
		}

		env, cleanup, err := openAdminCLI()
		if err != nil {
			return err
		}
		defer cleanup()

		resp, err := env.adminSvc.RotateClientSecret(context.Background(), clientID)
		if err != nil {
			return fmt.Errorf("rotate secret: %w", err)
		}

		fmt.Printf("secret rotated: client_id=%s\n", resp.ClientID)
		fmt.Printf("client_secret=%s (shown once, store securely)\n", resp.ClientSecret)
		return nil
	},
}

// --- client list ---

var clientListCmd = &cobra.Command{
	Use:   "list",
	Short: "List registered clients",
	RunE: func(cmd *cobra.Command, args []string) error {
		env, cleanup, err := openAdminCLI()
		if err != nil {
			return err
		}
		defer cleanup()

		status, _ := cmd.Flags().GetString("status")
		source, _ := cmd.Flags().GetString("source")
		limit, _ := cmd.Flags().GetInt("limit")

		clients, err := env.adminSvc.ListClients(cmd.Context(), input.ClientFilter{
			Status: status,
			Source: source,
			Limit:  limit,
		})
		if err != nil {
			return fmt.Errorf("list clients: %w", err)
		}

		for _, c := range clients {
			fmt.Printf("id=%s name=%s status=%s source=%s\n", c.ID, c.Name, c.Status, c.RegistrationSource)
		}
		if len(clients) == 0 {
			fmt.Println("no clients found")
		}
		return nil
	},
}

func init() {
	// client create flags (stubs for ).
	clientCreateCmd.Flags().String("name", "", "Client name (required)")
	clientCreateCmd.Flags().String("grant-types", "authorization_code", "Comma-separated grant types")
	clientCreateCmd.Flags().String("redirect-uris", "", "Comma-separated redirect URIs")
	clientCreateCmd.Flags().String("scope", "", "Space-separated scopes")
	clientCreateCmd.Flags().String("auth-method", "none", "Token endpoint auth method")
	clientCreateCmd.Flags().Bool("agent", false, "Register as agent client")
	clientCreateCmd.Flags().String("agent-description", "", "Agent description (max 500 chars)")

	// client update flags (stubs for ).
	clientUpdateCmd.Flags().String("id", "", "Client ID (required)")
	clientUpdateCmd.Flags().String("name", "", "New client name")
	clientUpdateCmd.Flags().String("redirect-uris", "", "New redirect URIs (comma-separated)")
	clientUpdateCmd.Flags().String("scope", "", "New scopes (space-separated)")
	clientUpdateCmd.Flags().String("grant-types", "", "New grant types (comma-separated)")

	// client delete flags (stubs for ).
	clientDeleteCmd.Flags().String("id", "", "Client ID (required)")
	clientDeleteCmd.Flags().Bool("force", false, "Force delete even with active tokens")

	// client rotate-secret flags (stubs for ).
	clientRotateSecretCmd.Flags().String("id", "", "Client ID (required)")

	// client list flags.
	clientListCmd.Flags().String("status", "", "Filter by status (active, suspended, revoked)")
	clientListCmd.Flags().String("source", "", "Filter by registration source (dcr, admin)")
	clientListCmd.Flags().Int("limit", 100, "Maximum results")

	clientCmd.AddCommand(clientCreateCmd)
	clientCmd.AddCommand(clientUpdateCmd)
	clientCmd.AddCommand(clientDeleteCmd)
	clientCmd.AddCommand(clientRotateSecretCmd)
	clientCmd.AddCommand(clientListCmd)
}
