package main

import (
	"fmt"
	"time"

	"github.com/spf13/cobra"

	"github.com/authplane/authserver/internal/admin/dto"
)

// grantCmd is the parent for grant management subcommands. Wraps the
// unified GrantAdmin port which spans consent_grants and broker_grants.
// Replaces the legacy `allowlist` subcommand (cross-client allowlists
// have been folded into per-Resource policy).
var grantCmd = &cobra.Command{
	Use:   "grant",
	Short: "Inspect + revoke user grants (consent + broker)",
	Long: "Read and revoke user grants. A user has up to two shapes:\n" +
		"  - consent_grants — per-MCP user→Agent authorization\n" +
		"  - broker_grants — per-provider upstream credential\n" +
		"Both surface here; revocation is split because the cascade " +
		"semantics differ.",
	Args: cobra.NoArgs, // unknown subcommand → loud error (see admin.go)
	RunE: func(cmd *cobra.Command, _ []string) error { return cmd.Help() },
}

// --- grant list-user-grants ---

var grantListUserGrantsCmd = &cobra.Command{
	Use:   "list-user-grants",
	Short: "List a user's consent and broker grants",
	RunE: func(cmd *cobra.Command, args []string) error {
		userID, _ := cmd.Flags().GetString("user")
		if userID == "" {
			return fmt.Errorf("--user is required")
		}

		env, cleanup, err := openCLIEnv()
		if err != nil {
			return err
		}
		defer cleanup()

		got, err := env.grantAdminSvc.ListForUser(cmd.Context(), userID)
		if err != nil {
			return fmt.Errorf("list user grants: %w", err)
		}

		jsonOut, _ := cmd.Flags().GetBool("json")
		if jsonOut {
			return writeJSON(cmd.OutOrStdout(), dto.UserGrantsToView(got))
		}

		out := cmd.OutOrStdout()
		_, _ = fmt.Fprintf(out, "consent_grants (%d):\n", len(got.Consent))
		for _, g := range got.Consent {
			_, _ = fmt.Fprintf(out, "  id=%s user_id=%s client_id=%s resource_id=%s scopes=%v%s\n",
				g.ID, g.UserID, g.ClientID, g.ResourceID, g.Scopes, revokedSuffix(g.RevokedAt))
		}
		_, _ = fmt.Fprintf(out, "broker_grants (%d):\n", len(got.Broker))
		for _, g := range got.Broker {
			_, _ = fmt.Fprintf(out, "  id=%s user_id=%s broker_provider_id=%s scopes_granted=%v version=%d%s\n",
				g.ID, g.UserID, g.BrokerProviderID, g.ScopesGranted, g.Version, revokedSuffix(g.RevokedAt))
		}
		return nil
	},
}

// --- grant revoke-consent ---

var grantRevokeConsentCmd = &cobra.Command{
	Use:   "revoke-consent",
	Short: "Revoke a consent grant by id (cascades onto live Mint issuances)",
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

		if err := env.grantAdminSvc.RevokeConsent(cmd.Context(), id); err != nil {
			return fmt.Errorf("revoke consent grant: %w", err)
		}
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "revoked consent grant: id=%s\n", id)
		return nil
	},
}

// --- grant revoke-broker ---

var grantRevokeBrokerCmd = &cobra.Command{
	Use:   "revoke-broker",
	Short: "Revoke a broker grant by id (no issuance cascade — upstream tokens are not AS-revocable)",
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

		if err := env.grantAdminSvc.RevokeBroker(cmd.Context(), id); err != nil {
			return fmt.Errorf("revoke broker grant: %w", err)
		}
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "revoked broker grant: id=%s\n", id)
		return nil
	},
}

// revokedSuffix returns the empty string for active rows or
// " revoked_at=<RFC3339>" for revoked ones. Used in human-readable output.
func revokedSuffix(rev *time.Time) string {
	if rev == nil {
		return ""
	}
	return " revoked_at=" + rev.UTC().Format(time.RFC3339)
}

func init() {
	grantListUserGrantsCmd.Flags().String("user", "", "User id (required)")
	grantListUserGrantsCmd.Flags().Bool("json", false, "Emit JSON instead of human-readable lines")

	grantRevokeConsentCmd.Flags().String("id", "", "Consent grant id (required)")

	grantRevokeBrokerCmd.Flags().String("id", "", "Broker grant id (required)")

	grantCmd.AddCommand(grantListUserGrantsCmd)
	grantCmd.AddCommand(grantRevokeConsentCmd)
	grantCmd.AddCommand(grantRevokeBrokerCmd)
}
