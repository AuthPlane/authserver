package main

import (
	"context"
	"fmt"

	"github.com/spf13/cobra"
)

// dcrCmd is the parent for DCR settings subcommands.
var dcrCmd = &cobra.Command{
	Use:   "dcr",
	Short: "Manage Dynamic Client Registration settings",
	Args:  cobra.NoArgs, // unknown subcommand → loud error (see admin.go)
	RunE:  func(cmd *cobra.Command, _ []string) error { return cmd.Help() },
}

// --- dcr get ---

var dcrGetCmd = &cobra.Command{
	Use:   "get",
	Short: "Show current DCR settings",
	RunE: func(cmd *cobra.Command, args []string) error {
		env, cleanup, err := openAdminCLI()
		if err != nil {
			return err
		}
		defer cleanup()

		mode, err := env.ds.RuntimeSettings().Get(context.Background(), "dcr_mode")
		if err != nil {
			return fmt.Errorf("read dcr mode: %w", err)
		}
		if mode == "" {
			mode = env.cfg.DCR.Mode // fall back to config file default
		}
		fmt.Printf("DCR mode: %s\n", mode)
		return nil
	},
}

// --- dcr set ---

var dcrSetCmd = &cobra.Command{
	Use:   "set",
	Short: "Update DCR settings",
	RunE: func(cmd *cobra.Command, args []string) error {
		mode, _ := cmd.Flags().GetString("mode")
		if mode == "" {
			return fmt.Errorf("--mode is required (open, admin_only, approved_redirects)")
		}

		valid := map[string]bool{"open": true, "admin_only": true, "approved_redirects": true}
		if !valid[mode] {
			return fmt.Errorf("invalid mode %q: must be open, admin_only, or approved_redirects", mode)
		}

		env, cleanup, err := openAdminCLI()
		if err != nil {
			return err
		}
		defer cleanup()

		if err := env.ds.RuntimeSettings().Set(context.Background(), "dcr_mode", mode); err != nil {
			return fmt.Errorf("persist dcr mode: %w", err)
		}
		fmt.Printf("DCR mode set to: %s\n", mode)
		fmt.Println("Note: restart the server for the change to take effect, or use the admin API for live updates.")
		return nil
	},
}

func init() {
	dcrSetCmd.Flags().String("mode", "", "DCR mode: open, admin_only, approved_redirects")

	dcrCmd.AddCommand(dcrGetCmd)
	dcrCmd.AddCommand(dcrSetCmd)
}
