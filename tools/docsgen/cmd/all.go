package cmd

import (
	"github.com/spf13/cobra"
)

// newAllCmd runs every generator subcommand in a fixed order, sharing the
// --out directory. Subcommands fail fast: the first error aborts the
// remaining generators so the failure is visible in CI.
func newAllCmd() *cobra.Command {
	c := &cobra.Command{
		Use:   "all",
		Short: "Run every generator (cli, http, env, config) in sequence",
		RunE: func(cmd *cobra.Command, args []string) error {
			// Build fresh subcommand instances; they read --out from the
			// persistent flag set, which propagates from the root.
			subs := []*cobra.Command{
				newCLICmd(),
				newHTTPCmd(),
				newEnvCmd(),
				newConfigCmd(),
				newOpenAPICmd(),
			}
			for _, sub := range subs {
				// Re-parent so the persistent --out flag resolves the
				// same value the user passed at the top level.
				sub.SetContext(cmd.Context())
				sub.Flags().AddFlagSet(cmd.Flags())
				if err := sub.RunE(sub, args); err != nil {
					return err
				}
			}
			return nil
		},
	}
	return c
}
