package main

import "github.com/spf13/cobra"

// adminCmd is the parent for all admin subcommands:
//
//	authserver admin client ...
//	authserver admin user ...
//	authserver admin key ...
//	authserver admin dcr ...
//	authserver admin resource ...
//	authserver admin provider ...
//	authserver admin grant ...
//	authserver admin issuance ...
var adminCmd = &cobra.Command{
	Use:   "admin",
	Short: "Administrative operations",
	Long:  "Manage clients, users, keys, resources, providers, grants, and issuances via CLI.",
	// Args=NoArgs + RunE=help is the cobra-idiomatic way to make typos like
	// `authserver admin resource-server list` fail loudly (`unknown command
	// "resource-server" for "authserver admin"`, exit 1) instead of silently
	// falling through to the help text with exit 0. Without RunE the parent
	// is non-Runnable and cobra short-circuits to flag.ErrHelp BEFORE
	// reaching the Args validator, so NoArgs alone is insufficient — see
	// cobra@v1.10.2/command.go:955. The RunE makes the parent runnable for
	// the no-args path; NoArgs catches the typo path.
	Args: cobra.NoArgs,
	RunE: func(cmd *cobra.Command, _ []string) error { return cmd.Help() },
}

func init() {
	adminCmd.AddCommand(clientCmd)
	adminCmd.AddCommand(userCmd)
	adminCmd.AddCommand(keyCmd)
	adminCmd.AddCommand(dcrCmd)
	adminCmd.AddCommand(resourceCmd)
	adminCmd.AddCommand(providerCmd)
	adminCmd.AddCommand(grantCmd)
	adminCmd.AddCommand(issuanceCmd)
	adminCmd.AddCommand(frontingCmd)
}
