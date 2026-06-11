// Package main is the entrypoint for the authserver binary.
package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var version = "dev"

// cfgFile holds the --config flag value, available to all subcommands.
var cfgFile string

func main() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

var rootCmd = &cobra.Command{
	Use:   "authserver",
	Short: "Authplane MCP Authorization Server",
	Long:  "A self-hosted OAuth 2.1 Authorization Server purpose-built for MCP.",
	// SilenceUsage suppresses the auto-printed usage tree on RunE errors —
	// cobra's default is to dump the full help on every failed RunE, which
	// drowns the actual error message.
	SilenceUsage: true,
	// SilenceErrors stops cobra from printing the error itself; main() owns
	// the single error path (`fmt.Fprintf(os.Stderr, "error: %v\n", err);
	// os.Exit(1)`). Without this the operator sees the same message twice
	// on every failure: once from cobra's `Error: ...` line, once from
	// main()'s `error: ...` line.
	SilenceErrors: true,
}

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print version",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf("authserver %s\n", version)
	},
}

func init() {
	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file path (default: auto-detect)")

	rootCmd.AddCommand(versionCmd)
	rootCmd.AddCommand(serveCmd)
	rootCmd.AddCommand(migrateCmd)
	rootCmd.AddCommand(adminCmd)
	rootCmd.AddCommand(purgeCmd)
}
