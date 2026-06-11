package main

import (
	"context"
	"fmt"

	"github.com/spf13/cobra"
)

// keyCmd is the parent for signing key management subcommands.
var keyCmd = &cobra.Command{
	Use:   "key",
	Short: "Manage signing keys",
	Args:  cobra.NoArgs, // unknown subcommand → loud error (see admin.go)
	RunE:  func(cmd *cobra.Command, _ []string) error { return cmd.Help() },
}

// --- key rotate ---

var keyRotateCmd = &cobra.Command{
	Use:   "rotate",
	Short: "Rotate the signing key",
	RunE: func(cmd *cobra.Command, args []string) error {
		jwksSvc, cleanup, err := openKeyRotationCLI()
		if err != nil {
			return err
		}
		defer cleanup()

		key, err := jwksSvc.RotateKey(context.Background())
		if err != nil {
			return fmt.Errorf("rotate key: %w", err)
		}

		fmt.Printf("key rotated: kid=%s alg=%s\n", key.KeyID, key.Algorithm)
		return nil
	},
}

// --- key list ---

var keyListCmd = &cobra.Command{
	Use:   "list",
	Short: "List signing keys",
	RunE: func(cmd *cobra.Command, args []string) error {
		jwksSvc, cleanup, err := openKeyRotationCLI()
		if err != nil {
			return err
		}
		defer cleanup()

		jwks, err := jwksSvc.BuildJWKS(context.Background())
		if err != nil {
			return fmt.Errorf("build jwks: %w", err)
		}

		for i, k := range jwks.Keys {
			status := "previous"
			if i == 0 {
				status = "current"
			}
			fmt.Printf("kid=%s alg=%s use=%s status=%s\n", k.KeyID, k.Algorithm, k.Use, status)
		}
		if len(jwks.Keys) == 0 {
			fmt.Println("no signing keys found")
		}
		return nil
	},
}

func init() {
	keyCmd.AddCommand(keyRotateCmd)
	keyCmd.AddCommand(keyListCmd)
}
