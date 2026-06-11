package main

import (
	"context"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/authplane/authserver/internal/adapters/storage"
	"github.com/authplane/authserver/internal/observability"
)

var migrateCmd = &cobra.Command{
	Use:   "migrate",
	Short: "Run database migrations",
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg, err := loadConfig()
		if err != nil {
			return fmt.Errorf("load config: %w", err)
		}

		obs := observability.NewNoop()
		ds, err := storage.Open(context.Background(), cfg.Storage, obs)
		if err != nil {
			return fmt.Errorf("open database: %w", err)
		}
		defer func() { _ = ds.Close() }()

		if err := ds.Migrate(context.Background()); err != nil {
			return fmt.Errorf("migrate: %w", err)
		}

		fmt.Println("migrations applied successfully")
		return nil
	},
}
