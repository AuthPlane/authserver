package output

import "context"

// RuntimeSettingsStore manages persistent runtime configuration settings.
// Settings are key-value pairs stored in the runtime_settings table.
type RuntimeSettingsStore interface {
	// Get returns the value for a setting key. Returns "" if not found.
	Get(ctx context.Context, key string) (string, error)

	// Set persists a setting key-value pair (upsert).
	Set(ctx context.Context, key, value string) error
}
