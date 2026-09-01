package output

import "context"

// EnabledGrantsProvider resolves the set of grant types the AS is configured to
// honor for a request. The static default returns the boot-time set; a
// substitute provider may resolve it per request. Consumers fail closed when
// Get returns an error (reject the registration rather than fall back to a
// permissive default).
type EnabledGrantsProvider interface {
	Get(ctx context.Context) ([]string, error)
}
