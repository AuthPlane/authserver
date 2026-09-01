package output

import "context"

// DCRMode holds the DCR configuration values needed by the service.
// Defined here to avoid importing internal/config from services.
type DCRMode struct {
	Mode              string
	ApprovedRedirects []string
}

// DCRModeProvider resolves the DCR policy (mode + approved redirects) from ctx.
// It is required, not optional: services consume it as a security control and
// fail closed if Get returns an error (RegisterClient/VerifyCIMD reject the
// request rather than fall back to a permissive default). Set applies a
// runtime mode change (admin endpoint): callers pass the mode to apply, and
// whether any other DCRMode field is honored is implementation-defined — the
// static default updates only Mode and preserves the approved-redirects list
// seeded at startup.
type DCRModeProvider interface {
	Get(ctx context.Context) (DCRMode, error)
	Set(ctx context.Context, mode DCRMode) error
}
