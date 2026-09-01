package services

import (
	"context"
	"fmt"

	"github.com/authplane/authserver/internal/ports/output"
)

// resolveEnabledGrants resolves the per-request enabled-grant set shared by every
// client-registration path (CIMD, DCR, admin). It centralizes the one fail-closed
// rule: a nil provider yields a nil slice (the domain validators treat nil as
// "no enforcement" — the test/legacy mode), and a present provider whose Get
// fails returns a wrapped error so the caller rejects the registration rather
// than fall through to a permissive default. Callers record the error on their
// span and return it; the wrap string lives only here.
func resolveEnabledGrants(ctx context.Context, p output.EnabledGrantsProvider) ([]string, error) {
	if p == nil {
		return nil, nil
	}
	grants, err := p.Get(ctx)
	if err != nil {
		return nil, fmt.Errorf("resolve enabled grants: %w", err)
	}
	return grants, nil
}
