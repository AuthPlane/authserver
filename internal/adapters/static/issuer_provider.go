package static

import (
	"context"
	"strings"

	"github.com/authplane/authserver/internal/ports/output"
)

// Compile-time conformance: IssuerProvider satisfies output.IssuerProvider.
var _ output.IssuerProvider = (*IssuerProvider)(nil)

// IssuerProvider returns the same configured issuer URL for every call,
// regardless of ctx. It is the byte-identity-preserving default used by
// cmd/authserver/serve.go.
type IssuerProvider struct {
	value string
}

// NewIssuerProvider builds an IssuerProvider, trimming any trailing slash so
// callers that concatenate "/oauth/token" etc. do not produce double-slash
// URLs. Matches the pre-existing trim convention in mint_issuer.go.
// Panics if the trimmed value is empty to surface operator typos at startup.
func NewIssuerProvider(issuer string) *IssuerProvider {
	trimmed := strings.TrimRight(issuer, "/")
	if trimmed == "" {
		panic("static.NewIssuerProvider: issuer must be non-empty (post trailing-slash trim)")
	}
	return &IssuerProvider{value: trimmed}
}

// Issuer returns the configured value. Ignores ctx. Always returns a nil error.
func (p *IssuerProvider) Issuer(_ context.Context) (string, error) {
	return p.value, nil
}
