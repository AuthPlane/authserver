package services_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/authplane/authserver/internal/domain/resource"
	"github.com/authplane/authserver/internal/observability"
	"github.com/authplane/authserver/internal/ports/output"
	"github.com/authplane/authserver/internal/services"
)

type environmentKey struct{}

type envIssuerProvider struct {
	byEnv map[string]string
}

func (p *envIssuerProvider) Issuer(ctx context.Context) (string, error) {
	env, _ := ctx.Value(environmentKey{}).(string)
	if v, ok := p.byEnv[env]; ok {
		return v, nil
	}
	return p.byEnv["prod"], nil // fallback
}

// Compile-time guard: the substitute satisfies the port.
var _ output.IssuerProvider = (*envIssuerProvider)(nil)

// failingIssuerProvider always returns an error. Used to verify that
// services wrap the IssuerProvider error with %w so callers can
// errors.Is against the underlying sentinel.
type failingIssuerProvider struct{}

var errIssuerResolve = errors.New("simulated resolve failure")

func (failingIssuerProvider) Issuer(_ context.Context) (string, error) {
	return "", errIssuerResolve
}

// Compile-time guard: failingIssuerProvider satisfies the port.
var _ output.IssuerProvider = failingIssuerProvider{}

// noopSigningKeyProvider is a stub JWKSSigningKeyProvider that panics if
// called — only used in tests where the issuer resolve fires before the
// signing key is fetched.
type noopSigningKeyProvider struct{}

func (noopSigningKeyProvider) GetSigningKey(_ context.Context) (*output.SigningKey, error) {
	panic("noopSigningKeyProvider: GetSigningKey should not be called in this test")
}

// noopIssuanceStore is a stub output.IssuanceStore that panics on any call.
type noopIssuanceStore struct{}

func (noopIssuanceStore) Insert(_ context.Context, _ *resource.Issuance) error {
	panic("noopIssuanceStore: Insert should not be called in this test")
}
func (noopIssuanceStore) GetByID(_ context.Context, _ string) (*resource.Issuance, error) {
	panic("noopIssuanceStore: GetByID should not be called in this test")
}
func (noopIssuanceStore) GetByJTI(_ context.Context, _ string) (*resource.Issuance, error) {
	panic("noopIssuanceStore: GetByJTI should not be called in this test")
}
func (noopIssuanceStore) Revoke(_ context.Context, _ string) error {
	panic("noopIssuanceStore: Revoke should not be called in this test")
}
func (noopIssuanceStore) RevokeFamily(_ context.Context, _, _, _ string) (int, error) {
	panic("noopIssuanceStore: RevokeFamily should not be called in this test")
}
func (noopIssuanceStore) ListForUser(_ context.Context, _ string, _ time.Time) ([]*resource.Issuance, error) {
	panic("noopIssuanceStore: ListForUser should not be called in this test")
}
func (noopIssuanceStore) ListForActor(_ context.Context, _ string, _ time.Time) ([]*resource.Issuance, error) {
	panic("noopIssuanceStore: ListForActor should not be called in this test")
}
func (noopIssuanceStore) ListForResource(_ context.Context, _ string, _ time.Time) ([]*resource.Issuance, error) {
	panic("noopIssuanceStore: ListForResource should not be called in this test")
}
func (noopIssuanceStore) PurgeExpired(_ context.Context, _ time.Time) (int, error) {
	panic("noopIssuanceStore: PurgeExpired should not be called in this test")
}

// TestIssuerProvider_ErrorWrapping_PropagatesToService verifies that a
// service wraps IssuerProvider errors using fmt.Errorf %w so callers
// can use errors.Is against the underlying sentinel. MintIssuer.Issue
// resolves the issuer before fetching the signing key, making it the
// lightest service to exercise this property without integration stores.
func TestIssuerProvider_ErrorWrapping_PropagatesToService(t *testing.T) {
	svc := services.NewMintIssuer(
		noopSigningKeyProvider{},
		noopIssuanceStore{},
		failingIssuerProvider{},
		observability.NewNoop(),
	)

	req := services.IssueRequest{
		Expiry: time.Now().Add(time.Hour),
	}

	_, err := svc.Issue(context.Background(), req)
	if err == nil {
		t.Fatal("expected error from Issue, got nil")
	}
	if !errors.Is(err, errIssuerResolve) {
		t.Errorf("errors.Is(err, errIssuerResolve) = false; got err = %v", err)
	}
}

func TestIssuerProvider_Substitution_PerRequestIssuer(t *testing.T) {
	provider := &envIssuerProvider{
		byEnv: map[string]string{
			"dev":     "https://issuer-dev.example.com",
			"staging": "https://issuer-staging.example.com",
			"prod":    "https://issuer.example.com",
		},
	}

	for _, tc := range []struct{ env, want string }{
		{"dev", "https://issuer-dev.example.com"},
		{"staging", "https://issuer-staging.example.com"},
		{"prod", "https://issuer.example.com"},
		{"", "https://issuer.example.com"}, // empty falls back to prod
	} {
		ctx := context.WithValue(context.Background(), environmentKey{}, tc.env)
		got, err := provider.Issuer(ctx)
		if err != nil {
			t.Errorf("env=%q: unexpected error: %v", tc.env, err)
		}
		if got != tc.want {
			t.Errorf("env=%q: Issuer() = %q, want %q", tc.env, got, tc.want)
		}
	}
}
