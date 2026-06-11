package services

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"github.com/authplane/authserver/internal/domain"
	"github.com/authplane/authserver/internal/domain/resource"
)

//  — three-bound enforcement matrix on BrokerIssuer.Issue. Covers the
// -specific surface: bound-D (no active grant → CauseConsentMissing),
// bound-E (upstream scope not granted → CauseScopeInsufficient + the
// upstream-form list of missing scopes), bound-1 (catalog miss surfaces
// ErrScopeNotInCatalog and is NOT a ConsentRequiredError), plus a
// happy-path sanity check that all bounds passing returns a token.
//
// These tests are decoupled from the existing TestBrokerIssuer_Issue_*
// suite so the narrowing contract has its own grep anchor.

func TestBrokerIssuer_Issue_BoundD_NoActiveGrant_PopulatesCauseConsentMissing(t *testing.T) {
	res := newGitHubBrokerResource()
	prov := newGitHubBrokerProvider()

	grants := &mockBrokerGrantStore{
		getFn: func(_ context.Context, _, _ string) (*resource.BrokerGrant, error) {
			return nil, nil
		},
	}
	reg, _ := newRegistryWith(t, "oauth", nil)
	bi := newBrokerIssuer(t, grants, &mockIssuanceStore{}, &mockDataEncryptor{}, reg, nil)

	_, err := bi.Issue(context.Background(), baseRequest(prov, res, []string{"repos.read"}, nil))
	var cre *domain.ConsentRequiredError
	if !errors.As(err, &cre) {
		t.Fatalf("Issue error = %v, want *domain.ConsentRequiredError", err)
	}
	if cre.Cause != domain.CauseConsentMissing {
		t.Errorf("Cause = %q, want %q", cre.Cause, domain.CauseConsentMissing)
	}
	if len(cre.MissingScopes) != 0 {
		t.Errorf("MissingScopes = %v, want nil/empty (bound-D has no scope diagnostic)", cre.MissingScopes)
	}
	if cre.ProviderSlug != prov.Slug {
		t.Errorf("ProviderSlug = %q, want %q", cre.ProviderSlug, prov.Slug)
	}
}

func TestBrokerIssuer_Issue_BoundE_UpstreamScopeNotGranted_PopulatesCauseScopeInsufficient(t *testing.T) {
	res := newGitHubBrokerResource() // catalog: repos.read→repo, users.read→read:user
	prov := newGitHubBrokerProvider()
	// Granted set is missing "repo" — the upstream-form of the requested
	// "repos.read" scope. Bound E rejects.
	grant := activeGrant("user-42", "bp-gh", []string{"read:user"})

	grants := &mockBrokerGrantStore{
		getFn: func(_ context.Context, _, _ string) (*resource.BrokerGrant, error) {
			return grant, nil
		},
	}
	reg, stub := newRegistryWith(t, "oauth", nil)
	bi := newBrokerIssuer(t, grants, &mockIssuanceStore{}, &mockDataEncryptor{}, reg, nil)

	_, err := bi.Issue(context.Background(), baseRequest(prov, res, []string{"repos.read"}, nil))
	var cre *domain.ConsentRequiredError
	if !errors.As(err, &cre) {
		t.Fatalf("Issue error = %v, want *domain.ConsentRequiredError", err)
	}
	if cre.Cause != domain.CauseScopeInsufficient {
		t.Errorf("Cause = %q, want %q", cre.Cause, domain.CauseScopeInsufficient)
	}
	// MissingScopes carries the upstream form (e.g. "repo"), not the fine
	// name ("repos.read") — the diagnostic is for forensics on the upstream
	// gate, not the AS-side catalog.
	wantMissing := []string{"repo"}
	if !reflect.DeepEqual(cre.MissingScopes, wantMissing) {
		t.Errorf("MissingScopes = %v, want %v (upstream form)", cre.MissingScopes, wantMissing)
	}
	if stub.vendCalls != 0 {
		t.Errorf("adapter.Vend called %d times on insufficient scope; want 0", stub.vendCalls)
	}
}

func TestBrokerIssuer_Issue_BoundE_PartialOverlap_OnlyMissingReported(t *testing.T) {
	res := newGitHubBrokerResource() // catalog: repos.read→repo, users.read→read:user
	prov := newGitHubBrokerProvider()
	// Granted set covers "repo" (upstream form of repos.read) but NOT
	// "read:user". Request both fine scopes; only the upstream form of
	// users.read is reported missing.
	grant := activeGrant("user-42", "bp-gh", []string{"repo"})

	grants := &mockBrokerGrantStore{
		getFn: func(_ context.Context, _, _ string) (*resource.BrokerGrant, error) {
			return grant, nil
		},
	}
	reg, _ := newRegistryWith(t, "oauth", nil)
	bi := newBrokerIssuer(t, grants, &mockIssuanceStore{}, &mockDataEncryptor{}, reg, nil)

	_, err := bi.Issue(context.Background(), baseRequest(prov, res, []string{"repos.read", "users.read"}, nil))
	var cre *domain.ConsentRequiredError
	if !errors.As(err, &cre) {
		t.Fatalf("Issue error = %v, want *domain.ConsentRequiredError", err)
	}
	if cre.Cause != domain.CauseScopeInsufficient {
		t.Errorf("Cause = %q, want %q", cre.Cause, domain.CauseScopeInsufficient)
	}
	wantMissing := []string{"read:user"}
	if !reflect.DeepEqual(cre.MissingScopes, wantMissing) {
		t.Errorf("MissingScopes = %v, want %v (only the unmapped upstream scope)", cre.MissingScopes, wantMissing)
	}
}

func TestBrokerIssuer_Issue_Bound1_ScopeNotInCatalog_DoesNotReturnConsentRequired(t *testing.T) {
	res := newGitHubBrokerResource()
	prov := newGitHubBrokerProvider()
	grant := activeGrant("user-42", "bp-gh", []string{"repo"})

	grants := &mockBrokerGrantStore{
		getFn: func(_ context.Context, _, _ string) (*resource.BrokerGrant, error) {
			return grant, nil
		},
	}
	reg, _ := newRegistryWith(t, "oauth", nil)
	bi := newBrokerIssuer(t, grants, &mockIssuanceStore{}, &mockDataEncryptor{}, reg, nil)

	_, err := bi.Issue(context.Background(), baseRequest(prov, res, []string{"not-in-catalog"}, nil))
	if !errors.Is(err, domain.ErrScopeNotInCatalog) {
		t.Fatalf("Issue error = %v, want errors.Is domain.ErrScopeNotInCatalog", err)
	}
	// Bound-1 failures are caller bugs (catalog miss); they must NOT
	// surface as ConsentRequiredError — re-consenting can't add a scope
	// that isn't in the catalog.
	var cre *domain.ConsentRequiredError
	if errors.As(err, &cre) {
		t.Errorf("bound-1 catalog-miss should not return ConsentRequiredError, got %+v", cre)
	}
}

func TestBrokerIssuer_Issue_AllBoundsPass_ReturnsToken(t *testing.T) {
	res := newGitHubBrokerResource()
	prov := newGitHubBrokerProvider()
	grant := activeGrant("user-42", "bp-gh", []string{"repo"})

	grants := &mockBrokerGrantStore{
		getFn: func(_ context.Context, _, _ string) (*resource.BrokerGrant, error) {
			return grant, nil
		},
	}
	reg, _ := newRegistryWith(t, "oauth", nil)
	bi := newBrokerIssuer(t, grants, &mockIssuanceStore{}, &mockDataEncryptor{}, reg, nil)

	resp, err := bi.Issue(context.Background(), baseRequest(prov, res, []string{"repos.read"}, nil))
	if err != nil {
		t.Fatalf("Issue err = %v, want nil (all bounds pass)", err)
	}
	if resp == nil || resp.AccessToken == "" {
		t.Fatalf("expected non-empty access token, got %+v", resp)
	}
	// Sanity: a happy-path response carries no ConsentRequiredError.
	var cre *domain.ConsentRequiredError
	if errors.As(err, &cre) {
		t.Errorf("happy path should not return ConsentRequiredError, got %+v", cre)
	}
}
