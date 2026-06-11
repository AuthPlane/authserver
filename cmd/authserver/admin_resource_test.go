package main

import (
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/authplane/authserver/internal/admin/dto"
	"github.com/authplane/authserver/internal/domain"
	"github.com/authplane/authserver/internal/domain/resource"
	"github.com/authplane/authserver/internal/ports/input"
)

func runResourceCmd(t *testing.T, args ...string) (string, error) {
	t.Helper()
	return dispatchRoot(t, resourceCmd, args)
}

func TestResourceCmd_Create_HappyPath(t *testing.T) {
	var captured *resource.Resource
	stub := &stubResourceAdmin{
		CreateFn: func(_ context.Context, r *resource.Resource) error {
			r.ID = "res-1"
			captured = r
			return nil
		},
	}
	newTestCLIEnv(t, stub, nil, nil, nil)

	out, err := runResourceCmd(t, "create",
		"--slug", "github-repo",
		"--uri", "https://api.github.com",
		"--backend-kind", "broker",
		"--broker-provider", "prov-gh",
		"--scopes", "repo|repo|Repository read/write",
		"--scopes", "read:user|read:user|Read user profile",
		"--policy-allowed-clients", "test-mcp,analytics-mcp",
	)
	if err != nil {
		t.Fatalf("unexpected error: %v\nout=%s", err, out)
	}
	if captured == nil {
		t.Fatalf("Create was not called; out=%s", out)
	}
	if captured.Slug != "github-repo" || captured.BackendKind != resource.BackendBroker || captured.BrokerProviderID != "prov-gh" {
		t.Fatalf("unexpected resource passed: %+v", captured)
	}
	if len(captured.Scopes) != 2 {
		t.Fatalf("expected 2 scopes, got %+v", captured.Scopes)
	}
	if captured.Scopes[1].Name != "read:user" || captured.Scopes[1].Upstream != "read:user" {
		t.Fatalf("scope tuple parse lost data: %+v", captured.Scopes[1])
	}
	wantClients := []string{"test-mcp", "analytics-mcp"}
	if !equalStringSlice(captured.Policy.Exchange.AllowedClientIDs, wantClients) {
		t.Fatalf("policy clients = %v, want %v", captured.Policy.Exchange.AllowedClientIDs, wantClients)
	}
	if !strings.Contains(out, "id=res-1") {
		t.Fatalf("expected output to include id=res-1, got %q", out)
	}
}

func TestResourceCmd_Create_RejectsInvalidSlug(t *testing.T) {
	stub := &stubResourceAdmin{
		CreateFn: func(_ context.Context, _ *resource.Resource) error {
			// Service-side validation owns slug shape — return the
			// canonical sentinel so the CLI propagates it.
			return domain.ErrInvalidSlug
		},
	}
	newTestCLIEnv(t, stub, nil, nil, nil)

	if _, err := runResourceCmd(t, "create",
		"--slug", "Bad Slug With Spaces",
		"--backend-kind", "mint",
	); err == nil {
		t.Fatalf("expected error for invalid slug, got nil")
	}
}

func TestResourceCmd_Create_ScopesFromRepeatedFlags(t *testing.T) {
	var captured *resource.Resource
	stub := &stubResourceAdmin{
		CreateFn: func(_ context.Context, r *resource.Resource) error {
			captured = r
			return nil
		},
	}
	newTestCLIEnv(t, stub, nil, nil, nil)

	if _, err := runResourceCmd(t, "create",
		"--slug", "mcp",
		"--backend-kind", "mint",
		"--scopes", "tasks:summarize||",
		"--scopes", "tasks:read|",
	); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(captured.Scopes) != 2 {
		t.Fatalf("expected 2 scopes, got %+v", captured.Scopes)
	}
	if captured.Scopes[0].Name != "tasks:summarize" || captured.Scopes[0].Upstream != "" {
		t.Fatalf("unexpected scope[0]: %+v", captured.Scopes[0])
	}
	if captured.Scopes[1].Name != "tasks:read" || captured.Scopes[1].Upstream != "" {
		t.Fatalf("unexpected scope[1]: %+v", captured.Scopes[1])
	}
}

func TestResourceCmd_Create_ScopesFromFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "scopes.json")
	body := []byte(`[
		{"name":"repo","upstream":"repo","description":"Repository read/write"},
		{"name":"read:user","upstream":"read:user","description":"Read user profile"}
	]`)
	if err := writeFile(path, body); err != nil {
		t.Fatalf("seed scopes file: %v", err)
	}

	var captured *resource.Resource
	stub := &stubResourceAdmin{
		CreateFn: func(_ context.Context, r *resource.Resource) error {
			captured = r
			return nil
		},
	}
	newTestCLIEnv(t, stub, nil, nil, nil)

	if _, err := runResourceCmd(t, "create",
		"--slug", "gh",
		"--backend-kind", "broker",
		"--broker-provider", "prov-gh",
		"--scopes-file", path,
	); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(captured.Scopes) != 2 || captured.Scopes[0].Description != "Repository read/write" {
		t.Fatalf("scopes-file parse lost data: %+v", captured.Scopes)
	}
}

func TestResourceCmd_Create_ScopesAndScopesFile_MutuallyExclusive(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "scopes.json")
	if err := writeFile(path, []byte(`[]`)); err != nil {
		t.Fatalf("seed: %v", err)
	}

	stub := &stubResourceAdmin{
		CreateFn: func(_ context.Context, _ *resource.Resource) error {
			t.Fatalf("Create should NOT have been called when both --scopes and --scopes-file are set")
			return nil
		},
	}
	newTestCLIEnv(t, stub, nil, nil, nil)

	_, err := runResourceCmd(t, "create",
		"--slug", "x",
		"--backend-kind", "mint",
		"--scopes", "foo|",
		"--scopes-file", path,
	)
	if err == nil || !strings.Contains(err.Error(), "mutually exclusive") {
		t.Fatalf("expected 'mutually exclusive' error, got %v", err)
	}
}

func TestResourceCmd_List_FiltersByBackendKind(t *testing.T) {
	var capturedFilter input.ResourceFilter
	stub := &stubResourceAdmin{
		ListFn: func(_ context.Context, f input.ResourceFilter) ([]*resource.Resource, error) {
			capturedFilter = f
			return []*resource.Resource{
				{ID: "r1", Slug: "a", BackendKind: resource.BackendBroker, BrokerProviderID: "prov-1"},
			}, nil
		},
	}
	newTestCLIEnv(t, stub, nil, nil, nil)

	if _, err := runResourceCmd(t, "list", "--backend-kind", "broker"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if capturedFilter.BackendKind != resource.BackendBroker {
		t.Fatalf("expected filter.BackendKind=broker, got %q", capturedFilter.BackendKind)
	}

	// invalid backend-kind → CLI error before service call
	stub.ListFn = func(_ context.Context, _ input.ResourceFilter) ([]*resource.Resource, error) {
		t.Fatalf("List must not be called with invalid --backend-kind")
		return nil, nil
	}
	if _, err := runResourceCmd(t, "list", "--backend-kind", "garbage"); err == nil {
		t.Fatalf("expected error for invalid --backend-kind")
	}
}

// TestResourceCmd_Update_PartialPatch_OmittingPolicyLeavesItUnchanged is the
// security-footgun regression. Spec §Risks: omitting --policy-allowed-clients
// MUST leave the persisted allowlist UNCHANGED. The patch struct sent to
// the service must have Policy == nil, NOT an empty Policy{}.
func TestResourceCmd_Update_PartialPatch_OmittingPolicyLeavesItUnchanged(t *testing.T) {
	stub := &stubResourceAdmin{
		PatchFn: func(_ context.Context, id string, p input.ResourcePatch) (*resource.Resource, error) {
			if id != "res-1" {
				t.Fatalf("expected id=res-1, got %q", id)
			}
			if p.Policy != nil {
				t.Fatalf("PATCH semantics violated: omitting --policy-* must yield Policy=nil; got %+v", p.Policy)
			}
			if p.Scopes != nil {
				t.Fatalf("PATCH semantics violated: omitting --scopes must yield Scopes=nil; got %+v", p.Scopes)
			}
			if p.DisplayName == nil || *p.DisplayName != "Renamed" {
				t.Fatalf("expected DisplayName=Renamed, got %+v", p.DisplayName)
			}
			return &resource.Resource{ID: id, Slug: "github-repo"}, nil
		},
	}
	newTestCLIEnv(t, stub, nil, nil, nil)

	if _, err := runResourceCmd(t, "update", "--id", "res-1", "--display-name", "Renamed"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

// TestResourceCmd_Update_PolicyClear_ResetsToEmpty asserts
// --policy-clear translates into Policy = &Policy{} (explicit wipe).
func TestResourceCmd_Update_PolicyClear_ResetsToEmpty(t *testing.T) {
	stub := &stubResourceAdmin{
		PatchFn: func(_ context.Context, _ string, p input.ResourcePatch) (*resource.Resource, error) {
			if p.Policy == nil {
				t.Fatalf("--policy-clear must yield non-nil Policy patch (explicit wipe), got nil")
			}
			if len(p.Policy.Exchange.AllowedClientIDs) != 0 {
				t.Fatalf("--policy-clear must wipe the allowlist; got %v", p.Policy.Exchange.AllowedClientIDs)
			}
			if len(p.Policy.Connect.AllowedReturnURLs) != 0 {
				t.Fatalf("--policy-clear must wipe the connect URLs; got %v", p.Policy.Connect.AllowedReturnURLs)
			}
			return &resource.Resource{ID: "res-1"}, nil
		},
	}
	newTestCLIEnv(t, stub, nil, nil, nil)

	if _, err := runResourceCmd(t, "update", "--id", "res-1", "--policy-clear"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestResourceCmd_Update_PolicyClear_RejectsCombinedWithExplicitFlags(t *testing.T) {
	stub := &stubResourceAdmin{
		PatchFn: func(_ context.Context, _ string, _ input.ResourcePatch) (*resource.Resource, error) {
			t.Fatalf("Patch must NOT be called when --policy-clear is mixed with explicit --policy-* flags")
			return nil, nil
		},
	}
	newTestCLIEnv(t, stub, nil, nil, nil)

	_, err := runResourceCmd(t, "update", "--id", "res-1",
		"--policy-clear",
		"--policy-allowed-clients", "foo",
	)
	if err == nil || !strings.Contains(err.Error(), "mutually exclusive") {
		t.Fatalf("expected 'mutually exclusive' error, got %v", err)
	}
}

func TestResourceCmd_Update_ScopesClear_ResetsToEmpty(t *testing.T) {
	stub := &stubResourceAdmin{
		PatchFn: func(_ context.Context, _ string, p input.ResourcePatch) (*resource.Resource, error) {
			if p.Scopes == nil {
				t.Fatalf("--scopes-clear must yield non-nil Scopes patch")
			}
			if len(*p.Scopes) != 0 {
				t.Fatalf("--scopes-clear must yield empty slice, got %v", *p.Scopes)
			}
			return &resource.Resource{ID: "res-1"}, nil
		},
	}
	newTestCLIEnv(t, stub, nil, nil, nil)

	if _, err := runResourceCmd(t, "update", "--id", "res-1", "--scopes-clear"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestResourceCmd_Update_ReplacesPolicyAllowlist(t *testing.T) {
	stub := &stubResourceAdmin{
		PatchFn: func(_ context.Context, _ string, p input.ResourcePatch) (*resource.Resource, error) {
			if p.Policy == nil {
				t.Fatalf("expected non-nil Policy when --policy-allowed-clients is set")
			}
			want := []string{"alpha", "beta"}
			if !equalStringSlice(p.Policy.Exchange.AllowedClientIDs, want) {
				t.Fatalf("policy clients = %v, want %v", p.Policy.Exchange.AllowedClientIDs, want)
			}
			return &resource.Resource{ID: "res-1"}, nil
		},
	}
	newTestCLIEnv(t, stub, nil, nil, nil)

	if _, err := runResourceCmd(t, "update", "--id", "res-1",
		"--policy-allowed-clients", "alpha,beta",
	); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestResourceCmd_Delete_NotFound_Returns1(t *testing.T) {
	stub := &stubResourceAdmin{
		DeleteFn: func(_ context.Context, _ string) error {
			return domain.ErrResourceNotFound
		},
	}
	newTestCLIEnv(t, stub, nil, nil, nil)

	if _, err := runResourceCmd(t, "delete", "--id", "missing"); err == nil {
		t.Fatalf("expected error for not-found delete")
	}
}

func TestResourceCmd_Get_JSONOutputShape(t *testing.T) {
	row := &resource.Resource{
		ID:               "r1",
		Slug:             "gh",
		URI:              "https://api.github.com",
		BackendKind:      resource.BackendBroker,
		BrokerProviderID: "prov-gh",
		DisplayName:      "GitHub",
		Scopes:           []resource.Scope{{Name: "repo", Upstream: "repo", Description: "Repo R/W"}},
		Policy: resource.Policy{
			Exchange: resource.ExchangePolicy{AllowedClientIDs: []string{"agent-x"}},
			Connect:  resource.ConnectPolicy{AllowedReturnURLs: []string{"https://app/callback"}},
		},
		CreatedAt: time.Unix(1700000000, 0).UTC(),
		UpdatedAt: time.Unix(1700001000, 0).UTC(),
	}
	stub := &stubResourceAdmin{
		GetByIDFn: func(_ context.Context, _ string) (*resource.Resource, error) {
			return row, nil
		},
	}
	newTestCLIEnv(t, stub, nil, nil, nil)

	out, err := runResourceCmd(t, "get", "--id", "r1", "--json")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	var got dto.ResourceView
	if jsonErr := json.Unmarshal([]byte(out), &got); jsonErr != nil {
		t.Fatalf("--json output is not valid JSON: %v\noutput=%s", jsonErr, out)
	}
	if got.ID != "r1" || got.BackendKind != "broker" || got.Policy.Connect == nil {
		t.Fatalf("unexpected --json shape: %+v", got)
	}
	if !equalStringSlice(got.Policy.Exchange.AllowedClientIDs, []string{"agent-x"}) {
		t.Fatalf("policy.exchange not preserved: %+v", got.Policy.Exchange)
	}
}

func TestResourceCmd_Get_MintResource_OmitsConnectInJSON(t *testing.T) {
	row := &resource.Resource{
		ID: "r2", Slug: "mcp", BackendKind: resource.BackendMint,
		Policy: resource.Policy{
			Exchange: resource.ExchangePolicy{AllowedClientIDs: []string{}},
		},
	}
	stub := &stubResourceAdmin{
		GetByIDFn: func(_ context.Context, _ string) (*resource.Resource, error) { return row, nil },
	}
	newTestCLIEnv(t, stub, nil, nil, nil)

	out, err := runResourceCmd(t, "get", "--id", "r2", "--json")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if strings.Contains(out, `"connect"`) {
		t.Fatalf("Mint resources must omit policy.connect in JSON: %s", out)
	}
}

func TestResourceCmd_Create_BadScopeTuple_Returns1(t *testing.T) {
	stub := &stubResourceAdmin{
		CreateFn: func(_ context.Context, _ *resource.Resource) error {
			t.Fatalf("Create must not be called when --scopes parses fail")
			return nil
		},
	}
	newTestCLIEnv(t, stub, nil, nil, nil)

	_, err := runResourceCmd(t, "create",
		"--slug", "x", "--backend-kind", "mint",
		"--scopes", "|missing-name|nope",
	)
	if err == nil || !strings.Contains(err.Error(), "name part is empty") {
		t.Fatalf("expected 'name part is empty' error, got %v", err)
	}
}

func TestResourceCmd_Create_PropagatesGenericServiceError(t *testing.T) {
	stub := &stubResourceAdmin{
		CreateFn: func(_ context.Context, _ *resource.Resource) error {
			return errors.New("conflict: slug already in use")
		},
	}
	newTestCLIEnv(t, stub, nil, nil, nil)

	if _, err := runResourceCmd(t, "create",
		"--slug", "dup", "--backend-kind", "mint",
	); err == nil {
		t.Fatalf("expected error to propagate from service")
	}
}

// equalStringSlice is a tiny test helper used across resource patch
// assertions. Saves the stutter of comparing two string slices via
// reflect.DeepEqual just for the [] case.
func equalStringSlice(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
