package main

import (
	"bytes"
	"context"
	"testing"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	"github.com/authplane/authserver/internal/domain/resource"
	"github.com/authplane/authserver/internal/ports/input"
)

// resetCobraFlags clears any flag state left over from a previous Execute on
// the supplied command tree. Cobra and pflag retain values across Execute
// calls when the *cobra.Command is a package-level var (admin_*.go), so
// without this each test would inherit the last test's --user / --id /
// --since / etc. The walk covers the parent + every descendant.
//
// PFLAG GOTCHA — slice flags: calling Value.Set with the DefValue (e.g.
// "[]") on a pflag.StringArray flag APPENDS the literal string "[]" as a
// new element instead of clearing the slice. The fix is to type-assert
// to pflag.SliceValue (implemented by every slice/array flag value) and
// call Replace(nil). This single bug ate ~20 minutes during 's test
// scaffold; future contributors adding slice-typed CLI flags should NOT
// roll their own reset path — call this helper.
func resetCobraFlags(root *cobra.Command) {
	root.Flags().VisitAll(func(f *pflag.Flag) {
		if sv, ok := f.Value.(pflag.SliceValue); ok {
			_ = sv.Replace(nil)
		} else {
			_ = f.Value.Set(f.DefValue)
		}
		f.Changed = false
	})
	for _, child := range root.Commands() {
		resetCobraFlags(child)
	}
}

// pathFromRoot walks parent links and returns the args needed to dispatch
// from the root cobra.Command down to cmd.
//
// COBRA GOTCHA — walk-to-root: cobra v1.10.x's ExecuteC contains
//
//	if c.HasParent() {
//	    return c.Root().ExecuteC()
//	}
//
// at command.go:1090. So `subCmd.SetArgs([…]); subCmd.Execute()` does NOT
// run subCmd with those args — it walks up to the root, then uses the
// ROOT's args (which would default to os.Args[1:] if SetArgs was never
// called on root, or whatever the previous test set). Tests that look
// "right" can silently pass against `go test`'s own argv. The fix:
// call SetArgs on rootCmd with the full path prepended, then invoke
// rootCmd.Execute(). dispatchRoot below encapsulates that.
func pathFromRoot(cmd *cobra.Command) []string {
	var rev []string
	for c := cmd; c != nil && c.HasParent(); c = c.Parent() {
		rev = append(rev, c.Name())
	}
	out := make([]string, len(rev))
	for i, n := range rev {
		out[len(rev)-1-i] = n
	}
	return out
}

// dispatchRoot is the test-side mirror of cobra's ExecuteC walk-to-root.
// Builds the root-relative args (e.g. "admin resource create --slug …")
// and invokes the root so cobra resolves down to cmd. Returns rootCmd's
// stdout/stderr buffer + the Execute error.
func dispatchRoot(t *testing.T, cmd *cobra.Command, leafArgs []string) (string, error) {
	t.Helper()
	resetCobraFlags(rootCmd)
	full := append(pathFromRoot(cmd), leafArgs...)
	var out bytes.Buffer
	rootCmd.SetOut(&out)
	rootCmd.SetErr(&out)
	rootCmd.SetArgs(full)
	t.Cleanup(func() {
		rootCmd.SetArgs(nil)
		rootCmd.SetOut(nil)
		rootCmd.SetErr(nil)
	})
	err := rootCmd.Execute()
	return out.String(), err
}

// newTestCLIEnv builds a *cliEnv with the four admin service ports populated
// from the supplied stubs and overrides openCLIEnv for the test's lifetime.
// Tests override openCLIEnv directly because every CLI subcommand under
// `authserver admin {resource|provider|grant|issuance}` calls openCLIEnv()
// inside RunE — no other injection seam exists.
//
// Pass nil for any port whose subcommand isn't exercised by the test; the
// stub will panic on call so accidental leakage is loud rather than silent.
func newTestCLIEnv(
	t *testing.T,
	resources input.ResourceAdminPort,
	providers input.BrokerProviderAdminPort,
	grants input.GrantAdminPort,
	issuances input.IssuanceAdminPort,
) {
	t.Helper()
	prev := openCLIEnv
	env := &cliEnv{
		resourceAdminSvc:       resources,
		brokerProviderAdminSvc: providers,
		grantAdminSvc:          grants,
		issuanceAdminSvc:       issuances,
	}
	openCLIEnv = func() (*cliEnv, func(), error) {
		return env, func() {}, nil
	}
	t.Cleanup(func() { openCLIEnv = prev })
}

// stubResourceAdmin is a function-field stub for input.ResourceAdminPort;
// tests fill in just the methods they exercise. Unset methods panic so
// stray calls surface as test failures instead of nil-deref noise.
type stubResourceAdmin struct {
	ListFn      func(ctx context.Context, filter input.ResourceFilter) ([]*resource.Resource, error)
	GetByIDFn   func(ctx context.Context, id string) (*resource.Resource, error)
	GetBySlugFn func(ctx context.Context, slug string) (*resource.Resource, error)
	CreateFn    func(ctx context.Context, r *resource.Resource) error
	PatchFn     func(ctx context.Context, id string, patch input.ResourcePatch) (*resource.Resource, error)
	DeleteFn    func(ctx context.Context, id string) error
	PatchCalls  []resourcePatchCall
}

type resourcePatchCall struct {
	ID    string
	Patch input.ResourcePatch
}

func (s *stubResourceAdmin) List(ctx context.Context, f input.ResourceFilter) ([]*resource.Resource, error) {
	if s.ListFn == nil {
		panic("stubResourceAdmin.List not set")
	}
	return s.ListFn(ctx, f)
}

func (s *stubResourceAdmin) GetByID(ctx context.Context, id string) (*resource.Resource, error) {
	if s.GetByIDFn == nil {
		panic("stubResourceAdmin.GetByID not set")
	}
	return s.GetByIDFn(ctx, id)
}

func (s *stubResourceAdmin) GetBySlug(ctx context.Context, slug string) (*resource.Resource, error) {
	if s.GetBySlugFn == nil {
		panic("stubResourceAdmin.GetBySlug not set")
	}
	return s.GetBySlugFn(ctx, slug)
}

func (s *stubResourceAdmin) Create(ctx context.Context, r *resource.Resource) error {
	if s.CreateFn == nil {
		panic("stubResourceAdmin.Create not set")
	}
	return s.CreateFn(ctx, r)
}

func (s *stubResourceAdmin) Patch(ctx context.Context, id string, patch input.ResourcePatch) (*resource.Resource, error) {
	s.PatchCalls = append(s.PatchCalls, resourcePatchCall{ID: id, Patch: patch})
	if s.PatchFn == nil {
		panic("stubResourceAdmin.Patch not set")
	}
	return s.PatchFn(ctx, id, patch)
}

func (s *stubResourceAdmin) Delete(ctx context.Context, id string) error {
	if s.DeleteFn == nil {
		panic("stubResourceAdmin.Delete not set")
	}
	return s.DeleteFn(ctx, id)
}

// DeleteWithCascade is the cascade-aware variant. The CLI seed loop
// only invokes Delete (cascade=false equivalent); we plumb DeleteFn through
// so existing tests keep working without setting a separate Fn.
func (s *stubResourceAdmin) DeleteWithCascade(ctx context.Context, id string, _ bool) ([]*resource.FrontingLink, error) {
	if s.DeleteFn == nil {
		panic("stubResourceAdmin.DeleteWithCascade (via DeleteFn) not set")
	}
	return nil, s.DeleteFn(ctx, id)
}

// The CLI seed loop only calls List/Get/Create/Patch/Delete; the policy-edit
// methods are admin-API-only. Stubs panic so a stray call
// surfaces as a test failure rather than nil-deref noise.

func (s *stubResourceAdmin) AddAllowedClient(ctx context.Context, slug, clientID string) ([]string, error) {
	panic("stubResourceAdmin.AddAllowedClient not used by CLI seed loop")
}

func (s *stubResourceAdmin) RemoveAllowedClient(ctx context.Context, slug, clientID string) ([]string, error) {
	panic("stubResourceAdmin.RemoveAllowedClient not used by CLI seed loop")
}

func (s *stubResourceAdmin) ListAllowedClients(ctx context.Context, slug string) ([]string, error) {
	panic("stubResourceAdmin.ListAllowedClients not used by CLI seed loop")
}

func (s *stubResourceAdmin) AddAllowedReturnURL(ctx context.Context, slug, returnURL string) ([]string, error) {
	panic("stubResourceAdmin.AddAllowedReturnURL not used by CLI seed loop")
}

func (s *stubResourceAdmin) RemoveAllowedReturnURL(ctx context.Context, slug, returnURL string) ([]string, error) {
	panic("stubResourceAdmin.RemoveAllowedReturnURL not used by CLI seed loop")
}

func (s *stubResourceAdmin) ListAllowedReturnURLs(ctx context.Context, slug string) ([]string, error) {
	panic("stubResourceAdmin.ListAllowedReturnURLs not used by CLI seed loop")
}

func (s *stubResourceAdmin) AddRuntimeClientID(ctx context.Context, slug, clientID string) ([]string, error) {
	panic("stubResourceAdmin.AddRuntimeClientID not used by CLI seed loop")
}

func (s *stubResourceAdmin) RemoveRuntimeClientID(ctx context.Context, slug, clientID string) ([]string, error) {
	panic("stubResourceAdmin.RemoveRuntimeClientID not used by CLI seed loop")
}

func (s *stubResourceAdmin) ListRuntimeClientIDs(ctx context.Context, slug string) ([]string, error) {
	panic("stubResourceAdmin.ListRuntimeClientIDs not used by CLI seed loop")
}

// stubBrokerProviderAdmin is the equivalent stub for input.BrokerProviderAdminPort.
type stubBrokerProviderAdmin struct {
	ListFn      func(ctx context.Context) ([]*resource.BrokerProvider, error)
	GetByIDFn   func(ctx context.Context, id string) (*resource.BrokerProvider, error)
	GetBySlugFn func(ctx context.Context, slug string) (*resource.BrokerProvider, error)
	CreateFn    func(ctx context.Context, p *resource.BrokerProvider) error
	PatchFn     func(ctx context.Context, id string, patch input.BrokerProviderPatch) (*resource.BrokerProvider, error)
	DeleteFn    func(ctx context.Context, id string) error
}

func (s *stubBrokerProviderAdmin) List(ctx context.Context) ([]*resource.BrokerProvider, error) {
	if s.ListFn == nil {
		panic("stubBrokerProviderAdmin.List not set")
	}
	return s.ListFn(ctx)
}

func (s *stubBrokerProviderAdmin) GetByID(ctx context.Context, id string) (*resource.BrokerProvider, error) {
	if s.GetByIDFn == nil {
		panic("stubBrokerProviderAdmin.GetByID not set")
	}
	return s.GetByIDFn(ctx, id)
}

func (s *stubBrokerProviderAdmin) GetBySlug(ctx context.Context, slug string) (*resource.BrokerProvider, error) {
	if s.GetBySlugFn == nil {
		panic("stubBrokerProviderAdmin.GetBySlug not set")
	}
	return s.GetBySlugFn(ctx, slug)
}

func (s *stubBrokerProviderAdmin) Create(ctx context.Context, p *resource.BrokerProvider) error {
	if s.CreateFn == nil {
		panic("stubBrokerProviderAdmin.Create not set")
	}
	return s.CreateFn(ctx, p)
}

func (s *stubBrokerProviderAdmin) Patch(ctx context.Context, id string, patch input.BrokerProviderPatch) (*resource.BrokerProvider, error) {
	if s.PatchFn == nil {
		panic("stubBrokerProviderAdmin.Patch not set")
	}
	return s.PatchFn(ctx, id, patch)
}

func (s *stubBrokerProviderAdmin) Delete(ctx context.Context, id string) error {
	if s.DeleteFn == nil {
		panic("stubBrokerProviderAdmin.Delete not set")
	}
	return s.DeleteFn(ctx, id)
}

// stubGrantAdmin is the stub for input.GrantAdminPort.
type stubGrantAdmin struct {
	ListForUserFn   func(ctx context.Context, userID string) (input.UserGrants, error)
	RevokeConsentFn func(ctx context.Context, id string) error
	RevokeBrokerFn  func(ctx context.Context, id string) error
}

func (s *stubGrantAdmin) ListForUser(ctx context.Context, userID string) (input.UserGrants, error) {
	if s.ListForUserFn == nil {
		panic("stubGrantAdmin.ListForUser not set")
	}
	return s.ListForUserFn(ctx, userID)
}

func (s *stubGrantAdmin) RevokeConsent(ctx context.Context, id string) error {
	if s.RevokeConsentFn == nil {
		panic("stubGrantAdmin.RevokeConsent not set")
	}
	return s.RevokeConsentFn(ctx, id)
}

func (s *stubGrantAdmin) RevokeBroker(ctx context.Context, id string) error {
	if s.RevokeBrokerFn == nil {
		panic("stubGrantAdmin.RevokeBroker not set")
	}
	return s.RevokeBrokerFn(ctx, id)
}

// stubIssuanceAdmin is the stub for input.IssuanceAdminPort.
type stubIssuanceAdmin struct {
	ListForUserFn     func(ctx context.Context, userID string, since time.Time) ([]*resource.Issuance, error)
	ListForActorFn    func(ctx context.Context, clientID string, since time.Time) ([]*resource.Issuance, error)
	ListForResourceFn func(ctx context.Context, resourceID string, since time.Time) ([]*resource.Issuance, error)
	GetByIDFn         func(ctx context.Context, id string) (*resource.Issuance, error)
	GetByJTIFn        func(ctx context.Context, jti string) (*resource.Issuance, error)
	RevokeFn          func(ctx context.Context, id string) error
}

func (s *stubIssuanceAdmin) ListForUser(ctx context.Context, userID string, since time.Time) ([]*resource.Issuance, error) {
	if s.ListForUserFn == nil {
		panic("stubIssuanceAdmin.ListForUser not set")
	}
	return s.ListForUserFn(ctx, userID, since)
}

func (s *stubIssuanceAdmin) ListForActor(ctx context.Context, clientID string, since time.Time) ([]*resource.Issuance, error) {
	if s.ListForActorFn == nil {
		panic("stubIssuanceAdmin.ListForActor not set")
	}
	return s.ListForActorFn(ctx, clientID, since)
}

func (s *stubIssuanceAdmin) ListForResource(ctx context.Context, resourceID string, since time.Time) ([]*resource.Issuance, error) {
	if s.ListForResourceFn == nil {
		panic("stubIssuanceAdmin.ListForResource not set")
	}
	return s.ListForResourceFn(ctx, resourceID, since)
}

func (s *stubIssuanceAdmin) GetByID(ctx context.Context, id string) (*resource.Issuance, error) {
	if s.GetByIDFn == nil {
		panic("stubIssuanceAdmin.GetByID not set")
	}
	return s.GetByIDFn(ctx, id)
}

func (s *stubIssuanceAdmin) GetByJTI(ctx context.Context, jti string) (*resource.Issuance, error) {
	if s.GetByJTIFn == nil {
		panic("stubIssuanceAdmin.GetByJTI not set")
	}
	return s.GetByJTIFn(ctx, jti)
}

func (s *stubIssuanceAdmin) Revoke(ctx context.Context, id string) error {
	if s.RevokeFn == nil {
		panic("stubIssuanceAdmin.Revoke not set")
	}
	return s.RevokeFn(ctx, id)
}
