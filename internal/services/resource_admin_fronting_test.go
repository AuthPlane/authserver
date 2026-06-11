package services

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"

	"github.com/authplane/authserver/internal/domain"
	"github.com/authplane/authserver/internal/domain/resource"
	"github.com/authplane/authserver/internal/observability"
	"github.com/authplane/authserver/internal/ports/input"
	"github.com/authplane/authserver/internal/ports/output"
)

// recordingTxManager is an in-memory output.TransactionManager that
// remembers whether WithTransaction was called and runs the closure
// inline. Lets cascade tests assert the tx-aware code path without
// standing up a real DB tx.
type recordingTxManager struct {
	calls atomic.Int32
}

var _ output.TransactionManager = (*recordingTxManager)(nil)

func (r *recordingTxManager) WithTransaction(ctx context.Context, fn func(ctx context.Context) error) error {
	r.calls.Add(1)
	return fn(ctx)
}

// TestResourceAdminService_DeleteWithCascade_409 verifies that DELETE without
// ?cascade=true on a resource that has fronting links surfaces
// ErrResourceHasFrontingLinks plus the dependent list — the wire-level
// shape that the HTTP handler renders into a 409 body.
func TestResourceAdminService_DeleteWithCascade_409(t *testing.T) {
	res := newFakeResourceStore()
	frontSvc, fres, _, _ := newFrontingService(t)
	// FrontingService and ResourceAdminService share the resource store so
	// the link-validation path resolves real entries.
	_ = fres

	// Two mints + one fronting link a→b. Easiest path: seed the FRONTING
	// service's resource store, then plumb the SAME store into the resource
	// admin service so they agree on which resources exist.
	seedResource(t, fres, "a", resource.BackendMint, []string{"s"})
	seedResource(t, fres, "b", resource.BackendMint, []string{"s"})
	if err := frontSvc.Create(context.Background(), &resource.FrontingLink{
		SourceSlug: "a", TargetSlug: "b",
		ScopeMap: resource.ScopeMap{"s": {"s"}},
	}, "admin"); err != nil {
		t.Fatalf("seed link: %v", err)
	}

	// ResourceAdminService over the SAME resource store as the fronting
	// service — that's how production wires them.
	svc := NewResourceAdminService(fres, newFakeBrokerProviderStore(), newFakeClientStore(), observability.NewNoop(), nil,
		WithFrontingValidator(frontSvc),
	)
	_ = res

	// Resolve a's id from the shared store.
	aRes, err := fres.GetBySlug(context.Background(), "a")
	if err != nil {
		t.Fatalf("get by slug: %v", err)
	}

	deps, err := svc.DeleteWithCascade(context.Background(), aRes.ID, false)
	if !errors.Is(err, domain.ErrResourceHasFrontingLinks) {
		t.Fatalf("expected ErrResourceHasFrontingLinks, got %v", err)
	}
	if len(deps) != 1 || deps[0].SourceSlug != "a" || deps[0].TargetSlug != "b" {
		t.Errorf("expected single dependent a→b, got %v", deps)
	}
}

// TestResourceAdminService_DeleteWithCascade_TrueRemovesLinks verifies the
// cascade path: ?cascade=true deletes the dependent links + the resource.
func TestResourceAdminService_DeleteWithCascade_TrueRemovesLinks(t *testing.T) {
	frontSvc, fres, links, _ := newFrontingService(t)

	seedResource(t, fres, "a", resource.BackendMint, []string{"s"})
	seedResource(t, fres, "b", resource.BackendMint, []string{"s"})
	if err := frontSvc.Create(context.Background(), &resource.FrontingLink{
		SourceSlug: "a", TargetSlug: "b",
		ScopeMap: resource.ScopeMap{"s": {"s"}},
	}, "admin"); err != nil {
		t.Fatalf("seed link: %v", err)
	}

	svc := NewResourceAdminService(fres, newFakeBrokerProviderStore(), newFakeClientStore(), observability.NewNoop(), nil,
		WithFrontingValidator(frontSvc),
	)

	aRes, _ := fres.GetBySlug(context.Background(), "a")
	deps, err := svc.DeleteWithCascade(context.Background(), aRes.ID, true)
	if err != nil {
		t.Fatalf("cascade: %v", err)
	}
	if len(deps) != 1 {
		t.Errorf("expected 1 cascaded dep, got %d", len(deps))
	}

	// Resource gone.
	if _, err := fres.GetByID(context.Background(), aRes.ID); !errors.Is(err, domain.ErrResourceNotFound) {
		t.Errorf("resource still present: %v", err)
	}
	// Link gone.
	if _, err := links.Get(context.Background(), "a", "b"); !errors.Is(err, domain.ErrFrontingLinkNotFound) {
		t.Errorf("link still present: %v", err)
	}
}

// TestResourceAdminService_Patch_ScopeRemovalBlocked verifies the edit-time
// hook fires on Patch when a scope referenced by a fronting link would be
// dropped.
func TestResourceAdminService_Patch_ScopeRemovalBlocked(t *testing.T) {
	frontSvc, fres, _, _ := newFrontingService(t)
	seedResource(t, fres, "src", resource.BackendMint, []string{"a", "b"})
	seedResource(t, fres, "tgt", resource.BackendMint, []string{"A"})
	if err := frontSvc.Create(context.Background(), &resource.FrontingLink{
		SourceSlug: "src", TargetSlug: "tgt",
		ScopeMap: resource.ScopeMap{"a": {"A"}},
	}, "admin"); err != nil {
		t.Fatalf("seed link: %v", err)
	}

	svc := NewResourceAdminService(fres, newFakeBrokerProviderStore(), newFakeClientStore(), observability.NewNoop(), nil,
		WithFrontingValidator(frontSvc),
	)

	srcRes, _ := fres.GetBySlug(context.Background(), "src")
	scopes := []resource.Scope{{Name: "b"}} // dropping "a" — blocked
	patch := input.ResourcePatch{Scopes: &scopes}
	_, err := svc.Patch(context.Background(), srcRes.ID, patch)
	if err == nil {
		t.Fatal("expected scope-removal block, got nil")
	}
	if !domain.IsError(err) {
		t.Errorf("expected domain error, got %T %v", err, err)
	}
}

// TestResourceAdminService_Patch_KindChangeForbidden verifies the kind-change
// guard fires when fronting links reference the resource.
func TestResourceAdminService_Patch_KindChangeForbidden(t *testing.T) {
	frontSvc, fres, _, _ := newFrontingService(t)
	seedResource(t, fres, "src", resource.BackendMint, []string{"a"})
	seedResource(t, fres, "tgt", resource.BackendMint, []string{"A"})
	if err := frontSvc.Create(context.Background(), &resource.FrontingLink{
		SourceSlug: "src", TargetSlug: "tgt",
		ScopeMap: resource.ScopeMap{"a": {"A"}},
	}, "admin"); err != nil {
		t.Fatalf("seed link: %v", err)
	}

	providers := newFakeBrokerProviderStore()
	providers.seed("p-1", "p-1")

	svc := NewResourceAdminService(fres, providers, newFakeClientStore(), observability.NewNoop(), nil,
		WithFrontingValidator(frontSvc),
	)

	srcRes, _ := fres.GetBySlug(context.Background(), "src")
	bk := resource.BackendBroker
	pid := "p-1"
	patch := input.ResourcePatch{BackendKind: &bk, BrokerProviderID: &pid}
	_, err := svc.Patch(context.Background(), srcRes.ID, patch)
	if err == nil {
		t.Fatal("expected kind-change block, got nil")
	}
	if !domain.IsError(err) {
		t.Errorf("expected domain error, got %T %v", err, err)
	}
}

// TestResourceAdminService_Delete_NoFrontingDeps_Succeeds verifies the
// pre- delete path still works when no links reference the resource.
func TestResourceAdminService_Delete_NoFrontingDeps_Succeeds(t *testing.T) {
	frontSvc, fres, _, _ := newFrontingService(t)
	seedResource(t, fres, "lonely", resource.BackendMint, []string{"a"})

	svc := NewResourceAdminService(fres, newFakeBrokerProviderStore(), newFakeClientStore(), observability.NewNoop(), nil,
		WithFrontingValidator(frontSvc),
	)

	r, _ := fres.GetBySlug(context.Background(), "lonely")
	if err := svc.Delete(context.Background(), r.ID); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if _, err := fres.GetByID(context.Background(), r.ID); !errors.Is(err, domain.ErrResourceNotFound) {
		t.Errorf("resource still present after delete: %v", err)
	}
}

// TestResourceAdminService_DeleteWithCascade_TxAtomicity verifies the
// cascade path runs inside the transaction manager when one is wired —
// the load-bearing guarantee that motivated the SQLite ResourceStore.Delete
// dbOrTx fix. Without this assertion, a regression that drops the
// WithTransaction wrapping would silently fall back to non-atomic
// sequential deletes.
func TestResourceAdminService_DeleteWithCascade_TxAtomicity(t *testing.T) {
	frontSvc, fres, _, _ := newFrontingService(t)
	seedResource(t, fres, "a", resource.BackendMint, []string{"s"})
	seedResource(t, fres, "b", resource.BackendMint, []string{"s"})
	if err := frontSvc.Create(context.Background(), &resource.FrontingLink{
		SourceSlug: "a", TargetSlug: "b",
		ScopeMap: resource.ScopeMap{"s": {"s"}},
	}, "admin"); err != nil {
		t.Fatalf("seed link: %v", err)
	}

	tx := &recordingTxManager{}
	svc := NewResourceAdminService(fres, newFakeBrokerProviderStore(), newFakeClientStore(), observability.NewNoop(), nil,
		WithFrontingValidator(frontSvc),
		WithResourceAdminTransactionManager(tx),
	)

	aRes, _ := fres.GetBySlug(context.Background(), "a")
	if _, err := svc.DeleteWithCascade(context.Background(), aRes.ID, true); err != nil {
		t.Fatalf("cascade: %v", err)
	}
	if got := tx.calls.Load(); got != 1 {
		t.Errorf("WithTransaction calls = %d, want 1", got)
	}
}

// TestResourceAdminService_DeleteWithCascade_TxRollsBackResource verifies
// that when the resource delete fails AFTER the link cascade succeeds, the
// caller sees the failure and the recordingTxManager would have rolled
// back (its inline runner returns the error rather than committing). The
// fake resource store can be coaxed into returning an error via deleteFn.
func TestResourceAdminService_DeleteWithCascade_TxRollsBackResource(t *testing.T) {
	frontSvc, fres, _, _ := newFrontingService(t)
	seedResource(t, fres, "a", resource.BackendMint, []string{"s"})
	seedResource(t, fres, "b", resource.BackendMint, []string{"s"})
	if err := frontSvc.Create(context.Background(), &resource.FrontingLink{
		SourceSlug: "a", TargetSlug: "b",
		ScopeMap: resource.ScopeMap{"s": {"s"}},
	}, "admin"); err != nil {
		t.Fatalf("seed link: %v", err)
	}

	// Force ResourceStore.Delete to fail. The recordingTxManager runs the
	// closure inline and propagates the error — a real tx manager would
	// roll back.
	boom := errors.New("simulated DB failure")
	fres.deleteFn = func(_ context.Context, _ string) error { return boom }

	tx := &recordingTxManager{}
	svc := NewResourceAdminService(fres, newFakeBrokerProviderStore(), newFakeClientStore(), observability.NewNoop(), nil,
		WithFrontingValidator(frontSvc),
		WithResourceAdminTransactionManager(tx),
	)

	aRes, _ := fres.GetBySlug(context.Background(), "a")
	_, err := svc.DeleteWithCascade(context.Background(), aRes.ID, true)
	if !errors.Is(err, boom) {
		t.Fatalf("expected simulated failure, got %v", err)
	}
	if got := tx.calls.Load(); got != 1 {
		t.Errorf("WithTransaction calls = %d, want 1", got)
	}
}

// TestResourceAdminService_Patch_SlugRenameBlocked verifies that renaming a
// Resource's slug is rejected when fronting links reference the current
// (pre-patch) slug. The dependents-list lookup keys on prev.Slug; a
// regression that uses r.Slug (post-patch) would silently allow the rename.
func TestResourceAdminService_Patch_SlugRenameBlocked(t *testing.T) {
	frontSvc, fres, _, _ := newFrontingService(t)
	seedResource(t, fres, "old-slug", resource.BackendMint, []string{"a"})
	seedResource(t, fres, "tgt", resource.BackendMint, []string{"A"})
	if err := frontSvc.Create(context.Background(), &resource.FrontingLink{
		SourceSlug: "old-slug", TargetSlug: "tgt",
		ScopeMap: resource.ScopeMap{"a": {"A"}},
	}, "admin"); err != nil {
		t.Fatalf("seed link: %v", err)
	}

	svc := NewResourceAdminService(fres, newFakeBrokerProviderStore(), newFakeClientStore(), observability.NewNoop(), nil,
		WithFrontingValidator(frontSvc),
	)

	srcRes, _ := fres.GetBySlug(context.Background(), "old-slug")
	newSlug := "new-slug"
	patch := input.ResourcePatch{Slug: &newSlug}
	_, err := svc.Patch(context.Background(), srcRes.ID, patch)
	if err == nil {
		t.Fatal("expected slug-rename block, got nil")
	}
	if !domain.IsError(err) {
		t.Errorf("expected domain error, got %T %v", err, err)
	}
}

// TestResourceAdminService_Patch_SlugRename_NoDeps_Allowed is the negative
// control for SlugRenameBlocked: a slug rename when no links reference
// the resource must succeed.
func TestResourceAdminService_Patch_SlugRename_NoDeps_Allowed(t *testing.T) {
	frontSvc, fres, _, _ := newFrontingService(t)
	seedResource(t, fres, "lonely-old", resource.BackendMint, []string{"a"})

	svc := NewResourceAdminService(fres, newFakeBrokerProviderStore(), newFakeClientStore(), observability.NewNoop(), nil,
		WithFrontingValidator(frontSvc),
	)

	r, _ := fres.GetBySlug(context.Background(), "lonely-old")
	newSlug := "lonely-new"
	if _, err := svc.Patch(context.Background(), r.ID, input.ResourcePatch{Slug: &newSlug}); err != nil {
		t.Fatalf("rename without deps: %v", err)
	}
}
