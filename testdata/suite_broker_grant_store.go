package testdata

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"reflect"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/authplane/authserver/internal/domain"
	"github.com/authplane/authserver/internal/domain/resource"
	"github.com/authplane/authserver/internal/ports/output"
)

// BrokerGrantStoreSuiteDeps bundles the stores an  BrokerGrantStore
// integration suite needs. The suite seeds its own users / providers via
// the supplied stores so the (user_id, broker_provider_id) FK chain is
// satisfiable end-to-end.
type BrokerGrantStoreSuiteDeps struct {
	Grants    output.BrokerGrantStore
	Providers output.BrokerProviderStore
	Users     output.UserStore
}

// RunBrokerGrantStoreTests runs the integration test suite against
// the supplied factory.
func RunBrokerGrantStoreTests(t *testing.T, newDeps func(*testing.T) BrokerGrantStoreSuiteDeps) {
	t.Helper()

	t.Run("Create_Active", func(t *testing.T) {
		deps := newDeps(t)
		ctx := context.Background()
		seedUser(t, deps.Users, "u-bg-create")
		seedBrokerProvider(t, deps.Providers, "p-bg-create", "bg-create")

		now := time.Now().UTC().Truncate(time.Second)
		blob := []byte{0xde, 0xad, 0xbe, 0xef}
		g := &resource.BrokerGrant{
			ID:               "bg-create",
			UserID:           "u-bg-create",
			BrokerProviderID: "p-bg-create",
			CredentialData:   blob,
			ScopesGranted: []string{
				"https://www.googleapis.com/auth/calendar.readonly",
			},
			EncBackend: "master-key",
			CreatedAt:  now,
			UpdatedAt:  now,
		}
		if err := deps.Grants.Create(ctx, g); err != nil {
			t.Fatalf("create: %v", err)
		}

		got, err := deps.Grants.Get(ctx, "u-bg-create", "p-bg-create")
		if err != nil {
			t.Fatalf("get: %v", err)
		}
		if got == nil {
			t.Fatal("expected grant, got nil")
		}
		if got.Version != 1 {
			t.Errorf("version = %d, want 1 on Create", got.Version)
		}
		if !bytes.Equal(got.CredentialData, blob) {
			t.Errorf("credential_data round-trip mismatch:\n got %x\nwant %x", got.CredentialData, blob)
		}
		if !reflect.DeepEqual(got.ScopesGranted, g.ScopesGranted) {
			t.Errorf("scopes_granted round-trip: got %v, want %v", got.ScopesGranted, g.ScopesGranted)
		}
		if got.EncBackend != "master-key" {
			t.Errorf("enc_backend = %q, want %q", got.EncBackend, "master-key")
		}
		if got.RevokedAt != nil {
			t.Errorf("RevokedAt = %v, want nil for new grant", got.RevokedAt)
		}
	})

	t.Run("UniqueKey_UserProvider", func(t *testing.T) {
		deps := newDeps(t)
		ctx := context.Background()
		seedUser(t, deps.Users, "u-bg-uk")
		seedBrokerProvider(t, deps.Providers, "p-bg-uk", "bg-uk")

		first := newBrokerGrant("bg-uk-1", "u-bg-uk", "p-bg-uk")
		if err := deps.Grants.Create(ctx, first); err != nil {
			t.Fatalf("first create: %v", err)
		}

		// Second grant with the same (user, provider) but different id
		// must collide on UNIQUE (user_id, broker_provider_id).
		second := newBrokerGrant("bg-uk-2", "u-bg-uk", "p-bg-uk")
		err := deps.Grants.Create(ctx, second)
		if err == nil {
			t.Fatal("expected unique-key violation, got nil")
		}
	})

	t.Run("UpdateWithVersion_Success", func(t *testing.T) {
		deps := newDeps(t)
		ctx := context.Background()
		seedUser(t, deps.Users, "u-bg-uv")
		seedBrokerProvider(t, deps.Providers, "p-bg-uv", "bg-uv")

		g := newBrokerGrant("bg-uv", "u-bg-uv", "p-bg-uv")
		if err := deps.Grants.Create(ctx, g); err != nil {
			t.Fatalf("create: %v", err)
		}

		// Mutate then UpdateWithVersion. The store reads back version=1
		// from the row; caller passes version=1 and expects version=2
		// after the update.
		newBlob := []byte{0xca, 0xfe, 0xba, 0xbe}
		g.CredentialData = newBlob
		g.ScopesGranted = []string{"a", "b"}
		g.EncBackend = "vault-transit"
		g.Version = 1
		if err := deps.Grants.UpdateWithVersion(ctx, g); err != nil {
			t.Fatalf("update: %v", err)
		}

		got, err := deps.Grants.Get(ctx, "u-bg-uv", "p-bg-uv")
		if err != nil {
			t.Fatalf("get: %v", err)
		}
		if got.Version != 2 {
			t.Errorf("version = %d, want 2 after update", got.Version)
		}
		if !bytes.Equal(got.CredentialData, newBlob) {
			t.Errorf("credential_data after update mismatch:\n got %x\nwant %x", got.CredentialData, newBlob)
		}
		if got.EncBackend != "vault-transit" {
			t.Errorf("enc_backend = %q, want vault-transit", got.EncBackend)
		}
	})

	t.Run("UpdateWithVersion_StaleVersion_Conflict", func(t *testing.T) {
		deps := newDeps(t)
		ctx := context.Background()
		seedUser(t, deps.Users, "u-bg-stale")
		seedBrokerProvider(t, deps.Providers, "p-bg-stale", "bg-stale")

		g := newBrokerGrant("bg-stale", "u-bg-stale", "p-bg-stale")
		if err := deps.Grants.Create(ctx, g); err != nil {
			t.Fatalf("create: %v", err)
		}

		// First, a successful update bumps the row to version=2.
		g.CredentialData = []byte("v2")
		g.Version = 1
		if err := deps.Grants.UpdateWithVersion(ctx, g); err != nil {
			t.Fatalf("first update: %v", err)
		}

		// Caller still holds version=1 (stale). Second attempt must
		// return ErrBrokerGrantConflict, and the row's stored
		// version/credential must be unchanged.
		g.CredentialData = []byte("v3-stale")
		g.Version = 1
		err := deps.Grants.UpdateWithVersion(ctx, g)
		if !errors.Is(err, domain.ErrBrokerGrantConflict) {
			t.Fatalf("expected ErrBrokerGrantConflict, got %v", err)
		}

		got, err := deps.Grants.Get(ctx, "u-bg-stale", "p-bg-stale")
		if err != nil {
			t.Fatalf("get: %v", err)
		}
		if got.Version != 2 {
			t.Errorf("version after stale update = %d, want 2 (unchanged)", got.Version)
		}
		if !bytes.Equal(got.CredentialData, []byte("v2")) {
			t.Errorf("credential_data after stale update changed: %s", got.CredentialData)
		}
	})

	t.Run("UpdateWithVersion_ConcurrentGoroutines_OneWinsRestConflict", func(t *testing.T) {
		// Audit M3: the existing UpdateWithVersion_StaleVersion_Conflict test
		// validates the optimistic-lock semantics sequentially, but does not
		// exercise actual concurrent contention. Vend rotation under load fires
		// many goroutines at the same broker_grants row; the contract per
		// the data model Q4 is that exactly one wins each race and the
		// losers see ErrBrokerGrantConflict. Without this test, a regression
		// where the version bump becomes non-atomic (e.g. someone refactors
		// the UPDATE into a SELECT-then-UPDATE) would surface only in
		// production under load.
		deps := newDeps(t)
		ctx := context.Background()
		seedUser(t, deps.Users, "u-bg-race")
		seedBrokerProvider(t, deps.Providers, "p-bg-race", "bg-race")

		g := newBrokerGrant("bg-race", "u-bg-race", "p-bg-race")
		if err := deps.Grants.Create(ctx, g); err != nil {
			t.Fatalf("create: %v", err)
		}

		// Snapshot the initial version=1 grant. Each goroutine starts from
		// this snapshot — emulating N concurrent vends each holding a stale
		// view of the row. Exactly one must succeed; the rest must surface
		// ErrBrokerGrantConflict.
		const goroutines = 8
		var (
			wg          sync.WaitGroup
			start       = make(chan struct{})
			successes   atomic.Int32
			conflicts   atomic.Int32
			otherErrors atomic.Int32
		)
		for i := 0; i < goroutines; i++ {
			wg.Add(1)
			go func(idx int) {
				defer wg.Done()
				<-start
				attempt := *g
				attempt.CredentialData = []byte(fmt.Sprintf("rotation-%d", idx))
				attempt.Version = 1
				switch err := deps.Grants.UpdateWithVersion(ctx, &attempt); {
				case err == nil:
					successes.Add(1)
				case errors.Is(err, domain.ErrBrokerGrantConflict):
					conflicts.Add(1)
				default:
					otherErrors.Add(1)
					t.Errorf("goroutine %d: unexpected error: %v", idx, err)
				}
			}(i)
		}
		close(start)
		wg.Wait()

		if successes.Load() != 1 {
			t.Errorf("successes = %d, want exactly 1 (optimistic-lock contract violated)",
				successes.Load())
		}
		if conflicts.Load() != int32(goroutines-1) {
			t.Errorf("conflicts = %d, want %d (ErrBrokerGrantConflict)",
				conflicts.Load(), goroutines-1)
		}
		if otherErrors.Load() != 0 {
			t.Errorf("unexpected non-conflict errors: %d", otherErrors.Load())
		}

		got, err := deps.Grants.Get(ctx, "u-bg-race", "p-bg-race")
		if err != nil {
			t.Fatalf("get: %v", err)
		}
		if got == nil {
			t.Fatal("grant disappeared after race")
		}
		if got.Version != 2 {
			t.Errorf("version after race = %d, want 2 (single bump)", got.Version)
		}
		// CredentialData must be one of the rotation-* values, not the
		// initial blob — i.e. the winning UPDATE actually persisted.
		if !bytes.HasPrefix(got.CredentialData, []byte("rotation-")) {
			t.Errorf("credential_data after race = %q, expected rotation-* (winner's value)",
				got.CredentialData)
		}
	})

	t.Run("Revoke_BlocksGet", func(t *testing.T) {
		deps := newDeps(t)
		ctx := context.Background()
		seedUser(t, deps.Users, "u-bg-rev")
		seedBrokerProvider(t, deps.Providers, "p-bg-rev", "bg-rev")

		g := newBrokerGrant("bg-rev", "u-bg-rev", "p-bg-rev")
		if err := deps.Grants.Create(ctx, g); err != nil {
			t.Fatalf("create: %v", err)
		}
		if err := deps.Grants.Revoke(ctx, "bg-rev"); err != nil {
			t.Fatalf("revoke: %v", err)
		}

		got, err := deps.Grants.Get(ctx, "u-bg-rev", "p-bg-rev")
		if err != nil {
			t.Fatalf("get: %v", err)
		}
		if got != nil {
			t.Fatalf("expected (nil, nil) after revoke, got %+v", got)
		}

		// History view still includes it.
		all, err := deps.Grants.ListForUser(ctx, "u-bg-rev")
		if err != nil {
			t.Fatalf("list: %v", err)
		}
		if len(all) != 1 || all[0].RevokedAt == nil {
			t.Fatalf("expected ListForUser to return the revoked row, got %+v", all)
		}
	})

	t.Run("FK_ProviderMustExist", func(t *testing.T) {
		deps := newDeps(t)
		ctx := context.Background()
		seedUser(t, deps.Users, "u-bg-fk")

		g := newBrokerGrant("bg-fk", "u-bg-fk", "p-does-not-exist")
		err := deps.Grants.Create(ctx, g)
		if err == nil {
			t.Fatal("expected FK violation on missing broker_provider_id, got nil")
		}
		if !looksLikeFKError(err) {
			t.Fatalf("expected FK error, got: %v", err)
		}
	})

	// GetByID is the by-id lookup added in the  audit-followup
	// (B17). Used by the admin RevokeBroker path to enrich the audit
	// detail with the (user, provider) pair pre-revoke.
	t.Run("GetByID_ActiveAndRevoked", func(t *testing.T) {
		deps := newDeps(t)
		ctx := context.Background()
		seedUser(t, deps.Users, "u-bg-gbi")
		seedBrokerProvider(t, deps.Providers, "p-bg-gbi-active", "bg-gbi-active")
		seedBrokerProvider(t, deps.Providers, "p-bg-gbi-revoked", "bg-gbi-revoked")

		active := newBrokerGrant("bg-gbi-active", "u-bg-gbi", "p-bg-gbi-active")
		revoked := newBrokerGrant("bg-gbi-revoked", "u-bg-gbi", "p-bg-gbi-revoked")
		if err := deps.Grants.Create(ctx, active); err != nil {
			t.Fatalf("create active: %v", err)
		}
		if err := deps.Grants.Create(ctx, revoked); err != nil {
			t.Fatalf("create revoked: %v", err)
		}
		if err := deps.Grants.Revoke(ctx, "bg-gbi-revoked"); err != nil {
			t.Fatalf("revoke: %v", err)
		}

		gotActive, err := deps.Grants.GetByID(ctx, "bg-gbi-active")
		if err != nil {
			t.Fatalf("GetByID active: %v", err)
		}
		if gotActive == nil || gotActive.ID != "bg-gbi-active" {
			t.Fatalf("GetByID active: got %+v", gotActive)
		}
		if gotActive.RevokedAt != nil {
			t.Errorf("active grant: RevokedAt = %v, want nil", gotActive.RevokedAt)
		}

		gotRevoked, err := deps.Grants.GetByID(ctx, "bg-gbi-revoked")
		if err != nil {
			t.Fatalf("GetByID revoked: %v", err)
		}
		if gotRevoked == nil || gotRevoked.ID != "bg-gbi-revoked" {
			t.Fatalf("GetByID revoked: got %+v", gotRevoked)
		}
		if gotRevoked.RevokedAt == nil {
			t.Error("revoked grant: RevokedAt = nil, want timestamp (GetByID must NOT filter on revoked_at)")
		}
	})

	t.Run("GetByID_NotFound_ReturnsNilNoError", func(t *testing.T) {
		deps := newDeps(t)
		ctx := context.Background()

		got, err := deps.Grants.GetByID(ctx, "no-such-id")
		if err != nil {
			t.Fatalf("GetByID miss returned error: %v (expected nil)", err)
		}
		if got != nil {
			t.Errorf("GetByID miss: got %+v, want nil", got)
		}
	})

	// Upsert is the connect-callback path: a single atomic
	// INSERT … ON CONFLICT (user_id, broker_provider_id) DO UPDATE that
	// covers (a) first connect, (b) re-connect over an active grant,
	// (c) re-connect after Revoke. The previous lookup→revoke→create
	// pattern 500'd on (b) and (c) because Revoke is a soft-delete that
	// does NOT free the UNIQUE slot.

	t.Run("Upsert_Insert_NewRow", func(t *testing.T) {
		deps := newDeps(t)
		ctx := context.Background()
		seedUser(t, deps.Users, "u-bg-up-ins")
		seedBrokerProvider(t, deps.Providers, "p-bg-up-ins", "bg-up-ins")

		now := time.Now().UTC().Truncate(time.Second)
		g := &resource.BrokerGrant{
			ID:               "bg-up-ins",
			UserID:           "u-bg-up-ins",
			BrokerProviderID: "p-bg-up-ins",
			CredentialData:   []byte("first-creds"),
			ScopesGranted:    []string{"read"},
			EncBackend:       "master-key",
			CreatedAt:        now,
			UpdatedAt:        now,
		}
		out, err := deps.Grants.Upsert(ctx, g)
		if err != nil {
			t.Fatalf("upsert insert: %v", err)
		}
		if out.ID != "bg-up-ins" {
			t.Errorf("returned id = %q, want %q (insert preserves supplied id)", out.ID, "bg-up-ins")
		}
		if out.Version != 1 {
			t.Errorf("returned version = %d, want 1 on insert", out.Version)
		}

		// Round-trip via Get.
		got, err := deps.Grants.Get(ctx, "u-bg-up-ins", "p-bg-up-ins")
		if err != nil {
			t.Fatalf("get: %v", err)
		}
		if got == nil {
			t.Fatal("expected grant after Upsert, got nil")
		}
		if got.Version != 1 {
			t.Errorf("stored version = %d, want 1", got.Version)
		}
		if !bytes.Equal(got.CredentialData, []byte("first-creds")) {
			t.Errorf("credential_data = %q, want first-creds", got.CredentialData)
		}
	})

	t.Run("Upsert_Update_PreservesIdBumpsVersion", func(t *testing.T) {
		deps := newDeps(t)
		ctx := context.Background()
		seedUser(t, deps.Users, "u-bg-up-upd")
		seedBrokerProvider(t, deps.Providers, "p-bg-up-upd", "bg-up-upd")

		first := &resource.BrokerGrant{
			ID:               "bg-up-upd-ORIGINAL",
			UserID:           "u-bg-up-upd",
			BrokerProviderID: "p-bg-up-upd",
			CredentialData:   []byte("v1"),
			ScopesGranted:    []string{"read"},
			EncBackend:       "master-key",
			CreatedAt:        time.Now().UTC().Truncate(time.Second),
			UpdatedAt:        time.Now().UTC().Truncate(time.Second),
		}
		if _, err := deps.Grants.Upsert(ctx, first); err != nil {
			t.Fatalf("first upsert: %v", err)
		}

		// Second upsert with a DIFFERENT id but same (user, provider).
		// The UNIQUE constraint hits, ON CONFLICT fires, the existing
		// row's id is preserved, version bumps 1 → 2.
		second := &resource.BrokerGrant{
			ID:               "bg-up-upd-REPLACED",
			UserID:           "u-bg-up-upd",
			BrokerProviderID: "p-bg-up-upd",
			CredentialData:   []byte("v2"),
			ScopesGranted:    []string{"read", "write"},
			EncBackend:       "vault-transit",
			CreatedAt:        time.Now().UTC().Truncate(time.Second),
			UpdatedAt:        time.Now().UTC().Truncate(time.Second),
		}
		out, err := deps.Grants.Upsert(ctx, second)
		if err != nil {
			t.Fatalf("second upsert: %v", err)
		}

		if out.ID != "bg-up-upd-ORIGINAL" {
			t.Errorf("returned id = %q, want %q (update must preserve existing id)",
				out.ID, "bg-up-upd-ORIGINAL")
		}
		if out.Version != 2 {
			t.Errorf("returned version = %d, want 2 after update", out.Version)
		}
		if !bytes.Equal(out.CredentialData, []byte("v2")) {
			t.Errorf("returned credential_data = %q, want v2", out.CredentialData)
		}
		if !reflect.DeepEqual(out.ScopesGranted, []string{"read", "write"}) {
			t.Errorf("returned scopes = %v, want [read write]", out.ScopesGranted)
		}
		if out.EncBackend != "vault-transit" {
			t.Errorf("returned enc_backend = %q, want vault-transit", out.EncBackend)
		}
		if out.RevokedAt != nil {
			t.Errorf("returned revoked_at = %v, want nil", out.RevokedAt)
		}

		// The "REPLACED" id must NOT exist as a separate row — the
		// upsert wrote into the existing row, not a new one.
		gotByNewID, err := deps.Grants.GetByID(ctx, "bg-up-upd-REPLACED")
		if err != nil {
			t.Fatalf("getById replaced: %v", err)
		}
		if gotByNewID != nil {
			t.Errorf("a row materialized under the supplied id %q on update path; want nil",
				"bg-up-upd-REPLACED")
		}
	})

	t.Run("Upsert_ResurrectsRevokedRow", func(t *testing.T) {
		deps := newDeps(t)
		ctx := context.Background()
		seedUser(t, deps.Users, "u-bg-up-res")
		seedBrokerProvider(t, deps.Providers, "p-bg-up-res", "bg-up-res")

		// 1) Create + revoke. After revoke, Get returns nil but the row
		//    is still on disk and still occupies the UNIQUE slot.
		first := &resource.BrokerGrant{
			ID:               "bg-up-res-original",
			UserID:           "u-bg-up-res",
			BrokerProviderID: "p-bg-up-res",
			CredentialData:   []byte("revoked-creds"),
			ScopesGranted:    []string{"old"},
			EncBackend:       "master-key",
			CreatedAt:        time.Now().UTC().Truncate(time.Second),
			UpdatedAt:        time.Now().UTC().Truncate(time.Second),
		}
		if _, err := deps.Grants.Upsert(ctx, first); err != nil {
			t.Fatalf("first upsert: %v", err)
		}
		if err := deps.Grants.Revoke(ctx, "bg-up-res-original"); err != nil {
			t.Fatalf("revoke: %v", err)
		}

		// Pre-condition for the regression: under the OLD code a Create
		// here would 500 because the UNIQUE slot is still held by the
		// soft-deleted row. Upsert handles it.
		fresh := &resource.BrokerGrant{
			ID:               "bg-up-res-NEW-IGNORED",
			UserID:           "u-bg-up-res",
			BrokerProviderID: "p-bg-up-res",
			CredentialData:   []byte("fresh-creds"),
			ScopesGranted:    []string{"new"},
			EncBackend:       "master-key",
			CreatedAt:        time.Now().UTC().Truncate(time.Second),
			UpdatedAt:        time.Now().UTC().Truncate(time.Second),
		}
		out, err := deps.Grants.Upsert(ctx, fresh)
		if err != nil {
			t.Fatalf("resurrect upsert: %v", err)
		}
		if out.ID != "bg-up-res-original" {
			t.Errorf("resurrected id = %q, want %q (existing row's id, not the new one)",
				out.ID, "bg-up-res-original")
		}
		if out.RevokedAt != nil {
			t.Errorf("revoked_at = %v, want nil after resurrect", out.RevokedAt)
		}
		if out.Version != 2 {
			t.Errorf("version after resurrect = %d, want 2 (bump from 1 → 2)", out.Version)
		}
		if !bytes.Equal(out.CredentialData, []byte("fresh-creds")) {
			t.Errorf("credential_data after resurrect = %q, want fresh-creds", out.CredentialData)
		}

		// Get must now return the resurrected row (revoked_at IS NULL filter).
		got, err := deps.Grants.Get(ctx, "u-bg-up-res", "p-bg-up-res")
		if err != nil {
			t.Fatalf("get after resurrect: %v", err)
		}
		if got == nil {
			t.Fatal("expected active grant after resurrect; Get returned nil")
		}
		if got.ID != "bg-up-res-original" {
			t.Errorf("Get id = %q, want %q", got.ID, "bg-up-res-original")
		}
	})
}

// newBrokerGrant builds a minimal grant used by the BrokerGrant suite.
// CredentialData is opaque non-empty bytes (the adapter must not parse
// them); ScopesGranted has one upstream-format entry.
func newBrokerGrant(id, userID, providerID string) *resource.BrokerGrant {
	now := time.Now().UTC().Truncate(time.Second)
	return &resource.BrokerGrant{
		ID:               id,
		UserID:           userID,
		BrokerProviderID: providerID,
		CredentialData:   []byte("opaque-encrypted-bytes"),
		ScopesGranted:    []string{"https://www.googleapis.com/auth/calendar"},
		EncBackend:       "master-key",
		CreatedAt:        now,
		UpdatedAt:        now,
	}
}

// seedBrokerProvider creates a minimal OAuth-protocol provider row so
// the (user, provider) FK chain in broker_grants is satisfiable.
func seedBrokerProvider(t *testing.T, store output.BrokerProviderStore, id, slug string) {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Second)
	p := &resource.BrokerProvider{
		ID:          id,
		Slug:        slug,
		DisplayName: "Test " + id,
		Protocol:    resource.ProtocolOAuth,
		ConfigData:  []byte(`{"client_id":"x"}`),
		CreatedAt:   now,
		UpdatedAt:   now,
	}
	if err := store.Create(context.Background(), p); err != nil {
		t.Fatalf("seed broker provider %q: %v", id, err)
	}
}
