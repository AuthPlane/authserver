// Package testdata provides test infrastructure for integration tests.
package testdata

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/authplane/authserver/internal/adapters/sqlite"
	"github.com/authplane/authserver/internal/crypto"
	"github.com/authplane/authserver/internal/domain"
	"github.com/authplane/authserver/internal/domain/client"
	"github.com/authplane/authserver/internal/domain/resource"
	"github.com/authplane/authserver/internal/observability"
	"github.com/authplane/authserver/internal/ports/output"
)

// TestHelper provides access to stores for test setup.
type TestHelper struct {
	Stores *sqlite.Stores
}

// SetupTestDB creates an in-memory SQLite database with migrations applied.
// It registers cleanup to close the DB when the test completes.
func SetupTestDB(t *testing.T) *sqlite.DB {
	t.Helper()

	obs := testProvider()
	db, err := sqlite.Open(":memory:", obs)
	if err != nil {
		t.Fatalf("open test db: %v", err)
	}

	if err := db.Migrate(context.Background()); err != nil {
		db.Close()
		t.Fatalf("migrate test db: %v", err)
	}

	t.Cleanup(func() { db.Close() })
	return db
}

// SetupTestStores creates an in-memory SQLite database and returns all stores.
func SetupTestStores(t *testing.T) *sqlite.Stores {
	t.Helper()
	return SetupTestDB(t).NewStores()
}

func testProvider() *observability.Provider {
	return observability.NewNoop()
}

// SeedClientAndUser creates a minimal client and user with the given IDs.
// Required by tests that insert token_families rows directly (:
// token_families.client_id and user_id are now FK-enforced).
func SeedClientAndUser(t *testing.T, cs output.ClientStore, us output.UserStore, clientID, userID string) {
	t.Helper()
	ctx := context.Background()
	if err := cs.Create(ctx, newTestClient(clientID)); err != nil {
		t.Fatalf("seed client %q: %v", clientID, err)
	}
	if err := us.Create(ctx, newTestUser(userID, userID+"@test.com")); err != nil {
		t.Fatalf("seed user %q: %v", userID, err)
	}
}

// EnsureClient idempotently creates a client with the given ID.
// helper for tests that need a parent client for token_families/machine_tokens
// FKs but may not know whether a previous step already seeded it.
func EnsureClient(t *testing.T, cs output.ClientStore, id string) {
	t.Helper()
	ctx := context.Background()
	if got, _ := cs.GetByID(ctx, id); got != nil {
		return
	}
	if err := cs.Create(ctx, newTestClient(id)); err != nil {
		t.Fatalf("ensure client %q: %v", id, err)
	}
}

// EnsureUser idempotently creates a user with the given ID. helper.
func EnsureUser(t *testing.T, us output.UserStore, id string) {
	t.Helper()
	ctx := context.Background()
	if got, _ := us.GetByID(ctx, id); got != nil {
		return
	}
	// Email must be unique; derive it from the ID so independent EnsureUser
	// calls in the same test database do not collide.
	if err := us.Create(ctx, newTestUser(id, id+"@test.com")); err != nil {
		t.Fatalf("ensure user %q: %v", id, err)
	}
}

// CreateClient inserts an OAuth client for tests that need to act as somebody
// other than the fixture's default client — a second caller, a suspended one,
// or a public one. An empty secret produces a public client.
func CreateClient(t *testing.T, stores *sqlite.Stores, id, secret string, status client.Status) {
	t.Helper()
	c := &client.Client{
		ID:           id,
		Name:         id,
		RedirectURIs: []string{"http://localhost/callback"},
		Status:       status,
		IssuedAt:     time.Now(),
	}
	if secret != "" {
		hash, err := crypto.HashBcrypt(secret)
		if err != nil {
			t.Fatalf("hash bcrypt: %v", err)
		}
		c.SecretHash = hash
	}
	if err := stores.Client.Create(context.Background(), c); err != nil {
		t.Fatalf("create client %s: %v", id, err)
	}
}

// CreateMintResource inserts a Mint Resource at uri, authorizing
// runtimeClientIDs to act AS it (policy.runtime.client_ids). An empty list
// leaves the Resource default-deny, which is the shipped default.
func CreateMintResource(t *testing.T, stores *sqlite.Stores, id, slug, uri string, runtimeClientIDs ...string) {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Second)
	r := &resource.Resource{
		ID:          id,
		Slug:        slug,
		DisplayName: "Test " + slug,
		URI:         uri,
		BackendKind: resource.BackendMint,
		Policy:      resource.Policy{Runtime: resource.RuntimePolicy{ClientIDs: runtimeClientIDs}},
		CreatedAt:   now,
		UpdatedAt:   now,
	}
	if err := stores.Resource.Create(context.Background(), r); err != nil {
		t.Fatalf("create resource %s: %v", slug, err)
	}
}

// FailingResourceResolver stands in for a resources store that cannot answer a
// lookup. It satisfies the narrow resolver the introspection service depends
// on, so a test can drive the paths where the AS fails to decide rather than
// the caller failing to qualify.
type FailingResourceResolver struct{ Err error }

// Resolve always fails with the configured error.
func (f FailingResourceResolver) Resolve(_ context.Context, _ string) (*resource.Resource, error) {
	return nil, f.Err
}

// NewUnavailableResourceResolver models the store being down — a server-side
// fault with no caller at fault.
func NewUnavailableResourceResolver() FailingResourceResolver {
	return FailingResourceResolver{Err: errors.New("resources table unavailable")}
}

// NewAmbiguousResourceResolver models two Resources answering to one slug or
// URI: an operator misconfiguration, distinct from both a store outage and an
// unentitled caller.
func NewAmbiguousResourceResolver() FailingResourceResolver {
	return FailingResourceResolver{Err: domain.ErrAmbiguousResource}
}

// resourceResolver is the narrow lookup the introspection service depends on.
// Declared here so testdata does not import the services package.
type resourceResolver interface {
	Resolve(ctx context.Context, slugOrURI string) (*resource.Resource, error)
}

// FlakyResourceResolver fails for one slug-or-URI and delegates the rest, so a
// test can drive a partial outage: one audience entry unresolvable while
// another still answers.
type FlakyResourceResolver struct {
	delegate resourceResolver
	failFor  string
}

// NewFlakyResourceResolver wraps delegate, failing only for failFor.
func NewFlakyResourceResolver(delegate resourceResolver, failFor string) FlakyResourceResolver {
	return FlakyResourceResolver{delegate: delegate, failFor: failFor}
}

// Resolve errors for the configured entry and delegates every other lookup.
func (f FlakyResourceResolver) Resolve(ctx context.Context, slugOrURI string) (*resource.Resource, error) {
	if slugOrURI == f.failFor {
		return nil, errors.New("resource lookup timed out")
	}
	return f.delegate.Resolve(ctx, slugOrURI)
}

// CreateIssuance writes a live Mint issuance row keyed by jti for a token
// the AS minted to clientID for the user against resourceID. The row's id
// is the jti, as MintIssuer writes it. consentClientID and parentJTI are
// the lineage columns; pass "" for a first-hop token with no parent.
func CreateIssuance(t *testing.T, stores *sqlite.Stores, jti, userID, clientID, resourceID, consentClientID, parentJTI string) {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Second)
	iss := &resource.Issuance{
		ID:              jti,
		JTI:             jti,
		SubjectUserID:   userID,
		ClientID:        clientID,
		ResourceID:      resourceID,
		Scopes:          []string{"tools/echo"},
		BackendKind:     resource.BackendMint,
		Revocable:       true,
		IssuedAt:        now,
		ExpiresAt:       now.Add(time.Hour),
		ConsentClientID: consentClientID,
		ParentJTI:       parentJTI,
	}
	if err := stores.Issuance.Insert(context.Background(), iss); err != nil {
		t.Fatalf("create issuance %s: %v", jti, err)
	}
}

// RevokeIssuance marks the issuance row with the given jti as revoked, the
// way the admin single-issuance revoke does.
func RevokeIssuance(t *testing.T, stores *sqlite.Stores, jti string) {
	t.Helper()
	if err := stores.Issuance.Revoke(context.Background(), jti); err != nil {
		t.Fatalf("revoke issuance %s: %v", jti, err)
	}
}

// IssuanceRevoked reports whether the issuance row with the given jti
// carries a revoked_at.
func IssuanceRevoked(t *testing.T, stores *sqlite.Stores, jti string) bool {
	t.Helper()
	got, err := stores.Issuance.GetByJTI(context.Background(), jti)
	if err != nil {
		t.Fatalf("get issuance %s: %v", jti, err)
	}
	if got == nil {
		t.Fatalf("get issuance %s: no row", jti)
	}
	return got.RevokedAt != nil
}

// BrokenIssuanceStore is an output.IssuanceStore whose every method fails
// with Err. It stands in for a store that is down, for the paths that must
// fail closed when the issuance log cannot be read.
type BrokenIssuanceStore struct{ Err error }

func (b BrokenIssuanceStore) Insert(context.Context, *resource.Issuance) error { return b.Err }
func (b BrokenIssuanceStore) GetByID(context.Context, string) (*resource.Issuance, error) {
	return nil, b.Err
}
func (b BrokenIssuanceStore) GetByJTI(context.Context, string) (*resource.Issuance, error) {
	return nil, b.Err
}
func (b BrokenIssuanceStore) Revoke(context.Context, string) error { return b.Err }
func (b BrokenIssuanceStore) RevokeFamily(context.Context, string, string, string) (int, error) {
	return 0, b.Err
}
func (b BrokenIssuanceStore) ListForUser(context.Context, string, time.Time) ([]*resource.Issuance, error) {
	return nil, b.Err
}
func (b BrokenIssuanceStore) ListForActor(context.Context, string, time.Time) ([]*resource.Issuance, error) {
	return nil, b.Err
}
func (b BrokenIssuanceStore) ListForResource(context.Context, string, time.Time) ([]*resource.Issuance, error) {
	return nil, b.Err
}
func (b BrokenIssuanceStore) PurgeExpired(context.Context, time.Time) (int, error) { return 0, b.Err }
