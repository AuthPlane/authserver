package storage

import (
	"context"
	"errors"

	"github.com/authplane/authserver/internal/domain"
	"github.com/authplane/authserver/internal/domain/user"
	"github.com/authplane/authserver/internal/ports/output"
)

// WrapUserStore fronts inner with c on GetByID, caching both a found user and
// domain.ErrUserNotFound. Other methods pass through; Update and Delete
// invalidate the entry. Expiry and size-bounding belong to the injected cache.
//
// It exists to protect the database: SessionMiddleware calls GetByID on every
// authenticated request, which without caching is one query per request.
//
// c must be non-nil — pass cache.NewMemoryTTLBounded[*Entry](ttl, maxSize), or
// a partition-aware implementation. To skip caching, use inner directly.
//
// Two properties callers depend on:
//
// GetByID always returns the caller's own copy, on hits and misses alike, so
// mutating it reaches neither the cache nor another caller. Mutators can keep
// writing in place and persisting with Update.
//
// That does not weaken optimistic locking, because Update binds u.Version into
// WHERE ... AND version = ? and increments the column in SQL without writing
// the new value back to the struct. If Update ever starts refreshing u.Version
// on success, revisit this: the copy handed out here would become a stale
// version carrier and change who wins a concurrent update.
//
// The cache TTL is the freshness bound everywhere — including the instance
// that served the change, and for deletes as much as disables. Update and
// Delete both invalidate after their write, which cannot stop an entry that has
// not arrived yet: a GetByID that reads the row before the write and stores it
// after the invalidation re-caches the old value.
//
// The two windows are not the same size. Update's is one read-through, the gap
// between that read loading the row and storing it. Delete's is wider, because
// AdminService.DeleteUser calls it inside a transaction and the invalidation
// therefore lands before COMMIT: every read between the two sees a live row.
// Delete's godoc has the detail.
//
// There is no stampede protection either — concurrent misses for one id each
// issue their own query — which multiplies the read-throughs those windows are
// measured in.
//
// Closing Update's needs double invalidation and a non-discarded Invalidate
// error; closing Delete's needs an invalidation that runs after the commit, and
// no method on this interface runs there. Both are tracked separately. Until
// then, do not treat this as a hard revocation boundary.
func WrapUserStore(inner output.UserStore, c output.Cache[*Entry]) output.UserStore {
	return &cachedUserStore{inner: inner, cache: c}
}

// WithUserCache returns a DataStore whose User() method is fronted with the
// given cache (see WrapUserStore, which requires c to be non-nil). All other
// DataStore methods pass through unchanged.
func WithUserCache(ds output.DataStore, c output.Cache[*Entry]) output.DataStore {
	wrapped := WrapUserStore(ds.User(), c)
	return &dsWithUserCache{DataStore: ds, users: wrapped}
}

// dsWithUserCache embeds the original DataStore and overrides User().
type dsWithUserCache struct {
	output.DataStore
	users output.UserStore
}

func (d *dsWithUserCache) User() output.UserStore { return d.users }

// Unwrap returns the wrapped DataStore so driver-specific consumers (e.g. the
// postgres_key signing-key factory, which needs the concrete *postgres.DB to
// extract its connection pool) can see through this decorator.
func (d *dsWithUserCache) Unwrap() output.DataStore { return d.DataStore }

// cachedUserStore is a transparent decorator over output.UserStore.
type cachedUserStore struct {
	inner output.UserStore
	cache output.Cache[*Entry]
}

// Entry is what the injected cache stores for one id: notFound=true is a cached
// domain.ErrUserNotFound, otherwise snapshot holds the user. Other errors are
// never cached.
//
// snapshot belongs to the cache and is never handed out — GetByID copies it in
// and out. That is not tidiness: AdminService.DisableUser calls u.Disable(),
// writing Status and UpdatedAt in place, while the session middleware reads
// IsActive() on every authenticated request, so a shared pointer is a data
// race. user.User is a flat struct of value fields, so *u is a full copy.
type Entry struct {
	snapshot *user.User
	notFound bool
}

var _ output.UserStore = (*cachedUserStore)(nil)

// GetByID short-circuits to the cache when an entry exists.
func (c *cachedUserStore) GetByID(ctx context.Context, id string) (*user.User, error) {
	if e, _ := c.cache.Load(ctx, id); e != nil {
		if e.notFound {
			return nil, domain.ErrUserNotFound
		}
		if e.snapshot == nil {
			// Cannot happen through Store below, which never caches a nil user;
			// guarding anyway so a hand-built Entry can't panic the request.
			return nil, domain.ErrStoreReturnedNoUser
		}
		cp := *e.snapshot
		return &cp, nil
	}

	u, err := c.inner.GetByID(ctx, id)
	switch {
	case err == nil && u == nil:
		// sqlite and postgres never do this, but the seam is exported. Converted
		// rather than forwarded because every caller returns early on an error,
		// while only three of twelve guard on a nil user — and four of the rest
		// (UpdateUser, DisableUser, EnableUser, the introspection subject check)
		// dereference it. Not cached: a broken answer is not worth a TTL.
		return nil, domain.ErrStoreReturnedNoUser
	case err == nil:
		cached := *u
		_ = c.cache.Store(ctx, id, &Entry{snapshot: &cached})
		out := *u
		return &out, nil
	case errors.Is(err, domain.ErrUserNotFound):
		_ = c.cache.Store(ctx, id, &Entry{notFound: true})
		return nil, err
	default:
		// Transient error — do not cache; let the caller decide policy.
		return nil, err
	}
}

// Update invalidates the cached entry so subsequent reads see the new row.
// Unconditionally, like Delete and for the same reason: a partially applied
// write must not leave a stale positive entry. A nil user is the one case that
// skips it, having no id to invalidate.
func (c *cachedUserStore) Update(ctx context.Context, u *user.User) error {
	err := c.inner.Update(ctx, u)
	if u != nil {
		_ = c.cache.Invalidate(ctx, u.ID)
	}
	return err
}

// Delete invalidates unconditionally — not gated on inner.Delete's error — so a
// partially succeeded delete (rare, but possible with FK cascade rollback)
// cannot leave a positive entry pointing at a row that is gone. That guarantee
// comes from being unconditional, not from where the call sits.
//
// It sits after the write, which shortens the exposure without closing it.
// AdminService.DeleteUser calls this from inside a transaction, so whichever
// side of inner.Delete the invalidation sits on it still runs before COMMIT —
// and the row stays visible to other connections until then. The window is
// therefore [invalidate, commit): a concurrent read in there misses, loads the
// still-live row, and caches a positive entry that nothing invalidates again.
// The deleted user keeps passing SessionMiddleware for the rest of the TTL.
//
// What moving the call bought is the DELETE statement's own duration, which is
// no longer inside the window. It did not buy the commit, and the commit is the
// slower part. Closing this needs invalidation after the transaction commits,
// which no method on output.UserStore can reach — an optional Invalidator with
// a type assertion in DeleteUser, or a post-commit hook on the tx manager.
// Tracked with the Update window rather than done here.
//
// Update is not affected: it does not run in a transaction, so its window is
// the one read-through described on WrapUserStore.
func (c *cachedUserStore) Delete(ctx context.Context, id string) error {
	err := c.inner.Delete(ctx, id)
	_ = c.cache.Invalidate(ctx, id)
	return err
}

func (c *cachedUserStore) Create(ctx context.Context, u *user.User) error {
	return c.inner.Create(ctx, u)
}

func (c *cachedUserStore) GetByEmail(ctx context.Context, email string) (*user.User, error) {
	return c.inner.GetByEmail(ctx, email)
}

func (c *cachedUserStore) GetByProviderSub(ctx context.Context, p user.Provider, sub string) (*user.User, error) {
	return c.inner.GetByProviderSub(ctx, p, sub)
}

func (c *cachedUserStore) List(ctx context.Context) ([]user.User, error) {
	return c.inner.List(ctx)
}

func (c *cachedUserStore) Count(ctx context.Context) (int, error) {
	return c.inner.Count(ctx)
}
