package signing

import (
	"testing"

	"github.com/authplane/authserver/internal/ports/output"
)

// fakeStore is a no-op DataStore (embedded nil interface — only identity is
// used; its methods are never called).
type fakeStore struct{ output.DataStore }

// wrapStore is a decorator that exposes Unwrap, like the user-cache wrapper.
type wrapStore struct {
	output.DataStore
	inner output.DataStore
}

func (w *wrapStore) Unwrap() output.DataStore { return w.inner }

// TestUnderlyingDataStore guards the fix for postgres_key signing failing to
// boot when the DataStore is fronted by the user cache: the factory must see
// through decorators to reach the concrete adapter.
func TestUnderlyingDataStore(t *testing.T) {
	base := &fakeStore{}

	if got := underlyingDataStore(base); got != base {
		t.Fatalf("plain store should return itself, got %p want %p", got, base)
	}

	wrapped := &wrapStore{inner: base}
	if got := underlyingDataStore(wrapped); got != base {
		t.Fatalf("decorated store should unwrap to base")
	}

	nested := &wrapStore{inner: wrapped}
	if got := underlyingDataStore(nested); got != base {
		t.Fatalf("nested decorators should unwrap to base")
	}

	// A decorator that unwraps to nil returns itself rather than nil.
	nilWrap := &wrapStore{inner: nil}
	if got := underlyingDataStore(nilWrap); got != nilWrap {
		t.Fatalf("nil Unwrap should return the wrapper itself")
	}
}
