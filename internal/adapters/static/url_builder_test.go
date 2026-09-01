package static_test

import (
	"context"
	"testing"

	"github.com/authplane/authserver/internal/adapters/static"
	"github.com/authplane/authserver/internal/ports/output"
)

// Compile-time check: the adapter satisfies the output port.
var _ output.URLBuilder = (*static.URLBuilder)(nil)

func TestURLBuilder_IgnoresContext(t *testing.T) {
	b := static.NewURLBuilder()

	type fakeKey struct{}
	ctx := context.WithValue(context.Background(), fakeKey{}, "should-be-ignored")

	const path = "/dashboard"
	got, err := b.Resolve(ctx, path)
	if err != nil {
		t.Fatalf("Resolve(ctx-with-value, %q) error = %v, want nil", path, err)
	}
	if got != path {
		t.Fatalf("Resolve(ctx-with-value, %q) = %q, want %q", path, got, path)
	}
}

func TestURLBuilder_Resolve_Root(t *testing.T) {
	b := static.NewURLBuilder()
	for _, p := range []string{"/", "/login", "/oauth/authorize?x=1"} {
		got, err := b.Resolve(context.Background(), p)
		if err != nil || got != p {
			t.Errorf("Resolve(%q) = %q, err=%v; want %q, nil (OSS is root-only)", p, got, err, p)
		}
	}
}
