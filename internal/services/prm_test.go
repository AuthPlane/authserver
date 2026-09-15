package services

import (
	"context"
	"errors"
	"slices"
	"testing"

	"github.com/authplane/authserver/internal/domain"
	"github.com/authplane/authserver/internal/domain/resource"
	"github.com/authplane/authserver/internal/observability"
)

// prmIssuer is a static IssuerProvider.
type prmIssuer string

func (p prmIssuer) Issuer(context.Context) (string, error) { return string(p), nil }

// prmResolver answers Resolve from a fixed table keyed by the exact
// slug-or-URI string, mirroring the registry's own "0 rows / 1 row / many"
// contract.
type prmResolver struct {
	byRef map[string]*resource.Resource
	// ambiguous refs report ErrAmbiguousResource regardless of byRef.
	ambiguous map[string]bool
	// seen records every ref looked up, in order, so tests can assert
	// resolution *order* rather than only its outcome.
	seen []string
}

func (r *prmResolver) Resolve(_ context.Context, ref string) (*resource.Resource, error) {
	r.seen = append(r.seen, ref)
	if r.ambiguous[ref] {
		return nil, domain.ErrAmbiguousResource
	}
	if res, ok := r.byRef[ref]; ok {
		return res, nil
	}
	return nil, domain.ErrResourceNotFound
}

func prmResource(uri, slug, name string, scopes ...string) *resource.Resource {
	sc := make([]resource.Scope, 0, len(scopes))
	for _, s := range scopes {
		sc = append(sc, resource.Scope{Name: s})
	}
	return &resource.Resource{URI: uri, Slug: slug, DisplayName: name, Scopes: sc}
}

func newPRMService(t *testing.T, issuer string, r *prmResolver) *PRMetadataService {
	t.Helper()
	return NewPRMetadataService(prmIssuer(issuer), r, observability.NewNoop())
}

func TestPRMetadata_BarePathServesTheOriginResource(t *testing.T) {
	t.Parallel()

	r := &prmResolver{byRef: map[string]*resource.Resource{
		"https://auth.example.com": prmResource("https://auth.example.com", "root", "Root MCP", "tools/echo"),
	}}
	svc := newPRMService(t, "https://auth.example.com", r)

	md, err := svc.Metadata(context.Background(), "")
	if err != nil {
		t.Fatalf("Metadata: %v", err)
	}

	if md.Resource != "https://auth.example.com" {
		t.Errorf("resource = %q", md.Resource)
	}
	if !slices.Equal(md.AuthorizationServers, []string{"https://auth.example.com"}) {
		t.Errorf("authorization_servers = %v", md.AuthorizationServers)
	}
	if !slices.Equal(md.BearerMethodsSupported, []string{"header"}) {
		t.Errorf("bearer_methods_supported = %v; the MCP spec forbids query-string tokens", md.BearerMethodsSupported)
	}
	if !slices.Equal(md.ScopesSupported, []string{"tools/echo"}) {
		t.Errorf("scopes_supported = %v", md.ScopesSupported)
	}
	if md.ResourceName != "Root MCP" {
		t.Errorf("resource_name = %q", md.ResourceName)
	}
}

// A client holding https://auth.example.com/mcp builds the metadata URL itself
// per RFC 9728 §3.1. That reconstruction must find the Resource.
func TestPRMetadata_RFC9728PathReconstruction(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct{ name, ref, wantURI string }{
		{"single segment", "mcp", "https://auth.example.com/mcp"},
		{"multi segment", "server/mcp", "https://auth.example.com/server/mcp"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			r := &prmResolver{byRef: map[string]*resource.Resource{
				tc.wantURI: prmResource(tc.wantURI, "s", "Name", "tools/echo"),
			}}
			svc := newPRMService(t, "https://auth.example.com", r)

			md, err := svc.Metadata(context.Background(), tc.ref)
			if err != nil {
				t.Fatalf("Metadata(%q): %v", tc.ref, err)
			}
			if md.Resource != tc.wantURI {
				t.Errorf("resource = %q, want %q", md.Resource, tc.wantURI)
			}
		})
	}
}

// A Resource on a different host is unreachable by reconstruction — the only
// way to it is the AS-hosted form addressed by slug, which is what a 401
// challenge points at.
func TestPRMetadata_SlugReachesAForeignHostResource(t *testing.T) {
	t.Parallel()

	r := &prmResolver{byRef: map[string]*resource.Resource{
		"billing": prmResource("https://mcp.other.example.com/mcp", "billing", "Billing", "tools/invoice"),
	}}
	svc := newPRMService(t, "https://auth.example.com", r)

	md, err := svc.Metadata(context.Background(), "billing")
	if err != nil {
		t.Fatalf("Metadata: %v", err)
	}
	if md.Resource != "https://mcp.other.example.com/mcp" {
		t.Errorf("resource = %q", md.Resource)
	}
	// The document still names this AS: that is the whole point of hosting it
	// here rather than on the resource's own origin.
	if !slices.Equal(md.AuthorizationServers, []string{"https://auth.example.com"}) {
		t.Errorf("authorization_servers = %v", md.AuthorizationServers)
	}
}

// Reconstruction must be tried first. A client that constructed the RFC path
// deserves the Resource it named, never one that merely carries that slug.
func TestPRMetadata_ReconstructionWinsOverSlug(t *testing.T) {
	t.Parallel()

	r := &prmResolver{byRef: map[string]*resource.Resource{
		"https://auth.example.com/mcp": prmResource("https://auth.example.com/mcp", "other", "By path", "a"),
		"mcp":                          prmResource("https://elsewhere.example.com/x", "mcp", "By slug", "b"),
	}}
	svc := newPRMService(t, "https://auth.example.com", r)

	md, err := svc.Metadata(context.Background(), "mcp")
	if err != nil {
		t.Fatalf("Metadata: %v", err)
	}
	if md.Resource != "https://auth.example.com/mcp" {
		t.Errorf("resource = %q, want the path-reconstructed match to win", md.Resource)
	}
	if len(r.seen) == 0 || r.seen[0] != "https://auth.example.com/mcp" {
		t.Errorf("lookup order = %v, want the reconstruction attempted first", r.seen)
	}
}

// A trailing slash on the configured issuer must not produce a doubled slash in
// the reconstructed identifier.
func TestPRMetadata_IssuerTrailingSlashDoesNotDoubleUp(t *testing.T) {
	t.Parallel()

	r := &prmResolver{byRef: map[string]*resource.Resource{
		"https://auth.example.com/mcp": prmResource("https://auth.example.com/mcp", "s", "N", "a"),
	}}
	svc := newPRMService(t, "https://auth.example.com/", r)

	if _, err := svc.Metadata(context.Background(), "mcp"); err != nil {
		t.Fatalf("Metadata: %v", err)
	}
	for _, ref := range r.seen {
		if ref == "https://auth.example.com//mcp" {
			t.Errorf("reconstructed a doubled slash: %v", r.seen)
		}
	}
}

func TestPRMetadata_UnknownRefIsNotFound(t *testing.T) {
	t.Parallel()

	svc := newPRMService(t, "https://auth.example.com", &prmResolver{byRef: map[string]*resource.Resource{}})

	_, err := svc.Metadata(context.Background(), "nope")
	if !errors.Is(err, domain.ErrResourceNotFound) {
		t.Errorf("error = %v, want ErrResourceNotFound", err)
	}
}

// An ambiguous reference is an operator misconfiguration. Reporting it as
// not-found keeps the endpoint from becoming a probe for registry contents.
func TestPRMetadata_AmbiguousRefCollapsesToNotFound(t *testing.T) {
	t.Parallel()

	svc := newPRMService(t, "https://auth.example.com", &prmResolver{
		byRef:     map[string]*resource.Resource{},
		ambiguous: map[string]bool{"dupe": true},
	})

	_, err := svc.Metadata(context.Background(), "dupe")
	if !errors.Is(err, domain.ErrResourceNotFound) {
		t.Errorf("error = %v, want ErrResourceNotFound (not ErrAmbiguousResource)", err)
	}
	if errors.Is(err, domain.ErrAmbiguousResource) {
		t.Error("ambiguity must not leak to the client")
	}
}

// A Resource with no registered scopes must omit scopes_supported rather than
// emit an empty list, which a client reads as "advertises no scopes".
func TestPRMetadata_NoScopesYieldsEmptySlice(t *testing.T) {
	t.Parallel()

	r := &prmResolver{byRef: map[string]*resource.Resource{
		"https://auth.example.com": prmResource("https://auth.example.com", "root", "Root"),
	}}
	svc := newPRMService(t, "https://auth.example.com", r)

	md, err := svc.Metadata(context.Background(), "")
	if err != nil {
		t.Fatalf("Metadata: %v", err)
	}
	if len(md.ScopesSupported) != 0 {
		t.Errorf("scopes_supported = %v, want empty", md.ScopesSupported)
	}
}

// A ref that is not valid UTF-8, or carries a NUL, can never name a registered
// resource. It must be refused before it reaches the store: Postgres rejects
// such bytes as a text parameter, which previously produced two failed round
// trips, three ERROR log lines carrying the attacker's bytes, two error spans
// and a 500 — from an unauthenticated request.
func TestPRMetadata_MalformedRefIsRefusedWithoutTouchingTheStore(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		ref  string
	}{
		{"invalid utf-8", "\xff"},
		{"invalid utf-8 pair", "\xff\xfe"},
		{"embedded NUL", "mcp\x00x"},
		{"lone NUL", "\x00"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			r := &prmResolver{byRef: map[string]*resource.Resource{}}
			svc := newPRMService(t, "https://auth.example.com", r)

			_, err := svc.Metadata(context.Background(), tc.ref)
			if !errors.Is(err, domain.ErrResourceNotFound) {
				t.Errorf("error = %v, want ErrResourceNotFound", err)
			}
			if len(r.seen) != 0 {
				t.Errorf("store was queried %d time(s) with %q; a malformed ref must be refused before any lookup", len(r.seen), r.seen)
			}
		})
	}
}

// A Resource may be registered without a URI — the slug is then its canonical
// identifier. But resource is the one REQUIRED member of RFC 9728 §2, and §3.3
// has the client compare it against the identifier it asked about, so a
// document with an empty resource is one a conformant client must reject.
// Serving 404 is the honest answer rather than emitting an invalid document.
func TestPRMetadata_ResourceWithoutURIIsNotFound(t *testing.T) {
	t.Parallel()

	r := &prmResolver{byRef: map[string]*resource.Resource{
		"slug-only": {Slug: "slug-only", DisplayName: "No URI", URI: ""},
	}}
	svc := newPRMService(t, "https://auth.example.com", r)

	_, err := svc.Metadata(context.Background(), "slug-only")
	if !errors.Is(err, domain.ErrResourceNotFound) {
		t.Errorf("error = %v, want ErrResourceNotFound", err)
	}
}
