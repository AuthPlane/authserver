package wellknown_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/authplane/authserver/api/public/wellknown"
	"github.com/authplane/authserver/internal/domain"
	"github.com/authplane/authserver/internal/observability"
	"github.com/authplane/authserver/internal/ports/input"
)

// stubPRM answers from a fixed ref → document table and records what it was
// asked, so the routing assertions can check the ref actually extracted from
// the URL path rather than only the status code.
type stubPRM struct {
	docs map[string]*input.ProtectedResourceMetadata
	seen []string
}

func (s *stubPRM) Metadata(_ context.Context, ref string) (*input.ProtectedResourceMetadata, error) {
	s.seen = append(s.seen, ref)
	if doc, ok := s.docs[ref]; ok {
		return doc, nil
	}
	return nil, domain.ErrResourceNotFound
}

// prmRequest builds the context-carrying GET these tests issue. The caller
// sends it and closes the body: keeping the Do and the Close in the same
// function is what lets bodyclose verify the pairing.
func prmRequest(t *testing.T, ts *httptest.Server, path string) *http.Request {
	t.Helper()

	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, ts.URL+path, nil)
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	return req
}

func newPRMServer(t *testing.T, prm input.PRMetadataPort) *httptest.Server {
	t.Helper()

	mux := http.NewServeMux()
	wellknown.RegisterRoutes(mux, wellknown.Deps{PRMetadata: prm}, observability.NewNoop())
	ts := httptest.NewServer(mux)
	t.Cleanup(ts.Close)
	return ts
}

func TestPRMRoutes_RefExtraction(t *testing.T) {
	t.Parallel()

	doc := &input.ProtectedResourceMetadata{
		Resource:               "https://auth.example.com/mcp",
		AuthorizationServers:   []string{"https://auth.example.com"},
		ScopesSupported:        []string{"tools/echo"},
		BearerMethodsSupported: []string{"header"},
		ResourceName:           "Demo MCP",
	}

	cases := []struct {
		name    string
		path    string
		wantRef string
	}{
		{"bare path yields an empty ref", "/.well-known/oauth-protected-resource", ""},
		{"single path segment", "/.well-known/oauth-protected-resource/mcp", "mcp"},
		// RFC 9728 §3.1 inserts the well-known segment before the resource's
		// full path, which is frequently multi-segment. A single-segment route
		// pattern would 404 these.
		{"multi segment path", "/.well-known/oauth-protected-resource/server/mcp", "server/mcp"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			stub := &stubPRM{docs: map[string]*input.ProtectedResourceMetadata{tc.wantRef: doc}}
			ts := newPRMServer(t, stub)

			resp, err := ts.Client().Do(prmRequest(t, ts, tc.path))
			if err != nil {
				t.Fatalf("GET: %v", err)
			}
			defer func() { _ = resp.Body.Close() }()

			if resp.StatusCode != http.StatusOK {
				t.Fatalf("status = %d, want 200", resp.StatusCode)
			}
			if len(stub.seen) != 1 || stub.seen[0] != tc.wantRef {
				t.Errorf("service asked for ref %v, want %q", stub.seen, tc.wantRef)
			}
			if ct := resp.Header.Get("Content-Type"); ct != "application/json" {
				t.Errorf("content-type = %q, want application/json", ct)
			}
		})
	}
}

func TestPRMRoutes_DocumentShape(t *testing.T) {
	t.Parallel()

	stub := &stubPRM{docs: map[string]*input.ProtectedResourceMetadata{
		"": {
			Resource:               "https://auth.example.com",
			AuthorizationServers:   []string{"https://auth.example.com"},
			ScopesSupported:        []string{"tools/echo", "tools/query"},
			BearerMethodsSupported: []string{"header"},
			ResourceName:           "Demo MCP",
		},
	}}
	ts := newPRMServer(t, stub)

	resp, err := ts.Client().Do(prmRequest(t, ts, "/.well-known/oauth-protected-resource"))
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	var got map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatalf("decode: %v", err)
	}

	// RFC 9728 §2 member names, checked as wire strings rather than through the
	// Go struct: a renamed json tag is exactly the regression that would make
	// every conformant client stop understanding the document.
	if got["resource"] != "https://auth.example.com" {
		t.Errorf("resource = %v", got["resource"])
	}
	for _, key := range []string{"authorization_servers", "scopes_supported", "bearer_methods_supported", "resource_name"} {
		if _, ok := got[key]; !ok {
			t.Errorf("missing member %q", key)
		}
	}
}

// An identifier the AS does not know about is a legitimate question with a
// legitimate answer. It must not surface as a 500.
func TestPRMRoutes_UnknownResourceIs404(t *testing.T) {
	t.Parallel()

	ts := newPRMServer(t, &stubPRM{docs: map[string]*input.ProtectedResourceMetadata{}})

	resp, err := ts.Client().Do(prmRequest(t, ts, "/.well-known/oauth-protected-resource/nope"))
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("status = %d, want 404", resp.StatusCode)
	}
}

// A nil port must leave the routes unregistered rather than register handlers
// that panic — the same contract JWKS and ASMetadata already follow.
func TestPRMRoutes_NilPortLeavesRoutesUnregistered(t *testing.T) {
	t.Parallel()

	mux := http.NewServeMux()
	wellknown.RegisterRoutes(mux, wellknown.Deps{}, observability.NewNoop())
	ts := httptest.NewServer(mux)
	t.Cleanup(ts.Close)

	resp, err := ts.Client().Do(prmRequest(t, ts, "/.well-known/oauth-protected-resource"))
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("status = %d, want 404 from an unregistered route", resp.StatusCode)
	}
}
