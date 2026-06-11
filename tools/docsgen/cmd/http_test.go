package cmd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestRunHTTPGen_RepoEndToEnd runs the real generator against the real
// repo (it locates the repo root via go.mod). Asserts:
//   - the output file exists and starts with the canonical
//     GeneratedByHeader;
//   - a sanity floor of route count is met (at least 80 endpoint
//     sections — the live count is 97; we leave headroom so a single
//     route deletion does not break the test);
//   - the critical prior-audit shape (`consent_url`, not `connect_url`)
//     is preserved from api/shared/errors.go;
//   - at least 5 DTO sections are emitted, covering the canonical
//     minimums (createResourceRequest, ResourceView,
//     OAuthErrorResponse, tokenResponseDTO, createClientRequest);
//   - re-running the generator is idempotent (byte-identical output).
func TestRunHTTPGen_RepoEndToEnd(t *testing.T) {
	tmp1 := t.TempDir()
	target1, err := runHTTPGen(tmp1)
	if err != nil {
		t.Fatalf("runHTTPGen first pass: %v", err)
	}
	body1, err := os.ReadFile(target1)
	if err != nil {
		t.Fatalf("read first pass: %v", err)
	}
	s := string(body1)

	if !strings.HasPrefix(s, GeneratedByHeader) {
		t.Errorf("missing GeneratedByHeader; got first 80 bytes: %q", s[:min(80, len(s))])
	}

	// Sanity floor on endpoint sections.
	endpointAnchors := strings.Count(s, `<a id="http-`)
	if endpointAnchors < 80 {
		t.Errorf("endpoint section count = %d; want ≥ 80 (live repo has ~97)", endpointAnchors)
	}

	// Sanity floor on DTO sections.
	dtoAnchors := strings.Count(s, `<a id="dto-`)
	if dtoAnchors < 20 {
		t.Errorf("DTO section count = %d; want ≥ 20", dtoAnchors)
	}

	// Critical: api/shared/errors.go §36 has `ConsentURL string
	// \`json:"consent_url,omitempty"\``. The OSS doc audit found a
	// previous drift documenting `connect_url`. Guard against
	// regression here.
	if !strings.Contains(s, "`consent_url`") {
		t.Error("expected consent_url field in OAuthErrorResponse table")
	}
	if strings.Contains(s, "`connect_url`") {
		t.Error("unexpected connect_url field; should be consent_url (see audit finding)")
	}

	// DoD-required DTO names that must appear.
	required := []string{
		"`createResourceRequest`",
		"`ResourceView`",
		"`OAuthErrorResponse`",
		"`tokenResponseDTO`",
		"`createClientRequest`",
	}
	for _, name := range required {
		if !strings.Contains(s, "### "+name) {
			t.Errorf("missing required DTO section %s", name)
		}
	}

	// Required endpoint anchors — the canonical "must always exist" set.
	requiredAnchors := []string{
		"http-public-oauth-token",
		"http-admin-resources-create",
		"http-admin-clients-create",
	}
	for _, a := range requiredAnchors {
		if !strings.Contains(s, `<a id="`+a+`"></a>`) {
			t.Errorf("missing required anchor %s", a)
		}
	}

	// Idempotency: re-run and diff byte-for-byte.
	tmp2 := t.TempDir()
	target2, err := runHTTPGen(tmp2)
	if err != nil {
		t.Fatalf("runHTTPGen second pass: %v", err)
	}
	body2, err := os.ReadFile(target2)
	if err != nil {
		t.Fatalf("read second pass: %v", err)
	}
	if string(body1) != string(body2) {
		t.Error("generator is not idempotent; two runs produced different output")
	}
}

// TestSplitMethodPath asserts the small parsing helper handles the
// canonical Go 1.22 ServeMux pattern syntax (and rejects malformed
// shapes).
func TestSplitMethodPath(t *testing.T) {
	cases := []struct {
		in         string
		wantMethod string
		wantPath   string
	}{
		{"GET /admin/clients", "GET", "/admin/clients"},
		{"POST /oauth/token", "POST", "/oauth/token"},
		{"DELETE /admin/clients/{id}", "DELETE", "/admin/clients/{id}"},
		{"GET /admin/resources/{slug}/policy/connect/allowed-return-urls",
			"GET", "/admin/resources/{slug}/policy/connect/allowed-return-urls"},
		{"badpattern", "", ""},
		{"FOO /bar", "", ""},
		{"GET noleadingslash", "", ""},
	}
	for _, c := range cases {
		m, p := splitMethodPath(c.in)
		if m != c.wantMethod || p != c.wantPath {
			t.Errorf("splitMethodPath(%q) = %q,%q; want %q,%q",
				c.in, m, p, c.wantMethod, c.wantPath)
		}
	}
}

// TestRouteAnchor asserts the verb-suffix policy + admin/-stripping
// behavior described on the function.
func TestRouteAnchor(t *testing.T) {
	cases := []struct {
		r    httpRoute
		want string
	}{
		{httpRoute{Method: "POST", Path: "/admin/resources", Server: "admin"},
			"http-admin-resources-create"},
		{httpRoute{Method: "GET", Path: "/admin/resources", Server: "admin"},
			"http-admin-resources-list"},
		{httpRoute{Method: "GET", Path: "/admin/resources/{id}", Server: "admin"},
			"http-admin-resources-id-get"},
		{httpRoute{Method: "PATCH", Path: "/admin/resources/{id}", Server: "admin"},
			"http-admin-resources-id-update"},
		{httpRoute{Method: "DELETE", Path: "/admin/resources/{id}", Server: "admin"},
			"http-admin-resources-id-delete"},
		{httpRoute{Method: "POST", Path: "/admin/clients/{id}/rotate-secret", Server: "admin"},
			"http-admin-clients-id-rotate-secret"},
		{httpRoute{Method: "POST", Path: "/oauth/token", Server: "public"},
			"http-public-oauth-token"},
		{httpRoute{Method: "POST", Path: "/login", Server: "public"},
			"http-public-login-post"},
		{httpRoute{Method: "GET", Path: "/login", Server: "public"},
			"http-public-login"},
	}
	for _, c := range cases {
		got := routeAnchor(c.r)
		if got != c.want {
			t.Errorf("routeAnchor(%+v) = %q; want %q", c.r, got, c.want)
		}
	}
}

// TestParseJSONTag covers the small json-tag splitter.
func TestParseJSONTag(t *testing.T) {
	cases := []struct {
		in       string
		wantName string
		wantOmit bool
	}{
		{"slug", "slug", false},
		{"slug,omitempty", "slug", true},
		{"name,omitempty,string", "name", true},
		{",omitempty", "", true},
	}
	for _, c := range cases {
		n, o := parseJSONTag(c.in)
		if n != c.wantName || o != c.wantOmit {
			t.Errorf("parseJSONTag(%q) = %q,%v; want %q,%v",
				c.in, n, o, c.wantName, c.wantOmit)
		}
	}
}

// TestBareTypeName strips slice/pointer prefixes and selector prefixes
// down to the bare ident, returning "" for scalars.
func TestBareTypeName(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"string", ""},
		{"int64", ""},
		{"ScopeView", "ScopeView"},
		{"*ScopeView", "ScopeView"},
		{"[]ScopeView", "ScopeView"},
		{"*[]ScopeView", "ScopeView"},
		{"map[string][]ScopeView", "ScopeView"},
		{"json.RawMessage", ""},
		{"*time.Time", ""},
		{"dto.PolicyView", "PolicyView"},
	}
	for _, c := range cases {
		got := bareTypeName(c.in)
		if got != c.want {
			t.Errorf("bareTypeName(%q) = %q; want %q", c.in, got, c.want)
		}
	}
}

// TestCamelToSlug asserts the DTO-name → anchor-slug conversion.
func TestCamelToSlug(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"CreateResourceRequest", "create-resource-request"},
		{"ResourceView", "resource-view"},
		{"DCRSettings", "dcrsettings"},
		{"OAuthErrorResponse", "oauth-error-response"},
		{"tokenResponseDTO", "token-response-dto"},
	}
	for _, c := range cases {
		got := camelToSlug(c.in)
		if got != c.want {
			t.Errorf("camelToSlug(%q) = %q; want %q", c.in, got, c.want)
		}
	}
}

// TestRunHTTPGen_WritesUnderOutDir asserts the entrypoint writes to a
// real file under the requested directory and the path it returns is
// that file.
func TestRunHTTPGen_WritesUnderOutDir(t *testing.T) {
	tmp := t.TempDir()
	target, err := runHTTPGen(tmp)
	if err != nil {
		t.Fatalf("runHTTPGen: %v", err)
	}
	want := filepath.Join(tmp, "http-api.md")
	if target != want {
		t.Errorf("target = %q; want %q", target, want)
	}
	if _, err := os.Stat(target); err != nil {
		t.Fatalf("stat %s: %v", target, err)
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
