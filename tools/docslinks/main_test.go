package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestGitHubSlug(t *testing.T) {
	// gitHubSlug receives heading text without the leading `#` markers —
	// headingRE strips those before calling it.
	cases := map[string]string{
		"Standards & Specifications":         "standards--specifications",
		"Status & roadmap":                   "status--roadmap",
		"Graceful shutdown":                  "graceful-shutdown",
		"What can go wrong":                  "what-can-go-wrong",
		"1. Install the binary":              "1-install-the-binary",
		"`postgres_key` (multi-instance HA)": "postgres_key-multi-instance-ha",
		"My Heading":                         "my-heading",
		"a/b — c":                            "ab--c",
		"trailing  ":                         "trailing",
		"":                                   "",
		"Already-Slugged":                    "already-slugged",
	}
	for in, want := range cases {
		if got := gitHubSlug(in); got != want {
			t.Errorf("gitHubSlug(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestFileAnchors(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "page.md")
	body := "# Top heading\n" +
		"\n" +
		`<a id="explicit-anchor"></a>` + "\n" +
		"\n" +
		"## Standards & Specifications\n" +
		"\n" +
		"```\n" +
		"## not a heading inside a fence\n" +
		"<a id=\"not-counted\"></a>\n" +
		"```\n" +
		"\n" +
		"### Single-quoted\n" +
		`<a id='single-quoted-anchor'></a>` + "\n"
	if err := os.WriteFile(path, []byte(body), 0644); err != nil {
		t.Fatal(err)
	}
	anchors, err := fileAnchors(path)
	if err != nil {
		t.Fatal(err)
	}
	wantPresent := []string{
		"top-heading",
		"explicit-anchor",
		"standards--specifications",
		"single-quoted",
		"single-quoted-anchor",
	}
	for _, w := range wantPresent {
		if _, ok := anchors[w]; !ok {
			t.Errorf("missing anchor %q (got %v)", w, anchors)
		}
	}
	if _, ok := anchors["not-counted"]; ok {
		t.Errorf("anchor inside fenced code block was counted (got %v)", anchors)
	}
}

func TestCheckFile_FindsAndIgnores(t *testing.T) {
	dir := t.TempDir()

	// Target page with a heading and an explicit anchor.
	target := filepath.Join(dir, "target.md")
	if err := os.WriteFile(target, []byte(
		"# Target\n\n## Real Section\n\n<a id=\"real-explicit\"></a>\n",
	), 0644); err != nil {
		t.Fatal(err)
	}

	// Source page exercising:
	//   - good link to a heading slug → must pass
	//   - good link to an explicit anchor → must pass
	//   - bad link to a missing fragment → must fail
	//   - bad link to a missing file → must fail
	//   - file:LINE ref → must be silently allowed (file exists)
	//   - inline-code containing a [...](...) shape → must be ignored
	//   - external http link → must be ignored
	source := filepath.Join(dir, "src.md")
	body := "# Source\n\n" +
		"- [good heading](target.md#real-section)\n" +
		"- [good explicit](target.md#real-explicit)\n" +
		"- [bad frag](target.md#does-not-exist)\n" +
		"- [bad file](nope.md#anything)\n" +
		"- [line ref](target.md:42)\n" +
		"- inline `func f[T any](v T)` should not match\n" +
		"- [external](https://example.com/x#frag)\n"
	if err := os.WriteFile(source, []byte(body), 0644); err != nil {
		t.Fatal(err)
	}

	cache := map[string]map[string]struct{}{}
	cacheErr := map[string]error{}
	broken, err := checkFile(dir, source, cache, cacheErr)
	if err != nil {
		t.Fatal(err)
	}

	// Expect exactly two failures: bad-frag and bad-file.
	if len(broken) != 2 {
		t.Fatalf("expected 2 broken, got %d: %+v", len(broken), broken)
	}
	hrefs := map[string]string{}
	for _, b := range broken {
		hrefs[b.Href] = b.Reason
	}
	if _, ok := hrefs["target.md#does-not-exist"]; !ok {
		t.Errorf("missing expected failure on bad fragment; got %v", hrefs)
	}
	if _, ok := hrefs["nope.md#anything"]; !ok {
		t.Errorf("missing expected failure on missing file; got %v", hrefs)
	}
}

// TestDiscoverFiles_MarkdownRoots pins the root-level files the checker is
// responsible for. The list is every Markdown root maintained in this repo
// — publishing is not the criterion.
//
// It guards one direction only: a root removed from discoverFiles fails
// here. A root never registered stays invisible, because this list is a
// copy of that one — which is how SECURITY.md sat outside the checker
// while it shipped three dead links.
func TestDiscoverFiles_MarkdownRoots(t *testing.T) {
	dir := t.TempDir()

	roots := []string{
		"README.md", "AGENTS.md", "CONTRIBUTING.md",
		"SECURITY.md", "CODE_OF_CONDUCT.md", "CHANGELOG.md",
		"PROJECT_LAYOUT_DATA_ENCRYPTION.md", "llms.txt",
	}
	for _, name := range roots {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("# x\n"), 0644); err != nil {
			t.Fatal(err)
		}
	}

	found, err := discoverFiles(dir)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]struct{}{}
	for _, p := range found {
		rel, err := filepath.Rel(dir, p)
		if err != nil {
			t.Fatal(err)
		}
		got[rel] = struct{}{}
	}
	for _, name := range roots {
		if _, ok := got[name]; !ok {
			t.Errorf("%s is not covered by the link checker (got %v)", name, got)
		}
	}
}

func TestIsDigitOnly(t *testing.T) {
	if !isDigitOnly("42") {
		t.Error("42 should be digit-only")
	}
	if isDigitOnly("4a") {
		t.Error("4a should not be digit-only")
	}
	if isDigitOnly("") {
		t.Error("empty should not be digit-only")
	}
}

// TestCheckFile_LineCites pins the line-cite rule: a hand-maintained page
// that cites Go source by line number fails; a docsgen-generated page, a
// page in docs/api/, and a bare file cite do not.
func TestCheckFile_LineCites(t *testing.T) {
	dir := t.TempDir()
	cache := map[string]map[string]struct{}{}
	cacheErr := map[string]error{}

	run := func(rel, body string) []brokenLink {
		t.Helper()
		path := filepath.Join(dir, rel)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
		broken, err := checkFile(dir, path, cache, cacheErr)
		if err != nil {
			t.Fatal(err)
		}
		return broken
	}

	// Hand-maintained page: one cite in prose, one in a fenced block, a
	// range, and a bare-file cite that must pass.
	broken := run("docs/guides/page.md",
		"# Page\n\n"+
			"See `internal/foo.go:12` for the check.\n"+
			"```\n"+
			"panic at handlers.go:7\n"+
			"```\n"+
			"Also `authorize.go:110-115`.\n"+
			"Fine: `StartAuthorization` in `internal/services/authorize.go`.\n")
	if len(broken) != 3 {
		t.Fatalf("expected 3 line-cite findings, got %d: %+v", len(broken), broken)
	}
	wantHrefs := []string{"internal/foo.go:12", "handlers.go:7", "authorize.go:110-115"}
	for i, b := range broken {
		if b.Href != wantHrefs[i] {
			t.Errorf("finding %d: href = %q, want %q", i, b.Href, wantHrefs[i])
		}
		if b.Reason != lineCiteReason {
			t.Errorf("finding %d: reason = %q, want %q", i, b.Reason, lineCiteReason)
		}
		if b.SourceFile != "docs/guides/page.md" {
			t.Errorf("finding %d: source = %q, want repo-relative path", i, b.SourceFile)
		}
	}

	// docsgen-generated page: exempt by its first-line marker.
	if broken := run("docs/reference/gen.md",
		"<!-- generated by tools/docsgen; do not edit. -->\n\nSee `internal/config/loader.go:404`.\n",
	); len(broken) != 0 {
		t.Errorf("generated page should be exempt, got %+v", broken)
	}

	// Marker anywhere but line 1 does not exempt.
	if broken := run("docs/guides/late-marker.md",
		"# Page\n<!-- generated by tools/docsgen -->\nSee `foo.go:1`.\n",
	); len(broken) != 1 {
		t.Errorf("marker off line 1 must not exempt, got %+v", broken)
	}

	// docs/api/ is exempt by path.
	if broken := run("docs/api/notes.md", "See `foo.go:1`.\n"); len(broken) != 0 {
		t.Errorf("docs/api/ page should be exempt, got %+v", broken)
	}

	// A hand-maintained reference page gets no exemption.
	if broken := run("docs/reference/audit-events.md", "See `entity.go:39`.\n"); len(broken) != 1 {
		t.Errorf("reference page must be checked, got %+v", broken)
	}
}
