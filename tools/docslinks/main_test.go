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
