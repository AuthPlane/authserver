package mdwriter

import (
	"strings"
	"testing"
)

func TestTableRender_Empty(t *testing.T) {
	tbl := &Table{}
	if got := tbl.Render(); got != "" {
		t.Fatalf("empty table should render as empty string, got %q", got)
	}
}

func TestTableRender_HeaderOnly(t *testing.T) {
	tbl := &Table{Headers: []string{"Flag", "Default", "Description"}}
	got := tbl.Render()
	want := "| Flag | Default | Description |\n| --- | --- | --- |\n"
	if got != want {
		t.Fatalf("header-only table mismatch\n got: %q\nwant: %q", got, want)
	}
}

func TestTableRender_Alignment(t *testing.T) {
	tbl := &Table{
		Headers: []string{"A", "B", "C"},
		Rows: [][]string{
			{"1", "2", "3"},
			{"short"},                // padded
			{"x", "y", "z", "extra"}, // truncated
		},
	}
	got := tbl.Render()
	lines := strings.Split(strings.TrimRight(got, "\n"), "\n")
	if len(lines) != 5 {
		t.Fatalf("expected 5 lines, got %d: %v", len(lines), lines)
	}
	// Each rendered line should contain exactly len(Headers)+1 pipes.
	for i, ln := range lines {
		if got := strings.Count(ln, "|"); got != 4 {
			t.Errorf("line %d %q has %d pipes, want 4", i, ln, got)
		}
	}
}

func TestTableRender_EscapesPipesAndNewlines(t *testing.T) {
	tbl := &Table{
		Headers: []string{"K", "V"},
		Rows:    [][]string{{"a|b", "line1\nline2"}},
	}
	got := tbl.Render()
	if !strings.Contains(got, `a\|b`) {
		t.Errorf("pipe not escaped: %q", got)
	}
	if strings.Contains(got, "line1\nline2") {
		t.Errorf("newline not stripped from cell: %q", got)
	}
}

func TestCodeBlock(t *testing.T) {
	got := CodeBlock("go", "func main() {}")
	if !strings.HasPrefix(got, "```go\n") {
		t.Errorf("missing lang fence: %q", got)
	}
	if !strings.HasSuffix(got, "```\n") {
		t.Errorf("missing closing fence: %q", got)
	}
	// No-lang variant.
	got = CodeBlock("", "hello\n")
	if !strings.HasPrefix(got, "```\n") {
		t.Errorf("missing empty fence: %q", got)
	}
}

func TestSlugNormalization(t *testing.T) {
	cases := map[string]string{
		"Hello World":           "hello-world",
		"  Spaces  Around  ":    "spaces-around",
		"Punctuation!@#$%":      "punctuation",
		"already-slugged":       "already-slugged",
		"MixedCASE_with_under":  "mixedcase-with-under",
		"---leading-trailing--": "leading-trailing",
	}
	for in, want := range cases {
		if got := Slug(in); got != want {
			t.Errorf("Slug(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestAnchor(t *testing.T) {
	got := Anchor("My Section")
	want := `<a id="my-section"></a>`
	if got != want {
		t.Errorf("Anchor mismatch: got %q want %q", got, want)
	}
}

func TestSection(t *testing.T) {
	got := Section(2, "Hello", "", "body text")
	if !strings.HasPrefix(got, "## Hello\n\n") {
		t.Errorf("missing heading: %q", got)
	}
	if !strings.Contains(got, `<a id="hello"></a>`) {
		t.Errorf("missing anchor: %q", got)
	}
	if !strings.Contains(got, "body text") {
		t.Errorf("missing body: %q", got)
	}
	// Level clamping.
	low := Section(0, "T", "", "")
	if !strings.HasPrefix(low, "# T") {
		t.Errorf("level 0 should clamp to 1, got %q", low)
	}
	high := Section(99, "T", "", "")
	if !strings.HasPrefix(high, "###### T") {
		t.Errorf("level 99 should clamp to 6, got %q", high)
	}
}
